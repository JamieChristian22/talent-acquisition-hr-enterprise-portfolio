"""Credential-gated, read-only HTTP connectors with local real-network contract tests.

These are NOT connected to any actual customer tenants. Never call a live service
without an owned test account and written approval; no candidate PII is persisted.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit
import httpx


class ProviderError(RuntimeError):
    """Sanitized integration error: credentials, upstream bodies and PII excluded."""


def _validated_url(url: str, allow_local_test_http: bool) -> None:
    parts = urlsplit(url)
    if parts.username or parts.password or parts.fragment or not parts.hostname:
        raise ProviderError("Invalid upstream endpoint")
    if parts.scheme == "https":
        return
    if allow_local_test_http and parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1"):
        return
    raise ProviderError("HTTPS required for upstream integration")


def _safe_get(client: httpx.Client, url: str, *, headers: dict, allow_local_test_http: bool) -> httpx.Response:
    _validated_url(url, allow_local_test_http)
    try:
        r = client.get(url, headers=headers, follow_redirects=False)
    except httpx.RequestError as exc:
        raise ProviderError("Upstream connection failed") from exc
    if r.status_code in (301, 302, 303, 307, 308):
        raise ProviderError("Redirects rejected to prevent credential forwarding")
    if r.status_code == 429:
        raise ProviderError("Rate limited: follow provider Retry-After before retry")
    if r.status_code in (401, 403):
        raise ProviderError("Upstream authorization failed")
    if r.status_code != 200:
        raise ProviderError("Upstream returned non-success response")
    if len(r.content) > 2_000_000:
        raise ProviderError("Upstream response too large")
    return r


class GreenhouseV3Reader:
    """Official Harvest v3 OAuth client-credentials flow, read-only listing.

    Uses a real HTTP client and OAuth token endpoint; auth and list URLs can only
    be changed for explicit localhost contract tests. Production fixed to docs.
    """

    TOKEN_URL = "https://auth.greenhouse.io/token"
    JOBS_URL = "https://harvest.greenhouse.io/v3/jobs"

    def __init__(self, client_id: str, client_secret: str, *,
                 client: httpx.Client | None = None,
                 token_url: str = TOKEN_URL, jobs_url: str = JOBS_URL,
                 allow_local_test_http: bool = False):
        if not client_id or not client_secret:
            raise ProviderError("Greenhouse OAuth credentials required")
        if not allow_local_test_http and (token_url != self.TOKEN_URL or jobs_url != self.JOBS_URL):
            raise ProviderError("Production Greenhouse endpoints are fixed")
        for u in (token_url, jobs_url):
            _validated_url(u, allow_local_test_http)
        self.client_id = client_id
        self.client_secret = client_secret
        self.client = client or httpx.Client(timeout=10, follow_redirects=False)
        self.token_url, self.jobs_url = token_url, jobs_url
        self.allow_local_test_http = allow_local_test_http

    def token(self) -> str:
        try:
            result = self.client.post(self.token_url,
                auth=(self.client_id, self.client_secret),
                data={"grant_type": "client_credentials"}, follow_redirects=False)
        except httpx.RequestError as exc:
            raise ProviderError("Token endpoint unreachable") from exc
        if result.status_code != 200:
            raise ProviderError("OAuth token request failed")
        try:
            body = result.json()
            value = body["access_token"]
            if not isinstance(value, str) or len(value) < 8:
                raise ValueError("Invalid token")
            return value
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("Invalid OAuth response") from exc

    def list_job_identifiers(self, max_pages: int = 3) -> list[str]:
        """Read job IDs ONLY, deliberately discarding any personal information."""
        if not 1 <= max_pages <= 10:
            raise ValueError("max_pages must be 1..10")
        token = self.token()
        url = self.jobs_url + "?per_page=25"
        result: list[str] = []
        seen: set[str] = set()
        origin = urlsplit(self.jobs_url)
        for _ in range(max_pages):
            response = _safe_get(self.client, url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                                 allow_local_test_http=self.allow_local_test_http)
            try:
                rows = response.json()
                if not isinstance(rows, list):
                    raise ValueError("Expected a list")
                for record in rows:
                    if not isinstance(record, dict) or not isinstance(record.get("id"), int):
                        raise ValueError("Invalid job record")
                    key = str(record["id"])
                    if key not in seen:
                        result.append(key)
                        seen.add(key)
            except (ValueError, KeyError, TypeError) as exc:
                raise ProviderError("Invalid job response format") from exc
            link = response.headers.get("link", "")
            match = re.search(r'<([^<>]+)>\s*;\s*rel="next"', link)
            if not match:
                break
            next_url = match.group(1)
            _validated_url(next_url, self.allow_local_test_http)
            nxt = urlsplit(next_url)
            if (nxt.scheme, nxt.netloc, nxt.path) != (origin.scheme, origin.netloc, origin.path):
                raise ProviderError("Unexpected pagination destination")
            url = next_url
        return result


class WorkdayTenantReader:
    """Reads a caller-specified tenant-approved HTTPS REST endpoint using a bearer token.

    Workday URLs and access policies are tenant-specific. This does not assume a
    universal `/workers` schema; provides envelope metadata only, not worker PII.
    """
    def __init__(self, endpoint: str, access_token: str, *, client: httpx.Client | None = None,
                 allow_local_test_http: bool = False):
        _validated_url(endpoint, allow_local_test_http)
        hostname = urlsplit(endpoint).hostname or ""
        if not allow_local_test_http and not any(hostname == suffix or hostname.endswith("." + suffix)
                                                 for suffix in ("workday.com", "myworkday.com")):
            raise ProviderError("Workday tenant endpoint must be an approved Workday host")
        if not access_token or len(access_token) < 8:
            raise ProviderError("Workday tenant token required")
        self.endpoint, self.token = endpoint, access_token
        self.client = client or httpx.Client(timeout=10, follow_redirects=False)
        self.allow_local_test_http = allow_local_test_http

    def read_summary(self) -> dict:
        r = _safe_get(self.client, self.endpoint,
                      headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
                      allow_local_test_http=self.allow_local_test_http)
        try:
            doc = r.json()
        except ValueError as exc:
            raise ProviderError("Invalid Workday JSON response") from exc
        if not isinstance(doc, (dict, list)):
            raise ProviderError("Unexpected Workday response format")
        records = doc if isinstance(doc, list) else doc.get("data", [])
        # Do not return worker records, PII, personnel IDs, or credentials.
        return {"provider": "workday", "read_only": True, "item_count": len(records) if isinstance(records, list) else None}
