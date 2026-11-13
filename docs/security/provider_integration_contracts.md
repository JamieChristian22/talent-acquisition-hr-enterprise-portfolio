# Real HTTP connector implementation and integration verification

These adapters execute **real HTTP requests** and are not copies of a fictitious API. They have been exercised against an ephemeral local HTTP server that implements expected status codes, token grants, bearer headers, cursor pagination and tenant responses. Tests never contact an employer tenant or upload applicant data. This is **contract-level verification**, not certification of a live Greenhouse/Workday integration.

## Greenhouse Harvest v3 (OAuth, read-only jobs)

`src/tahr/provider_clients.py:GreenhouseV3Reader` uses the documented v3 OAuth **client credentials** flow. Official production token URL: `https://auth.greenhouse.io/token`; read-only jobs endpoint: `https://harvest.greenhouse.io/v3/jobs`.

- OAuth POST sends `grant_type=client_credentials` with HTTP Basic credentials over HTTPS.
- Read requests send bearer token; output returns only job IDs, discarding job descriptions and any candidate PII.
- Follows same-origin cursor `Link: rel="next"` for up to 10 pages; rejects redirects to arbitrary hosts and cross-origin pagination, handles errors including 429 without silently retrying excessive requests.
- **No live credentials have been provided or used.** To test a real company-controlled Greenhouse account, an authorized operator must supply customer-issued OAuth credentials via a secrets manager or environment variables. Never commit tokens. A real tenant can restrict permissions and needs Site Admin list authorization. Verify terms and written authorization before first live request.

## Workday (tenant-specific read-only endpoint)

`WorkdayTenantReader` accepts an operator-approved Workday endpoint and bearer token with HTTPS, does a read-only GET and returns **only an envelope count**, not worker names/addresses/identifiers. Workday exposes APIs per tenant and security domain; the adapter **does not assume a universal Worker schema**. A real Workday connection needs a Workday tenant, registered client/ISU, scoped access and approval from the tenant owner. No real Workday account was accessed.

## Reproduce the actual HTTP contract tests

```bash
pip install -r requirements-secure.txt
PYTHONPATH=src python -m unittest tests.test_provider_contracts -v
```

The test suite boots a real `ThreadingHTTPServer` bound to `127.0.0.1:ephemeral_port`, exercises HTTP OAuth POST, GET with Authorization headers, two-page cursor behavior, Workday-like tenant reads, 401/429 rejection, cross-host pagination blocking, and HTTPS-required checks. No third-party network calls. `allow_local_test_http=True` permits `http://127.0.0.1` **only for these tests**; production Greenhouse URLs are fixed.

**Gaps:** No customer OAuth secrets, no real Workday tenant contract, no bulk synchronization, no mapping of actual personal HR data, no long-running refresh tasks, no vendor certification. Read-only external access is deliberate.

Official references: [Greenhouse Harvest v3 authentication](https://harvestdocs.greenhouse.io/docs/authentication), [Greenhouse pagination](https://harvestdocs.greenhouse.io/docs/pagination), [Greenhouse list candidates/jobs](https://harvestdocs.greenhouse.io/reference/get_v3-candidates), [Workday Developer Platform](https://developer.workday.com/documentation/GUID-6c547385-848b-4005-ab2c-632f1d6b5688).
