# Real local accounts, RBAC, sessions and a realistic threat model

**Status:** Working local training service with real password verification and a persistent user database; NOT a hosted production HR platform. Synthetic records only. The separate static `demo/index.html` intentionally stays **unauthenticated and client-side only**; it is not a secure app. Run `secure_web` only through the FastAPI backend.

## Start without paying or connecting a real HR account

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-secure.txt
PYTHONPATH=src python -m tahr.admin create training.admin --role admin
PYTHONPATH=src python -m tahr.admin create training.recruiter --role recruiter
PYTHONPATH=src python -m tahr.admin create training.manager --role hiring_manager
PYTHONPATH=src python -m tahr.admin create training.analyst --role analyst
PYTHONPATH=src python -m tahr.admin create training.auditor --role auditor
PYTHONPATH=src python -m tahr.secure_service
```

Open <http://127.0.0.1:8766> in a browser. No default passwords and no hosted signup. The CLI prompts for strong passwords without echoing; do not use real candidate data. Account and workflow databases are created under `$HOME/.tahr-local/`, not in the repository. `TAHR_RUNTIME_DIR` overrides that directory. Username names are arbitrary synthetic labels, not personal data.

## Role permissions (checked *server-side* on every request)

| Permission | Admin | Recruiter | Hiring manager | Analyst | Auditor |
| --- | :---: | :---: | :---: | :---: | :---: |
| Read requisitions | yes | yes | yes | no | no |
| Create requisition | yes | no | yes | no | no |
| Approve requisition | yes | no | yes | no | no |
| Read application records | yes | yes | no | no | no |
| Create/advance application | yes | yes | no | no | no |
| Schedule interview | yes | yes | no | no | no |
| Aggregate hiring metrics | yes | yes | yes | yes | no |
| Security access audit | yes | no | no | no | yes |
| Probe approved read-only HR integrations | yes | no | no | no | no |

A user cannot approve their own requisition, even as admin. HTTP-supplied actor/requestor fields are ignored. Role changes and disable actions revoke existing sessions immediately. `PYTHONPATH=src python -m tahr.admin set-role training.recruiter --role auditor` or `... disable training.recruiter`. The operator must have filesystem access; there is no public admin web panel.

## Security controls implemented and verified

- **Credentials:** Argon2id (19 MiB, 2 iterations, parallelism 1) and randomly salted password hashes; 15-character minimum; usernames not enumerated by login errors; 5 failed attempts per account/15-minute window.
- **Sessions:** 384-bit random opaque session tokens, SHA-256 server-side verifier, HttpOnly SameSite=Strict cookies, 8-hour absolute expiry, rotation on sign-in, revocation on logout, role changes, and account disable. Tokens are never returned in JSON, logs or JS storage.
- **CSRF:** synchronizer token returned only on successful sign-in and compared via a server-side digest for state changes. Browser `Origin` and content-type restrictions add defense in depth. Cookies use Secure=True when `create_app(cookie_secure=True)` is installed behind approved TLS; local loopback uses insecure cookie *only* on localhost. Browser page refresh requires a fresh login for protected writes (CSRF token intentionally lives only in JS memory).
- **Headers and frontend:** no wildcard CORS; restrictive CSP without inline JavaScript; frame blocking, `nosniff`, no-referrer, no-store, permissions policy. HTML-escaped DOM updates (`textContent`), no raw candidate data embedded in scripts.
- **Controls:** least privilege, separation of duties, bounded inputs, enforced workflow transitions, durable access audit records; no anonymous access to HR resources.
- **Testing:** `unittest` tests every role/permission, failure paths, spoofing, CSRF, lockouts and revocation. Bandit + pip-audit run via CI. Playwright + axe-core scan login and authenticated role views at desktop and 375px mobile.

## Threat model and boundary

| Threat | Mitigation | Remaining risk |
|---|---|---|
| Password dumping | Argon2id with random salt | Host compromise can steal an active DB; protect file permissions, disk encryption, backup |
| Session replay | Opaque random token hashed at rest, rotate/revoke, HttpOnly | Full browser compromise possible; MFA and centralized session anomaly detection not included |
| IDOR/role escalation | Permission checks on every route; identity from server-side session | Not independently penetration-tested |
| Cross-site forgery | Strict cookie, explicit synchronizer CSRF header, Origin check | Reverse-proxy setup requires additional review |
| XSS and injection | CSP, escaped JS DOM text, SQLite prepared parameters | Manual offensive security and full WAF configuration still needed |
| Data exfiltration via providers | Credentials opt-in; read-only APIs, same-origin pagination; PII discarded | Real tenant DPA, consent, retention and security review not implemented |
| Excessive sign-in guessing | Throttle by username and generic errors | IP/device-based rate limiting and bot defenses are not provided |
| Availability/backup | Local database; deterministic synthetic rebuild | No HA, backup restoration SLA, centralized monitoring or SIEM |

**Do not publish this training API on a public domain.** It lacks MFA, SSO/OIDC, production key management, TLS reverse-proxy configuration, managed secrets, HA/DR, tenant isolation, production-grade account recovery, comprehensive log retention policy, or independent compliance certification. Authentication is real; production certification is not implied. For production use, add centralized IdP/SSO with MFA, hosted database isolation, policy-as-code, security review and legal assessment.

References: [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet), [OWASP ASVS 5.0](https://asvs.owasp.org/), [WCAG 2.2](https://www.w3.org/TR/WCAG22/).
