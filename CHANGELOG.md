## v3.0 — Verified local account security and provider contracts (2026-11-13)
- Added FastAPI authenticated local service, CLI user provisioning and five server-enforced RBAC roles.
- Added Argon2id, throttled login, opaque token-hashed sessions, CSRF, Origin checks, security headers and access audit.
- Added read-only Greenhouse Harvest v3 OAuth connector and tenant-specific Workday HTTP reader, with local real HTTP contract tests.
- Added semantic secure app interface, Playwright/axe-core WCAG checks and GitHub Actions security/dependency gates.
- Preserved original synthetic public demo; no real employer tenant credentials or actual applicant data used.
- Remaining: live provider tenant approval, MFA/SSO, public-hosting hardening, manual accessibility, third-party penetration testing.

## 2.0.0 — 2026-11-13 — Enterprise interactive portfolio lab

- Introduced synthetic in-memory requisition, approvals, application-stage and interview scheduling workflow.
- Added local-only HTTP JSON API and vendor-shaped mock adapters with idempotent imports.
- Added source-cohort analysis, stage-pair lag distributions, mature cohorts and historical fill quartiles.
- Added offline accessible interactive demo, new Excel analytics workbook, detailed runbooks and risk review.
- Added functional, negative, API and accessibility regression checks.
- No real ATS, HRIS, calendar, email, identity provider or candidate data is accessed.

# Changelog

## 1.0.0 — 2026-11-13

- Delivered fictional Northstar TA and People Operations data: 42 requisitions, 1,249 application records, stage histories, offers, surveys, new-hire onboarding, 204 employee records and 150 HR cases.
- Added 9-table constrained SQLite warehouse, deterministic generator, central KPI definitions, offline dashboard and optional Streamlit exploration.
- Added operational Excel workbook with full candidate/application data, formula-driven leadership KPIs, data validation, recruiting/HR trackers and example structured interview scorecard.
- Added 6-page executive case study PDF built from `metrics.json`, source documentation, 30/60/90 plan, RACI, governance, risk register and hiring/HR workflow examples.
- Added restricted mock aggregate audit illustration, QA/negative tests, GitHub Actions CI, PDF build script, release checker and publishing notes.
- Corrected open-requisition disposition semantics to avoid describing still-open requisitions as filled.

### Known intentional limitations

All source data are fabricated. There are no ATS/HRIS vendor integrations, applicant-facing live workflow, authentication, legal compliance certification or measured intervention results. Excel is supplied as a finished workbook; programmatic Excel reauthoring requires a compatible spreadsheet tool and is not part of the offline CLI.
