# Accessibility verification: real tools and disclosed limits

The secure app uses labeled fields, `<main>` and page hierarchy, keyboard skip link, visible focus rings, real table captions/headers, a live status region and a responsive layout. `secure_web/secure.js` renders untrusted values via textContent, not innerHTML.

GitHub Actions `.github/workflows/secure-quality.yml` installs **Playwright Chromium** and **@axe-core/playwright 4.14.0**, starts the real FastAPI service bound to loopback, creates random disposable account passwords (in a temporary 0600 file, never in Git), and checks:

1. Login page axe automated WCAG A/AA 2.0/2.1/2.2 tags and tab-to-skip-link.
2. Logged-in admin page axe scan, role-specific controls and form submission.
3. Logged-in analyst page axe scan and prohibited control visibility.
4. Mobile 375px page axe scan and horizontal overflow check.

Run locally on a machine with Node 22+ and network access to npm/Playwright browsers:

```bash
npm install
npx playwright install chromium
export TAHR_RUNTIME_DIR=/tmp/tahr-a11y-runtime
export TAHR_TEST_LOGIN_FILE=/tmp/tahr-a11y-login.json
PYTHONPATH=src python scripts/prepare_secure_browser.py
PYTHONPATH=src python -m tahr.secure_service &
npm run test:a11y
```

**Accessibility limitations:** Automated axe scans do not prove WCAG compliance. Manual keyboard-only navigation, screen reader sessions (NVDA/VoiceOver), high zoom, reduced motion, contrast across states, and usability research remain follow-ups. The static public demo `demo/index.html` is a distinct experience and is not covered by the secure UI audit. Browser test runtime is reported separately; passing unit tests are not equivalent to passing axe scans.

Reference: [W3C accessibility evaluation tools](https://www.w3.org/WAI/test-evaluate/tools/list/).
