"""Zero-dependency hardening assertions; complements Bandit/Dependency audit."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
api = (ROOT/'src/tahr/secure_service.py').read_text()
ui = (ROOT/'secure_web/index.html').read_text()
js = (ROOT/'secure_web/secure.js').read_text()
assert 'httponly=True' in api and 'samesite="strict"' in api
assert 'hmac.compare_digest' in api and 'argon2' in api
assert '"auditor": {"audit:read"}' in api
assert 'frame-ancestors \'none\'' in api
assert '<script src="/secure.js" defer></script>' in ui
assert '<script>' not in ui and 'onclick=' not in ui
assert 'localStorage' not in js.replace('// Deliberately no localStorage/sessionStorage: tokens stay in HttpOnly cookies;','')
assert 'textContent' in js and '.innerHTML' not in js
assert (ROOT/'tests/browser/secure-operations.spec.cjs').is_file()
assert (ROOT/'tests/test_provider_contracts.py').is_file()
print('Source hardening and required test assets: PASS')
