"""CI-only: generate disposable users and a private temporary credential file."""
from __future__ import annotations
import json
import os
from pathlib import Path
import secrets
from tahr.secure_service import IdentityStore

out = Path(os.environ["TAHR_TEST_LOGIN_FILE"])
base = Path(os.environ["TAHR_RUNTIME_DIR"])
base.mkdir(parents=True, exist_ok=True)
store = IdentityStore(str(base / "identities.sqlite"))
accounts = {}
for role in ("admin", "analyst"):
    user = f"ci.{role}"
    password = secrets.token_urlsafe(32)
    store.create_user(user, password, role)
    accounts[role] = {"username": user, "password": password}
old_umask = os.umask(0o077)
try:
    out.write_text(json.dumps(accounts), encoding="utf-8")
    out.chmod(0o600)
finally:
    os.umask(old_umask)
print("Prepared disposable CI accounts; credentials not logged or committed")
