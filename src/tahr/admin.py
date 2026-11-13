"""Offline user provisioning: avoids default logins and plaintext password arguments."""
from __future__ import annotations
import argparse
from getpass import getpass
from pathlib import Path
from .secure_service import IdentityStore, ROLES


def main():
    p = argparse.ArgumentParser(description="Manage real local HR training accounts; never commit the SQLite file")
    p.add_argument("command", choices=["create", "set-role", "disable"])
    p.add_argument("username")
    p.add_argument("--role", choices=ROLES)
    p.add_argument("--db", default=str(Path.home() / ".tahr-local" / "identities.sqlite"))
    args = p.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import os
    if os.name == "posix":
        os.chmod(Path(args.db).parent, 0o700)
    store = IdentityStore(args.db)
    if args.command == "create":
        if not args.role:
            p.error("--role required for create")
        pwd, confirm = getpass("New password (15+ characters): "), getpass("Confirm password: ")
        if pwd != confirm:
            p.error("Passwords do not match")
        store.create_user(args.username, pwd, args.role)
        print("Account created. No password printed or saved in source control.")
    elif args.command == "set-role":
        if not args.role:
            p.error("--role required for set-role")
        store.set_role(args.username, args.role)
        print("Role updated and existing sessions revoked.")
    else:
        store.disable(args.username)
        print("Account disabled and sessions revoked.")

if __name__ == "__main__":
    main()
