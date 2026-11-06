"""Admin CLI for the Neverlose secure loader.

    python manage.py genkey                      create signing_key.pem, print public key
    python manage.py pubkey                      print public key for loader.lua
    python manage.py add [--scripts a,b] [--days 30] [--note text]
    python manage.py revoke <license key | hash prefix>
    python manage.py unbind <license key | hash prefix>   allow re-binding to a new account
    python manage.py list
"""

from __future__ import annotations

import argparse
import os
import time

from core import NAME_RE, LicenseDB, Signer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=os.environ.get("LOADER_KEY", "signing_key.pem"))
    ap.add_argument("--db", default=os.environ.get("LOADER_DB", "licenses.db"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey")
    sub.add_parser("pubkey")
    a = sub.add_parser("add")
    a.add_argument("--scripts", default="*", help='comma separated names, or "*" for all')
    a.add_argument("--days", type=int, default=None)
    a.add_argument("--note", default="")
    for c in ("revoke", "unbind"):
        sub.add_parser(c).add_argument("license")
    sub.add_parser("list")
    args = ap.parse_args()

    if args.cmd == "genkey":
        s = Signer.generate(args.key)
        print(f"wrote {args.key} (mode 600). Keep it secret and backed up offline.")
        print(f'PUBLIC_KEY_HEX = "{s.public_hex()}"')
    elif args.cmd == "pubkey":
        print(Signer.from_file(args.key).public_hex())
    elif args.cmd == "add":
        if args.scripts != "*":
            names = [n.strip() for n in args.scripts.split(",")]
            bad = [n for n in names if not NAME_RE.match(n)]
            if bad:
                raise SystemExit(f"invalid script names: {bad}")
        key = LicenseDB(args.db).add(args.scripts, args.days, args.note)
        print(key)
        print("(only a hash is stored; this key cannot be shown again)")
    elif args.cmd in ("revoke", "unbind"):
        db = LicenseDB(args.db)
        n = db.revoke(args.license) if args.cmd == "revoke" else db.unbind(args.license)
        if n != 1:
            raise SystemExit(f"{n} licenses matched; give the full key or a longer hash prefix")
        print("done")
    elif args.cmd == "list":
        for h, user, scripts, exp, revoked, note, seen in LicenseDB(args.db).list():
            exp_s = time.strftime("%Y-%m-%d", time.gmtime(exp)) if exp else "never"
            seen_s = time.strftime("%Y-%m-%d %H:%M", time.gmtime(seen)) if seen else "-"
            state = "REVOKED" if revoked else "active"
            print(f"{h[:12]}  {state:7}  user={user or '-':20} scripts={scripts:15} expires={exp_s}  seen={seen_s}  {note}")


if __name__ == "__main__":
    main()
