"""Signing, license storage and script storage for the Neverlose secure loader."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL = "NLLOADER-V1"
ENVELOPE_TTL = 120  # seconds a signed response stays valid

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
LICENSE_RE = re.compile(r"^[A-Za-z0-9-]{16,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
USER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------
class Signer:
    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Signer":
        p = Path(path)
        if os.name == "posix":
            mode = p.stat().st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError(f"{p} is readable by group/other; run: chmod 600 {p}")
        key = serialization.load_pem_private_key(p.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("signing key is not an Ed25519 key")
        return cls(key)

    @staticmethod
    def generate(path: str | os.PathLike) -> "Signer":
        p = Path(path)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # O_EXCL: never overwrite an existing key
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return Signer(key)

    def public_hex(self) -> str:
        raw = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw.hex()

    def envelope(self, payload: dict) -> bytes:
        """Serialise and sign a payload. The signature covers PROTOCOL\\0payload."""
        payload = {"proto": PROTOCOL, **payload}
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
        sig = self._key.sign(PROTOCOL.encode() + b"\0" + body)
        return json.dumps(
            {
                "payload": base64.b64encode(body).decode(),
                "sig": base64.b64encode(sig).decode(),
            }
        ).encode()


# --------------------------------------------------------------------------
# licenses
# --------------------------------------------------------------------------
def hash_license(key: str) -> str:
    # license keys are 160+ bit random tokens, so a fast hash is sufficient;
    # storing only the hash means a leaked database does not leak keys
    return hashlib.sha256(key.encode()).hexdigest()


def new_license_key() -> str:
    raw = secrets.token_hex(16).upper()  # 128 bits
    return "NL-" + "-".join(raw[i : i + 8] for i in range(0, 32, 8))


@dataclass
class LicenseCheck:
    ok: bool
    reason: str = ""
    scripts: str = ""

    def allows(self, name: str) -> bool:
        if self.scripts == "*":
            return True
        return name in {s.strip() for s in self.scripts.split(",") if s.strip()}


class LicenseDB:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS licenses (
        key_hash    TEXT PRIMARY KEY,
        username    TEXT,
        scripts     TEXT NOT NULL DEFAULT '*',
        expires_at  INTEGER,
        revoked     INTEGER NOT NULL DEFAULT 0,
        note        TEXT NOT NULL DEFAULT '',
        created_at  INTEGER NOT NULL,
        last_seen   INTEGER
    );
    """

    def __init__(self, path: str | os.PathLike):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(self.SCHEMA)
        if os.name == "posix":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def add(self, scripts: str = "*", days: int | None = None, note: str = "") -> str:
        key = new_license_key()
        expires = int(time.time()) + days * 86400 if days else None
        with self._lock:
            self._conn.execute(
                "INSERT INTO licenses (key_hash, scripts, expires_at, note, created_at) VALUES (?,?,?,?,?)",
                (hash_license(key), scripts, expires, note, int(time.time())),
            )
        return key

    def _update(self, key_or_prefix: str, sql: str, args: tuple = ()) -> int:
        # accept either the full license key or a hex prefix (>= 8 chars) of its hash
        prefix = key_or_prefix.lower()
        prefix_ok = len(prefix) >= 8 and all(c in "0123456789abcdef" for c in prefix)
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_hash FROM licenses WHERE key_hash = ? OR (? AND substr(key_hash, 1, ?) = ?)",
                (hash_license(key_or_prefix), prefix_ok, len(prefix), prefix),
            ).fetchall()
            if len(rows) != 1:
                return len(rows)
            self._conn.execute(sql + " WHERE key_hash = ?", (*args, rows[0][0]))
            return 1

    def revoke(self, key: str) -> int:
        return self._update(key, "UPDATE licenses SET revoked = 1")

    def unbind(self, key: str) -> int:
        return self._update(key, "UPDATE licenses SET username = NULL")

    def list(self):
        with self._lock:
            return self._conn.execute(
                "SELECT key_hash, username, scripts, expires_at, revoked, note, last_seen FROM licenses"
            ).fetchall()

    def check(self, key: str, username: str) -> LicenseCheck:
        if not LICENSE_RE.match(key or ""):
            return LicenseCheck(False, "invalid license")
        h = hash_license(key)
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT key_hash, username, scripts, expires_at, revoked FROM licenses WHERE key_hash = ?",
                (h,),
            ).fetchone()
            if row is None or not hmac.compare_digest(row[0], h):
                return LicenseCheck(False, "invalid license")
            _, bound, scripts, expires, revoked = row
            if revoked:
                return LicenseCheck(False, "license revoked")
            if expires is not None and expires < now:
                return LicenseCheck(False, "license expired")
            if bound is None:
                # first use binds the license to this Neverlose account
                self._conn.execute(
                    "UPDATE licenses SET username = ?, last_seen = ? WHERE key_hash = ? AND username IS NULL",
                    (username, now, h),
                )
                bound = self._conn.execute(
                    "SELECT username FROM licenses WHERE key_hash = ?", (h,)
                ).fetchone()[0]
            if not hmac.compare_digest(bound.encode(), username.encode()):
                return LicenseCheck(False, "license bound to another account")
            self._conn.execute("UPDATE licenses SET last_seen = ? WHERE key_hash = ?", (now, h))
            return LicenseCheck(True, scripts=scripts)


# --------------------------------------------------------------------------
# scripts
# --------------------------------------------------------------------------
class ScriptStore:
    """Reads scripts/manifest.json: {"name": {"version": 3, "file": "name.lua"}}"""

    MAX_SIZE = 2 * 1024 * 1024

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).resolve()

    def _manifest(self) -> dict:
        data = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        out = {}
        for name, meta in data.items():
            if not NAME_RE.match(name) or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            fname = meta.get("file", f"{name}.lua")
            if not isinstance(version, int) or version < 0 or not isinstance(fname, str):
                continue
            out[name] = {"version": version, "file": fname}
        return out

    def list(self) -> list[dict]:
        return [{"name": n, "version": m["version"]} for n, m in sorted(self._manifest().items())]

    def get(self, name: str) -> tuple[int, str] | None:
        if not NAME_RE.match(name):
            return None
        meta = self._manifest().get(name)
        if meta is None:
            return None
        path = (self.root / meta["file"]).resolve()
        # refuse path traversal out of the scripts directory
        if self.root not in path.parents:
            return None
        data = path.read_bytes()
        if len(data) == 0 or len(data) > self.MAX_SIZE or data[:1] == b"\x1b":
            return None
        return meta["version"], data.decode("utf-8")
