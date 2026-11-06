"""Tests for the secure loader. Requires `luajit` and `curl` on PATH.

    cd loader && python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "server"))

from core import PROTOCOL, LicenseDB, ScriptStore, Signer  # noqa: E402
from server import App, RateLimiter, make_handler  # noqa: E402

LOADER = ROOT / "client" / "loader.lua"
LUAJIT = shutil.which("luajit")

L_ORDER = 2**252 + 27742317777372353535851937790883648493


def lua_str(b: bytes | str) -> str:
    if isinstance(b, str):
        b = b.encode()
    return '"' + "".join(f"\\{c}" for c in b) + '"'


def lua_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "nil"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (str, bytes)):
        return lua_str(v)
    if isinstance(v, list):
        return "{" + ", ".join(lua_val(x) for x in v) + "}"
    if isinstance(v, dict):
        return "{" + ", ".join(f"[{lua_val(k)}] = {lua_val(x)}" for k, x in v.items()) + "}"
    raise TypeError(type(v))


def raw_pub(k: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@unittest.skipUnless(LUAJIT, "luajit not installed")
class LuaUnitTests(unittest.TestCase):
    def test_lua_crypto_and_envelopes(self):
        # --- SHA-512 across padding boundaries
        sha = []
        for n in [0, 1, 3, 55, 56, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 1000, 70000]:
            m = os.urandom(n)
            sha.append({"msg": m, "hex": hashlib.sha512(m).hexdigest()})

        # --- Ed25519
        ed = []
        # RFC 8032 test 1 and test 2
        ed.append({"label": "rfc8032-1", "valid": True, "msg": b"",
                   "pk": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                   "sig": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"})
        ed.append({"label": "rfc8032-2", "valid": True, "msg": bytes([0x72]),
                   "pk": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                   "sig": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"})
        for n in [0, 1, 64, 200, 5000]:
            k = Ed25519PrivateKey.generate()
            m = os.urandom(n)
            sig = k.sign(m)
            pk = raw_pub(k)
            ed.append({"label": f"random-{n}", "valid": True, "msg": m, "pk": pk.hex(), "sig": sig.hex()})
            ed.append({"label": f"tampered-msg-{n}", "valid": False, "msg": m + b"x", "pk": pk.hex(), "sig": sig.hex()})
            bad = bytearray(sig); bad[5] ^= 1
            ed.append({"label": f"tampered-R-{n}", "valid": False, "msg": m, "pk": pk.hex(), "sig": bytes(bad).hex()})
            bad = bytearray(sig); bad[40] ^= 1
            ed.append({"label": f"tampered-S-{n}", "valid": False, "msg": m, "pk": pk.hex(), "sig": bytes(bad).hex()})
            other = raw_pub(Ed25519PrivateKey.generate())
            ed.append({"label": f"wrong-key-{n}", "valid": False, "msg": m, "pk": other.hex(), "sig": sig.hex()})
            # malleability: S + L is the same signature mathematically; must be rejected
            s_int = int.from_bytes(sig[32:], "little") + L_ORDER
            if s_int < 2**256:
                mal = sig[:32] + s_int.to_bytes(32, "little")
                ed.append({"label": f"malleable-{n}", "valid": False, "msg": m, "pk": pk.hex(), "sig": mal.hex()})

        # --- base64
        b64 = []
        for n in range(0, 10):
            d = os.urandom(n)
            b64.append({"input": base64.b64encode(d).decode(), "output": d})
        for bad in ["A", "AB=C", "@@@@", "AA==AA==", "AB==", "ABC="]:
            # AB== and ABC= have non-zero padding bits -> non canonical
            b64.append({"input": bad, "output": None})

        # --- envelopes
        signer_key = Ed25519PrivateKey.generate()
        signer = Signer(signer_key)
        now = int(time.time())
        expect_script = {"kind": "script", "name": "demo", "nonce": "a" * 32, "username": "alice",
                         "now": now, "min_version": 2}

        def env(**over):
            p = {"kind": "script", "name": "demo", "version": 3, "code": "return 1",
                 "nonce": "a" * 32, "user": "alice", "iat": now, "exp": now + 120}
            p.update(over)
            return signer.envelope(p).decode()

        def resign_with_other_key():
            return Signer(Ed25519PrivateKey.generate()).envelope(
                {"kind": "script", "name": "demo", "version": 3, "code": "return 1",
                 "nonce": "a" * 32, "user": "alice", "iat": now, "exp": now + 120}).decode()

        good = env()
        outer = json.loads(good)
        payload = base64.b64decode(outer["payload"])
        swapped = json.dumps({"payload": base64.b64encode(payload.replace(b"return 1", b"return 2")).decode(),
                              "sig": outer["sig"]})

        envelopes = [
            {"label": "valid", "ok": True, "body": good, "expect": expect_script},
            {"label": "code swapped", "ok": False, "body": swapped, "expect": expect_script, "reason": "signature"},
            {"label": "other signer", "ok": False, "body": resign_with_other_key(), "expect": expect_script, "reason": "signature"},
            {"label": "replayed nonce", "ok": False, "body": env(nonce="b" * 32), "expect": expect_script, "reason": "nonce"},
            {"label": "other user", "ok": False, "body": env(user="bob"), "expect": expect_script, "reason": "user"},
            {"label": "other script", "ok": False, "body": env(name="evil"), "expect": expect_script, "reason": "name"},
            {"label": "rollback", "ok": False, "body": env(version=1), "expect": expect_script, "reason": "rollback"},
            {"label": "expired", "ok": False, "body": env(iat=now - 1000, exp=now - 900), "expect": expect_script, "reason": "expired"},
            {"label": "future", "ok": False, "body": env(iat=now + 1000, exp=now + 1100), "expect": expect_script, "reason": "future"},
            {"label": "bytecode", "ok": False, "body": env(code="\x1bLJ\x02"), "expect": expect_script, "reason": "bytecode"},
            {"label": "manifest as script", "ok": False, "body": env(kind="manifest"), "expect": expect_script, "reason": "kind"},
            {"label": "server error", "ok": False, "body": '{"error":"license revoked"}', "expect": expect_script, "reason": "revoked"},
            {"label": "garbage", "ok": False, "body": "<html>", "expect": expect_script, "reason": "malformed"},
            {"label": "bad sig b64", "ok": False, "body": json.dumps({"payload": outer["payload"], "sig": "!!!!"}), "expect": expect_script},
            {"label": "truncated sig", "ok": False, "body": json.dumps({"payload": outer["payload"], "sig": outer["sig"][:-8]}), "expect": expect_script},
        ]

        vectors = {
            "sha512": sha, "ed25519": ed, "b64": b64,
            "envelope_pk": raw_pub(signer_key).hex(), "envelopes": envelopes,
        }
        with tempfile.TemporaryDirectory() as td:
            vf = Path(td) / "vectors.lua"
            vf.write_text("return " + lua_val(vectors))
            r = subprocess.run([LUAJIT, str(HERE / "lua" / "unit.lua"), str(LOADER), str(vf)],
                               capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class ServerHarness:
    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        d = Path(self.dir.name)
        self.signer = Signer.generate(d / "key.pem")
        self.db = LicenseDB(d / "lic.db")
        scripts = d / "scripts"
        scripts.mkdir()
        (scripts / "demo.lua").write_text('E2E_MARK("ran")\n')
        (d / "outside.lua").write_text("secret")
        (scripts / "manifest.json").write_text(json.dumps({
            "demo": {"version": 4, "file": "demo.lua"},
            "escape": {"version": 1, "file": "../outside.lua"},
        }))
        self.app = App(self.signer, self.db, ScriptStore(scripts),
                       limiter=RateLimiter(rate_per_min=6000, burst=1000, max_failures=5, lockout=60))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.app))
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.dir.cleanup()

    def get(self, path, license=None, nonce="0" * 32, user="alice", method="GET"):
        h = {"X-Nonce": nonce, "X-User": user}
        if license:
            h["X-License"] = license
        req = urllib.request.Request(self.url + path, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.h = ServerHarness()

    def tearDown(self):
        self.h.close()

    def open(self, env):
        payload = base64.b64decode(env["payload"])
        sig = base64.b64decode(env["sig"])
        pub = self.h.signer._key.public_key()
        pub.verify(sig, PROTOCOL.encode() + b"\0" + payload)  # raises if invalid
        return json.loads(payload)

    def test_happy_path_and_binding(self):
        key = self.h.db.add()
        st, env = self.h.get("/v1/manifest", key)
        self.assertEqual(st, 200)
        p = self.open(env)
        self.assertEqual(p["kind"], "manifest")
        self.assertIn({"name": "demo", "version": 4}, p["scripts"])
        st, env = self.h.get("/v1/script/demo", key, nonce="1" * 32)
        p = self.open(env)
        self.assertEqual((p["name"], p["version"], p["nonce"], p["user"]), ("demo", 4, "1" * 32, "alice"))
        # license is now bound to alice
        st, env = self.h.get("/v1/manifest", key, user="bob")
        self.assertEqual(st, 403)

    def test_rejects_bad_input(self):
        key = self.h.db.add()
        self.assertEqual(self.h.get("/v1/manifest")[0], 400)                        # no license
        self.assertEqual(self.h.get("/v1/manifest", "NL-NOPE-NOPE-NOPE-NOPE")[0], 403)
        self.assertEqual(self.h.get("/v1/manifest", key, nonce="xyz")[0], 400)
        self.assertEqual(self.h.get("/v1/script/..%2fx", key)[0], 404)
        self.assertEqual(self.h.get("/v1/script/escape", key)[0], 404)              # path traversal
        self.assertEqual(self.h.get("/v1/script/missing", key)[0], 404)
        self.assertEqual(self.h.get("/v1/manifest", key, method="POST")[0], 405)

    def test_script_allowlist_revoke_expiry(self):
        limited = self.h.db.add(scripts="other")
        st, env = self.h.get("/v1/manifest", limited)
        self.assertEqual(self.open(env)["scripts"], [])
        self.assertEqual(self.h.get("/v1/script/demo", limited)[0], 404)
        key = self.h.db.add()
        self.assertEqual(self.h.db.revoke(key), 1)
        self.assertEqual(self.h.get("/v1/manifest", key)[0], 403)
        expired = self.h.db.add(days=-1)
        self.assertEqual(self.h.get("/v1/manifest", expired)[0], 403)

    def test_lockout_after_failures(self):
        good = self.h.db.add()
        for _ in range(5):
            self.h.get("/v1/manifest", "NL-BAD0-BAD0-BAD0-BAD0")
        self.assertEqual(self.h.get("/v1/manifest", good)[0], 429)

    def test_keys_not_stored_in_plaintext(self):
        key = self.h.db.add()
        raw = Path(self.h.dir.name, "lic.db").read_bytes()
        self.assertNotIn(key.encode(), raw)

    @unittest.skipUnless(LUAJIT and shutil.which("curl"), "luajit/curl not installed")
    def test_end_to_end_real_loader(self):
        key = self.h.db.add()
        r = subprocess.run(
            [LUAJIT, str(HERE / "lua" / "e2e.lua"), str(LOADER), self.h.url,
             self.h.signer.public_hex(), key, "alice", "demo"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"},
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("E2E_OK version=4", r.stdout)
        self.assertIn("signature verified", r.stdout)


if __name__ == "__main__":
    unittest.main()
