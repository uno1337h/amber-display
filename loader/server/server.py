"""HTTP server for the Neverlose secure loader.

Endpoints (GET only):
    /v1/manifest          signed list of scripts this license may load
    /v1/script/<name>     signed script envelope
    /healthz              liveness probe

Required request headers: X-License, X-Nonce (32 lowercase hex), X-User.

Configuration (environment variables):
    LOADER_KEY        path to the Ed25519 signing key   (default: signing_key.pem)
    LOADER_DB         path to the SQLite license db     (default: licenses.db)
    LOADER_SCRIPTS    directory with manifest.json      (default: scripts)
    LOADER_BIND       host:port                         (default: 127.0.0.1:8443)
    LOADER_TLS_CERT / LOADER_TLS_KEY   serve TLS directly (otherwise put a
                      TLS-terminating reverse proxy such as Caddy in front)
    LOADER_TRUST_PROXY=1   take client IP from the last X-Forwarded-For hop
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core import (
    ENVELOPE_TTL,
    LICENSE_RE,
    NAME_RE,
    NONCE_RE,
    USER_RE,
    LicenseDB,
    ScriptStore,
    Signer,
)

log = logging.getLogger("loader")


class RateLimiter:
    """Token bucket per client, plus a lockout after repeated auth failures."""

    def __init__(self, rate_per_min=30, burst=10, max_failures=10, lockout=900):
        self.rate = rate_per_min / 60.0
        self.burst = burst
        self.max_failures = max_failures
        self.lockout = lockout
        self._buckets: dict[str, tuple[float, float]] = {}
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            n, since = self._failures.get(client, (0, now))
            if n >= self.max_failures:
                if now - since < self.lockout:
                    return False
                self._failures.pop(client, None)
            tokens, last = self._buckets.get(client, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[client] = (tokens, now)
                return False
            self._buckets[client] = (tokens - 1, now)
            if len(self._buckets) > 100_000:  # bound memory under attack
                self._buckets.clear()
            return True

    def failure(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            n, since = self._failures.get(client, (0, now))
            self._failures[client] = (n + 1, since if n else now)

    def success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


class App:
    def __init__(self, signer: Signer, licenses: LicenseDB, scripts: ScriptStore,
                 trust_proxy: bool = False, limiter: RateLimiter | None = None):
        self.signer = signer
        self.licenses = licenses
        self.scripts = scripts
        self.trust_proxy = trust_proxy
        self.limiter = limiter or RateLimiter()


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "loader"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 10  # drop slow clients (slowloris)

        def log_message(self, fmt, *args):  # route through logging, never log headers
            log.info("%s %s", self.client_ip(), fmt % args)

        def client_ip(self) -> str:
            if app.trust_proxy:
                xff = self.headers.get("X-Forwarded-For", "")
                if xff:
                    return xff.split(",")[-1].strip()
            return self.client_address[0]

        def send_json(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.end_headers()
            self.wfile.write(body)

        def error(self, status: int, msg: str) -> None:
            self.send_json(status, ('{"error":"%s"}' % msg).encode())

        def do_GET(self):
            ip = self.client_ip()
            if self.path == "/healthz":
                return self.send_json(200, b'{"ok":true}')
            if not app.limiter.allow(ip):
                return self.error(429, "rate limited")

            if self.path == "/v1/manifest":
                name = None
            elif self.path.startswith("/v1/script/"):
                name = self.path[len("/v1/script/"):]
                if not NAME_RE.match(name):
                    return self.error(404, "not found")
            else:
                return self.error(404, "not found")

            key = self.headers.get("X-License", "")
            nonce = self.headers.get("X-Nonce", "")
            user = self.headers.get("X-User", "")
            if not LICENSE_RE.match(key) or not NONCE_RE.match(nonce) or not USER_RE.match(user):
                app.limiter.failure(ip)
                return self.error(400, "bad request")

            check = app.licenses.check(key, user)
            tag = hashlib.sha256(key.encode()).hexdigest()[:10]
            if not check.ok:
                app.limiter.failure(ip)
                log.warning("auth failed ip=%s lic=%s user=%r reason=%s", ip, tag, user, check.reason)
                return self.error(403, check.reason)
            app.limiter.success(ip)

            now = int(time.time())
            base = {"nonce": nonce, "user": user, "iat": now, "exp": now + ENVELOPE_TTL}

            if name is None:
                listing = [s for s in app.scripts.list() if check.allows(s["name"])]
                return self.send_json(200, app.signer.envelope({"kind": "manifest", "scripts": listing, **base}))

            if not check.allows(name):
                return self.error(404, "not found")
            found = app.scripts.get(name)
            if found is None:
                return self.error(404, "not found")
            version, code = found
            log.info("serve ip=%s lic=%s user=%r script=%s v%d", ip, tag, user, name, version)
            return self.send_json(200, app.signer.envelope(
                {"kind": "script", "name": name, "version": version, "code": code, **base}
            ))

        def _method_not_allowed(self):
            self.error(405, "method not allowed")

        do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _method_not_allowed

    return Handler


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signer = Signer.from_file(os.environ.get("LOADER_KEY", "signing_key.pem"))
    app = App(
        signer,
        LicenseDB(os.environ.get("LOADER_DB", "licenses.db")),
        ScriptStore(os.environ.get("LOADER_SCRIPTS", "scripts")),
        trust_proxy=os.environ.get("LOADER_TRUST_PROXY") == "1",
    )
    host, _, port = os.environ.get("LOADER_BIND", "127.0.0.1:8443").rpartition(":")
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(app))
    httpd.daemon_threads = True

    cert, key = os.environ.get("LOADER_TLS_CERT"), os.environ.get("LOADER_TLS_KEY")
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    log.info("public key %s", signer.public_hex())
    log.info("listening on %s:%s (%s)", host, port, "TLS" if cert else "plain HTTP - put a TLS proxy in front")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
