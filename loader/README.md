# Neverlose secure script loader

A loader for [Neverlose](https://docs-csgo.neverlose.cc) Lua scripts. It has two parts:

* `client/loader.lua` runs inside Neverlose. You give this one file to users.
* `server/` is a small Python server. It checks license keys and serves your scripts in signed envelopes.

## How it stays secure

| Threat | Defence |
|---|---|
| Tampered or forged script (MITM, hacked web server, DNS hijack) | Every response is **Ed25519-signed**, and the loader pins the public key. The private key stays on the signing machine, so a compromised network or web host still can't get code executed. The Neverlose API has no crypto library, so the loader verifies signatures in pure Lua (tested against the RFC 8032 vectors). |
| Replaying an old captured response | The client sends a fresh random nonce. The server signs it into the response, and the loader rejects any mismatch. |
| Downgrading to an older, vulnerable version | The loader stores the highest version it has seen in `db` and refuses anything older. |
| Response meant for another user or script | The signed payload contains the username, script name and envelope kind, and all three are checked. |
| Stale or long-lived envelopes | Each envelope is valid for 120 s (`iat`/`exp`), with ±300 s allowed for clock skew. |
| Malleable or non-canonical signatures | Signatures with S ≥ L are rejected. |
| Bytecode exploits | Bytecode is refused, and only text chunks are compiled (`load(..., "t")`). |
| Loaded script reaching into the loader | Scripts run in their own environment with `debug`, `getfenv`/`setfenv`, `load*`, `dofile`, `require` and `collectgarbage` hidden. Their globals don't leak into the loader. |
| Signature domain confusion | The signed message is prefixed with `NLLOADER-V1\0`. |
| License sharing | A license binds to the first Neverlose username that uses it. Licenses can be revoked, set to expire and limited to specific scripts. |
| Leaked license database | Only SHA-256 hashes of the 128-bit license keys are stored. |
| Brute force and abuse | The server rate-limits each IP and locks it out after repeated auth failures. It strictly validates headers, accepts GET only, rejects path traversal, caps script size and times out slow clients. |

### What it cannot protect against

Client-side code can't be fully protected. Anyone who can load a script can read its source from their own process memory. The loader controls **who** gets a script and **guarantees that what runs is exactly what you signed**. It can't hide the code from someone who is allowed to run it. If you need confidentiality, keep sensitive logic on the server.

The username binding relies on what the client reports (`common.get_username()`). It stops casual key sharing, but a modified client could send another name. The license key is the real secret.

## Setup

```bash
cd loader/server
pip install -r requirements.txt

python manage.py genkey            # writes signing_key.pem (mode 600) and prints PUBLIC_KEY_HEX
python manage.py add --days 30     # prints a license key, e.g. NL-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
python manage.py add --scripts hello,other --note "customer 42"
python manage.py list | revoke <key|hash-prefix> | unbind <key|hash-prefix>
```

Put your scripts in `server/scripts/` and list them in `manifest.json`. **Bump `version` on every release.** Clients refuse to go back to an older version.

Run the server behind a TLS-terminating reverse proxy, e.g. Caddy:

```
loader.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

```bash
LOADER_TRUST_PROXY=1 python server.py
```

You can also skip the proxy and serve TLS directly with `LOADER_TLS_CERT=... LOADER_TLS_KEY=...`. The other environment variables are listed at the top of `server.py`.

Finally, edit the two lines at the top of `client/loader.lua`:

```lua
local SERVER_URL = "https://loader.example.com"
local PUBLIC_KEY_HEX = "<output of manage.py genkey>"
```

Then distribute `loader.lua`. Users load it in Neverlose, paste their license key, click **Save key** → **Refresh**, pick a script and click **Load selected**.

### Key handling

* `signing_key.pem` is the root of trust, so back it up offline. If it leaks, generate a new key and ship a new `loader.lua`.
* For the strongest setup, keep the key off the web server. Sign envelopes on a separate service, and have the web server only relay them.

## Tests

The tests need `luajit` and `curl`:

```bash
cd loader && python -m unittest discover -s tests -v
```

They check SHA-512 and Ed25519 against Python's `hashlib`/`cryptography` and the RFC 8032 vectors. They also check that tampered, replayed, rolled-back, expired, wrong-user and bytecode envelopes are rejected, and test the server's auth, binding, revocation, lockout and path traversal handling. One test runs the real `loader.lua` end to end in a mocked Neverlose runtime against a live server.

## Neverlose API notes

The docs don't cover some behaviour the loader relies on, so it is written defensively:

* `network.get`'s callback arguments aren't documented. The loader accepts either a body string or a table with a `body` field.
* `load`/`loadstring` aren't documented. The loader uses LuaJIT's `load(src, name, "t", env)` and falls back to `loadstring` + `setfenv`.
* The return value of `group:list(...):get()` is assumed to be a 1-based index.

Check these on a first in-game run.
