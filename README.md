# freetls

An HTTPS/TLS client for Python with **highly controllable JA4 (TLS client)
fingerprints**, built on a real TLS handshake.

`freetls` performs the handshake with a Go + [uTLS](https://github.com/refraction-networking/utls)
engine compiled to a native shared library and loaded via `cffi`. It overrides
**only the ClientHello**, so you can emit arbitrary cipher suites, extension IDs
(including unknown ones), signature algorithms, ALPN and TLS versions while Go's
`crypto/tls` handles all the cryptography (key schedule, AEAD, certificate
validation, Hello Retry Request).

Highlights:

- **JA4** control to a very high degree, with **JA3** and **JA4S** reporting.
- Three modes: **Specific**, **Partially-random**, **True-random**.
- Real **TLS 1.0–1.3** handshakes (completed where the server allows); no SSLv3.
- A catalog of **220 common-JA4 profiles** derived from uTLS's real, current
  browser presets (Chrome up to 155, Firefox 148, Safari 26.3, Edge, iOS, Android/OkHttp, 360, QQ, Go).
- Drop-in **requests**, **httpx** (sync + async) and **aiohttp** transports.
- An `ssl.SSLContext`-style `wrap_socket()` API.
- Go-side **HTTP/2** with controllable SETTINGS / WINDOW_UPDATE / pseudo-header
  order.
- **Self-verification**: JA4/JA3/JA4S are recomputed from the exact bytes the
  engine emitted and received.

The library makes **no external network calls** at runtime and never contacts
third-party fingerprint services.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Choosing a fingerprint](#choosing-a-fingerprint)
  - [Modes](#modes)
  - [Profiles catalog](#profiles-catalog)
  - [The spec model](#the-spec-model)
- [HTTP/2](#http2)
- [Certificate verification](#certificate-verification)
- [Self-verification](#self-verification)
- [API reference](#api-reference)
- [Understanding the fingerprints](#understanding-the-fingerprints)
- [Architecture](#architecture)
- [Development](#development)
- [Troubleshooting / FAQ](#troubleshooting--faq)
- [Limitations](#limitations)

---

## Requirements

- Python **3.9+** (developed on 3.14).
- `cffi` (installed automatically).
- Optional HTTP integrations: `requests` / `urllib3`, `httpx`, `aiohttp`.
- Optional certificate parity: `cryptography`.
- Only for **building from source / editable installs**: a **Go toolchain
  (Go 1.27+)**. Prebuilt wheels bundle the compiled engine, so end users don't
  need Go. Go is found via `$FREETLS_GO`, then `go` on `PATH`, then common
  locations (`~/.local/go`, `/usr/local/go`, `/opt/go`, Homebrew).

## Installation

```bash
pip install freetls            # runtime core (wheel bundles the engine)
pip install "freetls[http]"    # + requests / urllib3
pip install "freetls[async]"   # + httpx / aiohttp
pip install "freetls[pki]"     # + cryptography (Python cert parity)
pip install "freetls[test]"    # everything needed to run the test suite
```

### From a source checkout

The easiest path sets up a virtualenv and builds the engine in one step:

```bash
git clone <repo> && cd freetls
make venv          # creates .venv, installs freetls[test], compiles the engine
.venv/bin/python -c "import freetls; print(freetls.engine_version())"
```

Or, without `make`:

```bash
pip install -e ".[test]"   # builds the engine during install (needs Go)
```

If you just put `src/` on `PYTHONPATH` on a fresh clone, the engine is
**built automatically on first use** when Go is available (disable with
`FREETLS_NO_AUTOBUILD=1`). You can always build it explicitly with `make native`.

The engine shared library is searched in this order: `$FREETLS_LIB`, then
`src/freetls/_lib/`, then `native/`, then `build/`. See
[Troubleshooting](#troubleshooting--faq).

---

## Quickstart

### requests

```python
import requests, freetls
from freetls import modes

session = requests.Session()
session.mount(
    "https://",
    freetls.JA4Adapter(spec=modes.baseline_spec(server_name="example.com")),
)
r = session.get("https://example.com/")
print(r.status_code)
```

The most recent connection's fingerprint is available on the adapter:

```python
adapter = freetls.JA4Adapter(spec=modes.baseline_spec(server_name="example.com"))
session = requests.Session(); session.mount("https://", adapter)
session.get("https://example.com/")
print(adapter.last_ja4, adapter.last_ja3, adapter.last_ja4s)
```

### httpx

```python
import httpx
from freetls.transport.httpx_transport import FreeTLSTransport, AsyncFreeTLSTransport

client = httpx.Client(transport=FreeTLSTransport(spec=spec))          # sync
aclient = httpx.AsyncClient(transport=AsyncFreeTLSTransport(spec=spec))  # async
```

### aiohttp

```python
import aiohttp
from freetls.transport.aiohttp_connector import FreeTLSConnector

connector = FreeTLSConnector(spec=spec)
async with aiohttp.ClientSession(connector=connector) as s:
    async with s.get("https://example.com/") as r:
        print(r.status)
print(connector.last_session.ja4)
```

### Raw session (socket-like)

```python
import freetls
from freetls import modes

spec = modes.baseline_spec(server_name="example.com", verify=False)
with freetls.TLSSession(spec) as tls:
    tls.connect("example.com", 443, server_hostname="example.com")
    tls.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
    data = tls.recv(4096)
    print(tls.version(), tls.selected_alpn_protocol())
    print(tls.ja4, tls.ja3, tls.ja4s)
```

### ssl.SSLContext-style wrap_socket

```python
import socket
from freetls import TLSContext

ctx = TLSContext.baseline(server_name="example.com", verify=False)
sock = socket.create_connection(("example.com", 443))
with ctx.wrap_socket(sock, server_hostname="example.com") as tls:
    tls.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
    print(tls.recv(4096))
    print(tls.ja4)
```

---

## Choosing a fingerprint

There are three ways to describe the ClientHello you want to send.

### Modes

```python
from freetls import modes, Cipher, NamedGroup, SignatureScheme, TLS10, TLS12, TLS13

# 1) baseline — a broad, high-compatibility Chrome-like hello.
spec = modes.baseline_spec(server_name="example.com")

# 2) specific — exact ciphers/extensions/sigalgs/alpn/versions.
# Ciphers/groups/sigalgs accept an int, an enum member, or a name string.
spec = modes.specific(
    ciphers=[
        Cipher.TLS_AES_128_GCM_SHA256,
        Cipher.TLS_AES_256_GCM_SHA384,
        "TLS_CHACHA20_POLY1305_SHA256",
        0x1304,  # raw hex also works
    ],
    server_name="example.com",
)

# 3) partially-random — a functional baseline + configurable random padding.
spec = modes.partial_random(
    server_name="example.com",
    n_random_ciphers=10, n_random_extensions=8, seed=42,
)

# 4) true-random — maximal random padding over a minimal working core.
spec = modes.true_random(
    server_name="example.com",
    n_ciphers=80, n_extensions=40, seed=None,
)
```

All modes accept `alpn=`, `vers_min=`, `vers_max=`, `verify=` and (for random
modes) `seed=`. Random modes always inject the functional set
(`supported_versions`, `key_share`, `signature_algorithms`, `supported_groups`,
one server-supported cipher, SNI/ALPN as configured) so the handshake still
completes. Padding is drawn only from **assigned IANA values**, and only from
extensions a server safely ignores (`modes.SAFE_PADDING_EXT_IDS`).

| Mode | You control | Range | Handshake-safe |
|------|-------------|-------|----------------|
| `specific` | ciphers, extensions, sigalgs, alpn, versions | exact | yes (baseline injected) |
| `partial_random` | baseline + counts of random padding | large | yes |
| `true_random` | random counts over the whole assigned universe | maximal | yes (minimal core) |

### Named constants (no hex needed)

freetls ships importable `IntEnum`s built from the IANA tables, so you never
have to memorise hex IDs:

```python
from freetls import Cipher, ExtensionType, SignatureScheme, NamedGroup

Cipher.TLS_AES_128_GCM_SHA256 == 0x1301
Cipher["TLS_AES_128_GCM_SHA256"]           # lookup by name
Cipher(0x1301).name                        # reverse lookup -> "TLS_AES_..."
ExtensionType.SERVER_NAME, ExtensionType.ALPN, ExtensionType.SNI   # aliases
SignatureScheme.RSA_PSS_RSAE_SHA256 == 0x0804
NamedGroup.X25519 == 0x001D
```

Because every member **is** an `int`, enums, hex ints, and name strings are
freely interchangeable anywhere a value is expected:

```python
from freetls import Extension, SignatureScheme, NamedGroup

Extension.signature_algorithms("rsa_pss_rsae_sha256", SignatureScheme.ECDSA_SECP256R1_SHA256)
Extension.supported_curves(NamedGroup.X25519, "secp256r1", 0x0018)
modes.specific(ciphers=["TLS_AES_128_GCM_SHA256", "tls_aes_256_gcm_sha384"])
```

Name matching is case-insensitive. An unknown name raises a clear `ValueError`
(e.g. `unknown cipher name: 'NOT_A_CIPHER'`). The tables/lookups live in
`freetls.fingerprint.tables` (`as_cipher`/`as_group`/`as_sigalg`/`as_extension`,
`cipher_name`/`cipher_value`, …).

### Profiles catalog

`freetls.profiles` ships real-world fingerprints you can select by name:

```python
from freetls import profiles

profiles.names()                      # 220 aliases, e.g. "chrome_155"
p = profiles.get("chrome_133")        # -> Profile(name, alias, preset, ja4, ja3, ...)
spec = p.spec(server_name="example.com", verify=False)

# or in one call:
spec = profiles.spec("firefox_120", server_name="example.com")
print(profiles.catalog_info())        # {"count": 220, "distinct_ja4": 110, ...}
```

Each profile's stored `ja4` is produced by the engine and verified by tests.
Profiles are built from uTLS presets plus realistic variants (HTTP/1.1-only,
no ALPN, no SNI). Presets whose JA4 is nondeterministic (extension shufflers
with GREASE-dependent padding) are excluded automatically, so a missing alias is
expected.

### The spec model

`FingerprintSpec` is the one object that describes a hello:

```python
from freetls import FingerprintSpec, Extension, TLS12, TLS13

spec = FingerprintSpec(
    ciphers=[0x1301, 0x1302],
    vers_min=TLS12, vers_max=TLS13,
    server_name="example.com",
    verify=True, root_ca="/path/ca.pem",
    timeout_ms=30000,
    extensions=[
        Extension.sni("example.com"),
        Extension.supported_versions(TLS13, TLS12),
        Extension.supported_curves(0x001D, 0x0017),
        Extension.ec_point_formats(0),
        Extension.signature_algorithms(0x0403, 0x0804),
        Extension.key_share(0x001D),
        Extension.psk_key_exchange_modes(1),
        Extension.alpn("h2", "http/1.1"),
        Extension.generic(0x1234, "aabbcc"),   # arbitrary extension ID + hex data
    ],
)
```

`Extension.kind` is one of: `sni`, `alpn`, `supported_versions`,
`supported_curves`, `ec_point_formats`, `signature_algorithms`, `key_share`,
`psk_key_exchange_modes`, `extended_master_secret`, `renegotiation_info`,
`session_ticket`, `status_request`, `sct`, `compress_certificate`, `padding`,
`application_settings`, `generic`, `grease`. Use `generic` for arbitrary,
server-ignored extension IDs (the basis of JA4_c range).

Specs also carry H2 fields (`h2_settings`, `h2_window_update`,
`h2_pseudo_header_order`) and profile fields (`preset`, `preset_no_sni`,
`preset_alpn`).

---

## HTTP/2

The Go engine includes its own HTTP/2 client so the H2 fingerprint is fully
controllable (SETTINGS values and order, connection WINDOW_UPDATE, and
pseudo-header order):

```python
import freetls
from freetls import modes

spec = modes.baseline_spec(server_name="example.com", alpn=["h2"])
spec.h2_settings = [[1, 65536], [2, 0], [4, 6291456], [6, 262144]]
spec.h2_window_update = 15663105
spec.h2_pseudo_header_order = ["method", "authority", "scheme", "path"]

with freetls.TLSSession(spec) as s:
    s.connect("example.com", 443, server_hostname="example.com")
    r = s.h2_request("/", headers=[["user-agent", "freetls"], ["accept", "*/*"]])
    print(r["status"], r["body"])
    print(r["sent_settings"], r["sent_window_update"], r["sent_pseudo_header_order"])
```

`h2_request(path, method="GET", headers=None, body=b"", scheme="https")` returns
a dict: `status`, `headers`, `body`, `body_b64`, and the `sent_*` fields echoing
exactly what was placed on the wire. Set `alpn=["h2"]` (or include it) so the
server negotiates HTTP/2.

---

## Certificate verification

The engine verifies with Go `crypto/x509`. Control it through the spec:

```python
spec = modes.baseline_spec(server_name="example.com", verify=True)
spec.root_ca = "/path/to/ca.pem"     # system roots are used when omitted
```

> **Important:** for the freetls transports (`JA4Adapter`,
> `FreeTLSTransport`, `FreeTLSConnector`), TLS trust is governed by
> `spec.verify` / `spec.root_ca`, **not** by the host library's `verify=`
> argument. The libraries' `verify=` no longer controls the handshake because
> the freetls engine does the TLS. Set verification on the spec.

An optional Python (`cryptography`) parity hook is available for independently
validating the peer's leaf certificate (see [Self-verification](#self-verification)).

---

## Self-verification

```python
from freetls import verify

verify.fingerprints(session)         # recompute JA4/JA3/JA4S from emitted bytes
verify.assert_consistent(session)    # raises FingerprintError on any mismatch
fp = verify.probe(spec, "127.0.0.1", port, server_hostname="h")  # connect + return fp
verify.verify_peer_with_python(session, ca_pem, "example.com")   # cryptography parity
```

`session.fingerprints` (and `session.ja4` / `.ja3` / `.ja4s`) are always computed
from the bytes the engine emitted (`client_hello`) and received (`server_hello`),
never from the spec. You can inspect those raw handshake bytes yourself:

```python
session.client_hello    # bytes: the exact ClientHello handshake message sent
session.server_hello    # bytes: the ServerHello received (for JA4S)
```

---

## API reference

### Top level — `import freetls`

| Name | Description |
|------|-------------|
| `freetls.JA4Adapter` | requests transport adapter (lazy; needs `requests`) |
| `freetls.transport` | transport package (requests/httpx/aiohttp) |
| `freetls.TLSSession` | socket-like TLS session |
| `freetls.TLSContext` | `ssl`-style context with `wrap_socket` |
| `freetls.FingerprintSpec`, `freetls.Extension` | the spec model |
| `freetls.Cipher`, `freetls.ExtensionType`, `freetls.SignatureScheme`, `freetls.NamedGroup` | IANA `IntEnum` constants (int-compatible; names/ints interchangeable) |
| `freetls.modes` | `baseline_spec`, `specific`, `partial_random`, `true_random` |
| `freetls.verify` | self-verification helpers |
| `freetls.JA4Adapter` / `freetls.engine_version()` | adapter / engine version string |
| `freetls.ja4_from_bytes`, `ja3_from_bytes`, `ja4s_from_bytes` | compute from raw handshake bytes |
| `freetls.parse_client_hello`, `parse_server_hello` | parse handshake bytes |
| `freetls.TLS10/11/12/13` | version constants |
| `FreeTLSError`, `EngineError`, `SpecError`, `HandshakeError`, `FingerprintError` | exceptions |

### `TLSSession`

`TLSSession(spec)`; connect with `connect(host, port=443, timeout=None, server_hostname=None)`
or `wrap_socket(sock, server_hostname)`.

- I/O: `sendall`, `send`, `recv`, `makefile("rb")`, `settimeout`, `gettimeout`,
  `fileno`, `shutdown`, `close`, context manager, `closed`.
- Fingerprints: `ja4`, `ja4_r`, `ja3`, `ja4s`, `fingerprints`, `client_hello`,
  `server_hello`.
- TLS info: `version()`, `cipher()`, `selected_alpn_protocol()`,
  `server_hostname()`, `getpeercert()` (returns `None`; use `state.peer_cert_der`),
  `state`.
- HTTP/2: `h2_request(...)`.

### `TLSContext`

`TLSContext(spec=None)` or classmethods `baseline/specific/partial_random/true_random(**kwargs)`.
Config: `set_ciphers`, `set_alpn_protocols` / `set_alpn`, `set_versions(min, max)`,
`set_server_name`, `set_verify(verify, root_ca=None)`, `load_verify_locations(cafile)`.
`wrap_socket(sock, server_hostname=None, do_handshake_on_connect=True)` returns a
`TLSSession`.

### `modes`

```python
baseline_spec(server_name=None, ciphers=None, alpn=DEFAULT_ALPN,
              sigalgs=DEFAULT_SIGALGS, groups=DEFAULT_GROUPS,
              vers_min=TLS12, vers_max=TLS13, verify=False)
specific(ciphers=None, extensions=None, server_name=None, ...)
partial_random(server_name=None, ciphers=None, alpn=..., vers_min=..., vers_max=...,
               n_random_ciphers=10, n_random_extensions=8, seed=None, verify=False)
true_random(server_name=None, alpn=..., vers_min=..., vers_max=...,
            n_ciphers=60, n_extensions=40, seed=None, verify=False)
```

### `profiles`

```python
profiles.names() -> list[str]
profiles.list_profiles() -> list[Profile]
profiles.get(name_or_alias) -> Profile | None
profiles.spec(name_or_alias, server_name=None, verify=False) -> FingerprintSpec
profiles.catalog_info() -> {"count", "distinct_ja4", "generated_by", "engine_version"}
```

### `verify`

```python
verify.fingerprints(session) -> dict
verify.assert_consistent(session) -> dict            # raises on mismatch
verify.probe(spec, host, port, server_hostname=None) -> dict
verify.python_verify_leaf(leaf_der, cafile, server_hostname, now=None)
verify.verify_peer_with_python(session, cafile, server_hostname=None)
```

### Fingerprint helpers — `freetls.fingerprint`

`ja4_from_bytes(raw)`, `ja3_from_bytes(raw)`, `ja4s_from_bytes(raw)`,
`ja4_from_spec(spec)` (offline), `first_last_alpn(value)`, plus the raw parser.

### Transports

- `freetls.JA4Adapter(spec=..., spec_factory=...)` (requests).
- `freetls.transport.httpx_transport.FreeTLSTransport` / `AsyncFreeTLSTransport`.
- `freetls.transport.aiohttp_connector.FreeTLSConnector`.
- `freetls.transport.urllib3_conn.Ja4HTTPSConnection` (the underlying urllib3
  connection class).

Pass a fixed `spec=` for a stable fingerprint, or `spec_factory=` (a callable
returning a fresh spec per connection) for per-connection randomization:

```python
adapter = freetls.JA4Adapter(
    spec_factory=lambda: modes.true_random(server_name="example.com")
)
```

---

## Understanding the fingerprints

**JA4** is a TLS ClientHello fingerprint in three `_`-separated parts
([FoxIO spec](https://github.com/FoxIO-LLC/ja4)):

```
t13d1516h2_8daaf6152771_e5627efa2ab1
│ ││ ││ │ └─ JA4_c: hash of sorted extensions + ordered sigalgs
│ ││ ││ └──── JA4_b: hash of sorted cipher suites
│ ││ │└────── ALPN first/last char (h2 -> h2, http/1.1 -> h1, none -> 00)
│ ││ └─────── extension count (2 digits, capped 99)
│ │└───────── cipher count (2 digits, capped 99)
│ └────────── SNI: d (domain) or i (none)
└──────────── version (13/12/11/10/s3/s2)
```

- GREASE values are ignored everywhere.
- `JA4_b` = first 12 hex of `sha256(sorted cipher hex list)`.
- `JA4_c` = first 12 hex of `sha256(sorted extension hex list, SNI+ALPN removed)`
  with `_` and the signature algorithms appended in their original order.
- Empty lists render as `000000000000`.
- Raw variants (`ja4_r`, `ja4_o`, `ja4_ro`) keep the unhashed lists; `ja4_from_bytes`
  returns them under those keys, and `session.ja4_r` exposes the sorted raw form.

**JA3** is the older, order-sensitive MD5 fingerprint; `session.ja3` returns it.

**JA4S** fingerprints the server's ServerHello (`session.ja4s`).

### Value universe and range

The selectable universe is **assigned IANA values only**: **356 cipher suites,
64 extensions, 49 signature schemes, 59 named groups** (regenerate with
`tools/gen_tables.py`). These are exposed as the `Cipher`, `ExtensionType`,
`SignatureScheme`, and `NamedGroup` enums (see
[Named constants](#named-constants-no-hex-needed)). `JA4_b` and `JA4_c` are
12-hex truncated SHA-256, so the
number of *distinct* JA4 values is capped at **2^48 per part (~2.8×10^14)**, and
about **2^96 (~7.9×10^28)** with a fixed header. The raw input space (subsets and
orderings of ciphers/extensions/sigalgs) is far larger — the hash truncation,
not the universe, is the binding limit.

---

## Architecture

```
Python:  requests / httpx / aiohttp / ssl-style wrap_socket
               │
         freetls.session.TLSSession  (socket-like)
               │  cffi  (freetls.engine._cffi)
Go:      native/engine.go  +  native/httpx_h2.go
               │  uTLS ClientHello override
               ▼
         crypto/tls (TLS 1.0–1.3)  +  x/net/http2
```

- Python owns the TCP connect and hands a **dup'd fd** to Go; the Go engine
  performs the TLS handshake and owns the encrypted channel. Reads/writes cross
  the cffi boundary.
- The engine takes a JSON spec (mirroring `FingerprintSpec`) and captures the
  emitted ClientHello and received ServerHello for fingerprinting.
- `native/httpx_h2.go` implements HTTP/2 over the same connection using
  `x/net/http2`'s Framer + HPACK, so the H2 fingerprint fields are explicit.

---

## Development

```bash
make help        # list targets
make venv        # create .venv + install freetls[test] + build the engine
make native      # build native/libfreetls.so (the c-shared engine)
make test        # full suite (unit + conformance + e2e + pcap)
make test-fast   # skip privileged pcap capture
make coverage    # enforce the 85% coverage gate
make gen         # regenerate IANA tables + profile catalog
make setup-caps  # one-time: make a local tcpdump capable of loopback capture
make build       # build sdist + wheel into dist/
cd native && go test ./...   # Go HTTP/2 wire test
```

`PY` and `GO` are overridable and auto-detected, so this works on any machine:

```bash
make test PY=python3.12 GO=/usr/local/go/bin/go
```

Environment knobs (all optional):

| Variable | Effect |
|----------|--------|
| `FREETLS_GO` | Path to the Go binary for source builds/tests |
| `FREETLS_LIB` | Explicit path to `libfreetls.so` (skip discovery) |
| `FREETLS_NO_AUTOBUILD` | Disable building the engine on first use |
| `FREETLS_SKIP_NATIVE` | Build/install without the native engine (docs only) |
| `FREETLS_TCPDUMP` | tcpdump used by pcap tests |

Run one test/file:

```bash
.venv/bin/python -m pytest tests/e2e/test_handshake.py -q
.venv/bin/python -m pytest "tests/unit/test_fingerprint.py::test_ja4_spec_worked_example" -q
```

The suite is entirely local: it starts self-hosted OpenSSL / Python `ssl` / Go
TLS servers and verifies with an independent pcap parser. Nothing hits the
network.

---

## Troubleshooting / FAQ

**"New engine symbols/behaviour don't show up."**
A wheel build copies the engine to `src/freetls/_lib/libfreetls.so`, which
*shadows* `native/libfreetls.so`. Delete it (`make clean`) or point the loader at
the fresh build: `FREETLS_LIB=$PWD/native/libfreetls.so`.

**"Could not load the native freetls engine."**
The loader auto-builds it from `native/` on first use when Go is present
(disable with `FREETLS_NO_AUTOBUILD=1`). Otherwise run `make native`, install the
prebuilt wheel, or set `FREETLS_LIB=/path/to/libfreetls.so`. Search order:
`$FREETLS_LIB` → `src/freetls/_lib` → `native/` → `build/`.

**Editing `native/*.go` has no effect.**
The `.so` is a build artifact; run `make native` (or `go build -buildmode=c-shared`)
and make sure no stale copy shadows it in `src/freetls/_lib/`.

**`pip install .` / the first import fails with a Go error.**
Install Go (1.27+), point at it with `FREETLS_GO=/path/to/go`, or install the
prebuilt wheel. Builds fetch Go modules, so a network connection is needed the
first time (or `cd native && go mod download` ahead of time). To build without
the engine (docs only): `FREETLS_SKIP_NATIVE=1 pip install .`.

**pcap tests are skipped.**
They need a tcpdump able to capture loopback. Run `make setup-caps` once
(Linux); on macOS loopback capture needs root, so run those tests under `sudo`
or point `FREETLS_TCPDUMP` at a capable binary. Without it the `pcap`-marked
tests skip rather than fail.

**`freetls.JA4Adapter` raises `ModuleNotFoundError`.**
Install the HTTP extra: `pip install "freetls[http]"`.

**A profile alias is missing.**
Presets whose JA4 is nondeterministic (extension shufflers with GREASE-dependent
padding) are excluded by design.

**Certificate errors with the transports.**
Set verification on the spec: `spec.verify = True` and `spec.root_ca = ...`
(the host library's `verify=` no longer controls the freetls handshake).

**aiohttp hangs on shutdown.**
`FreeTLSConnector` bridges the blocking engine onto an asyncio transport; use a
`spec.timeout_ms` and close the `ClientSession` within an event loop, as usual.

---

## Limitations

- **JA4H is out of scope** (only JA4, JA3 and JA4S).
- **No SSLv3.** TLS 1.0/1.1 handshakes only complete against servers that still
  accept them; modern servers will refuse, as expected.
- **JA4 collisions are bounded by the 12-hex truncation**; random modes cannot
  produce more than ~2^48 distinct values per part.
- Cross-platform wheel artifacts (macOS/Windows) are produced by the same build
  system on those platforms; this checkout is exercised on Linux/CPython 3.14.
