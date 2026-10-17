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

- **JA4** control to a very high degree, with **JA3**, **JA3N**, **JA4S**,
  **JA4X**, **JA4H** and the **Akamai HTTP/2** fingerprint reporting.
- Three modes: **Specific**, **Partially-random**, **True-random**.
- Real **TLS 1.0–1.3** handshakes (completed where the server allows); no SSLv3.
- A catalog of **248 common-JA4 profiles** derived from uTLS's real, current
  browser presets (Chrome up to 155, Firefox 148, Safari 26.3, Edge, iOS, Android/OkHttp, 360, QQ, Go) plus 28 QUIC profiles.
- Drop-in **requests**, **httpx** (sync + async) and **aiohttp** transports;
  requests and httpx select **HTTP/2 automatically via ALPN** (aiohttp is
  HTTP/1.1-only and offers a safe ALPN).
- An `ssl.SSLContext`-style `wrap_socket()` API, **Happy Eyeballs** (RFC 8305)
  connect, and **NSS key-log** (`SSLKEYLOGFILE`) export.
- Go-side **HTTP/2** with controllable SETTINGS / WINDOW_UPDATE / pseudo-header
  order; multi-request connections with flow control.
- **HTTP/3 / QUIC**: a spoofable QUIC Initial, JA4q/JA4Sq, a concurrent
  `QUICSession`, RFC 9297 datagrams, and opt-in HTTP/3 in the transports.
- **Self-verification**: JA4/JA3/JA4S are recomputed from the exact bytes the
  engine emitted and received.

The library makes **no external network calls** at runtime and never contacts
third-party fingerprint services.

> **Warning — unsafe by default.** `freetls` lets you offer arbitrary cipher
> suites and extension IDs. By default it does **not** verify that the engine
> can *complete* the suites you offer, so if a server selects an unbacked suite
> the handshake fails. Turn on **safe mode** (`freetls.set_safe_mode(True)` or
> `FingerprintSpec(safe=True)`) to reject any spec the engine cannot back. See
> [Safe & unsafe mode](#safe--unsafe-mode).

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Choosing a fingerprint](#choosing-a-fingerprint)
  - [Modes](#modes)
  - [Profiles catalog](#profiles-catalog)
  - [Custom & registered profiles](#custom--registered-profiles)
  - [The spec model](#the-spec-model)
- [Safe & unsafe mode](#safe--unsafe-mode)
- [Wide cipher support (libcrypto)](#wide-cipher-support-libcrypto)
- [HTTP/2](#http2)
- [HTTP/3](#http3)
- [Certificate verification](#certificate-verification)
- [Timeouts](#timeouts)
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
- **Prebuilt wheels bundle the compiled engine** (both the wide and the Go-only
  builds), so end users need **no build tools**.
- **Only for building from source / editable installs:**
  - a **Go toolchain (Go 1.27+)**;
  - a **C toolchain** (`gcc`/`cc`), **`perl`** and **`make`** — the default
    *wide* engine links a static OpenSSL built from the
    `native/third_party/openssl` submodule, whose `Configure` is a Perl script;
  - **network access the first time**, to fetch that submodule (shallow);
  - set **`FREETLS_NO_OPENSSL=1`** to build the **Go-only** engine instead, which
    needs only Go (no perl/make/OpenSSL).

  Go is found via `$FREETLS_GO`, then `go` on `PATH`, then common locations
  (`~/.local/go`, `/usr/local/go`, `/opt/go`, Homebrew).

## Installation

```bash
pip install freetls            # runtime core (wheel bundles the engine)
pip install "freetls[http]"    # + requests / urllib3
pip install "freetls[async]"   # + httpx / aiohttp
pip install "freetls[pki]"     # + cryptography (Python cert parity)
pip install "freetls[content]" # + brotli / zstandard content decoding
pip install "freetls[test]"    # everything needed to run the test suite
```

### From a source checkout

The easiest path sets up a virtualenv and builds the engine in one step:

```bash
git clone --recurse-submodules --shallow-submodules --depth 1 <repo> && cd freetls
make venv          # creates .venv, installs freetls[test], builds the WIDE engine
.venv/bin/python -c "import freetls; print(freetls.engine_version())"
```

`make venv` / `pip install .` build the **wide** engine by default (Go + a static
OpenSSL `libcrypto`), fetching the OpenSSL submodule (shallow) and compiling it
if needed. To build the dependency-free **Go-only** engine instead:

```bash
FREETLS_NO_OPENSSL=1 pip install -e ".[test]"   # Go-only (no perl/make/OpenSSL)
make native-go                                  # or, in a checkout
```

There is **no runtime auto-build**: the engine is compiled at install time and
merely loaded at runtime. Build it explicitly with `make native` (wide) or
`make native-go` (Go-only); switch between them at runtime with
`freetls.use_engine(freetls.Engine.GO)` (see
[Wide cipher support](#wide-cipher-support-libcrypto)).

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

`TLSContext` / `TLSSession` are **`ssl`-like, not `ssl`-compatible**. The
surface that exists — `connect`, `sendall`/`send`, `recv`, `makefile`,
`settimeout`, `close`, `selected_alpn_protocol`, `version`, `cipher`,
`getpeercert`, `wrap_socket` — behaves like its `ssl` counterpart, but this is
not a drop-in `ssl.SSLSocket`: it is **blocking-only**
(`setblocking(False)` raises), `pending()` always returns `0`, and there is no
memory BIO, no `SSLObject`, no `SSLContext.set_*` callback surface
(`set_servername_callback`, `set_ciphers`, `set_alpn_protocols`, …) and no
non-blocking handshake resumption. (Key-log export is available via
`FingerprintSpec.keylog`.) Porting existing `ssl` code requires adapting the I/O
loop. See [Limitations](#limitations) for the full list.

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

### GREASE & padding control

GREASE (RFC 8701) code points make a ClientHello look browser-like; servers
ignore them, and JA4/JA3 exclude them by value. `modes.GREASE_VALUES` holds the
16 reserved values.

```python
from freetls import modes, Extension

# Inject GREASE into the cipher/group/version slots + a GREASE extension.
spec = modes.baseline_spec(server_name="example.com", grease=True, seed=1)

# Or add it to an existing spec with fine-grained control.
modes.add_grease(spec, ciphers=True, groups=True, versions=True,
                 extensions=True, strategy="fixed")   # "random" (default) or "fixed"

# Padding: fixed byte length, or uTLS's Boring-style heuristic (no argument).
spec.extensions.append(Extension.padding(300))
spec.extensions.append(Extension.padding())
```

### TLS response extras & resumption

```python
from freetls import modes, Extension
from freetls.model import TLS12

spec = modes.baseline_spec(server_name="example.com")
spec.compression = [0]                                  # legacy compression method
spec.extensions.append(Extension.record_size_limit(16385))
spec.extensions.append(Extension.application_settings("h2"))   # ALPS

# Session resumption: enable the shared client session cache and keep the
# resumption extension. TLS 1.2 uses session_ticket, TLS 1.3 pre_shared_key
# (place it last). session.did_resume reports whether the handshake resumed.
spec.session_cache = 32
spec.extensions.append(Extension("session_ticket"))

# TLS 1.3:
tls13 = modes.baseline_spec(server_name="example.com")
tls13.session_cache = 32
tls13.extensions.append(Extension.pre_shared_key())

session = ...                                          # after handshake
session.did_resume                                     # bool
session.ocsp_response                                  # stapled OCSP (bytes)
session.signed_certificate_timestamps                  # list[bytes]
session.peer_application_settings                      # ALPS payload (bytes)
```

`did_resume` is available on a `TLSSession`; the OCSP/SCT/ALPS accessors return
empty values when the peer did not provide them.

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
print(profiles.catalog_info())        # {"count": 248, "quic_count": 28, ...}
```

Each profile's stored `ja4` is produced by the engine and verified by tests.
Profiles are built from uTLS presets plus realistic variants (HTTP/1.1-only,
no ALPN, no SNI). Presets whose JA4 is nondeterministic (extension shufflers
with GREASE-dependent padding) are excluded automatically, so a missing alias is
expected. For presets whose JA4 is stable but JA3 is not (extension shufflers),
`ja3` is left blank.

The catalog is generated from the uTLS version pinned in `native/go.mod`:
`tools/gen_presets.py` derives the preset list (and drops presets uTLS cannot
build), and `tools/gen_catalog.py` enumerates the profiles. Run `make gen` after
bumping uTLS. The `_Auto` aliases (`chrome_auto`, `firefox_auto`,
`safari_auto`, …) always track uTLS's latest version.

#### Search, export and HTTP/2 bundles

```python
from freetls import profiles

profiles.find_ja4("t13d1516h2_8daaf6152771")   # match by JA4 (exact/prefix/substr)
profiles.search("chrome")                      # match by name/alias/JA3

profiles.export()                              # list[dict] of all profiles
profiles.save_file("my_profiles.json")         # JSON loadable by load_file()
profiles.load_file("my_profiles.json")

# A profile spec with per-profile HTTP/2 controls applied:
spec = profiles.h2_bundle("chrome_155",
                          settings=[[1, 65536], [4, 131072]],
                          window_update=15663105,
                          pseudo_header_order=["method", "authority", "scheme", "path"])
```

A captured ClientHello can be converted back into a uTLS `ClientHelloSpec`
document (so it can be replayed as `FingerprintSpec(chlo_json=...)`):

```python
from freetls.fingerprint import chlo_json_from_raw

spec = freetls.FingerprintSpec(chlo_json=chlo_json_from_raw(captured_hello_bytes))
```

### Custom & registered profiles

You are not limited to the shipped catalog. Register your own profiles at
runtime — from a uTLS preset name or from a full **ClientHelloSpec JSON**
document — with no code changes:

```python
from freetls import profiles

# From a uTLS preset name:
profiles.add_profile("my_chrome", preset="HelloChrome_155")

# From a ClientHelloSpec JSON document (uTLS schema; names come from uTLS's
# dictionaries, e.g. cipher suites "TLS_AES_128_GCM_SHA256", groups "x25519",
# extensions "supported_versions"/"key_share"/...):
profiles.add_profile(
    "my_custom",
    chlo_json='{"cipher_suites": ["TLS_AES_128_GCM_SHA256"], '
              '"compression_methods": ["NULL"], '
              '"extensions": [{"name": "server_name"}, '
              '{"name": "supported_versions", "versions": ["TLS 1.3"]}, '
              '{"name": "key_share", "client_shares": [{"group": "x25519"}]}], '
              '"min_vers": 772, "max_vers": 772}',
)

profiles.get("my_custom").spec(server_name="example.com")   # used like any profile
profiles.names()                                            # includes "my_custom"

# Or load a batch from a JSON file (a list, or {"profiles": [...]}):
profiles.load_file("extra_profiles.json")
```

`ja4`/`ja3` are computed from the engine automatically; a malformed JSON
document or unknown name raises a clear error (never crashes). A raw spec can
also be used directly without registering it:

```python
from freetls import FingerprintSpec
spec = FingerprintSpec(chlo_json=chlo_json, server_name="example.com")
```

This is the escape hatch for the newest browser versions or any custom client:
scan for a ClientHello, convert it to the uTLS JSON schema, register it, and
`freetls` will drive a real handshake with that fingerprint.

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
`h2_pseudo_header_order`), preset fields (`preset`, `preset_no_sni`,
`preset_alpn`), and `chlo_json` (a full ClientHelloSpec JSON document — see
[Custom & registered profiles](#custom--registered-profiles)).

---

## Safe & unsafe mode

`freetls` can offer **any** cipher suite or extension ID — that is the point.
But the engine can only *complete* the suites it backs. By default `freetls`
does **not** check this, so offering a suite the engine cannot finish makes the
handshake fail (with `HandshakeError`) if a server selects it.

**Safe mode** validates the *effective* ClientHello (after preset / `chlo_json`
/ random expansion) against the engine's backed ciphers and an extension
whitelist, and raises `SpecError` otherwise:

```python
import freetls

freetls.set_safe_mode(True)                       # global default (off by default)
spec = freetls.modes.baseline_spec(server_name="example.com", safe=True)  # per-spec
spec = freetls.modes.safe_random(server_name="example.com")               # always safe
```

- **Whitelisted extensions**: SNI, ALPN, `supported_versions`,
  `supported_groups`, `ec_point_formats`, `signature_algorithms`, `key_share`,
  `psk_key_exchange_modes`, `extended_master_secret`, `renegotiation_info`,
  `session_ticket`, `status_request`, SCT, `compress_certificate`, `padding`,
  `application_settings` (ALPS), `pre_shared_key`, `record_size_limit`.
- **GREASE is always exempt** (JA4 excludes it).
- Modern **browser presets fail safe mode** (they carry GREASE-ECH and trust
  anchors, and some unbacked ciphers); safe mode is for fully-backed
  custom/simple configs. Of the 220-profile catalog, 75 pass with the default
  engine.
- For randomized workloads, use `modes.safe_random(...)` (or `safe=True` on
  `partial_random`/`true_random`). The defaults are **adaptive**: the cipher and
  extension *counts* are drawn uniformly over the whole feasible range, so the
  `JA4_a` count fields vary per call (fixing them freezes that field), and the
  sets are drawn uniformly, which saturates the 48-bit `JA4_b`/`JA4_c` hashes.
  The reachable space is bounded structurally: `JA4_b`/`JA4_c` are 48-bit, and in
  safe mode only five padding extensions are engine-backed, so safe `JA4_c` is
  capped at 2⁵ — the unsafe modes (44 padding extensions) reach ~2⁴⁴. On the
  Go-only engine the cipher pool is smaller and the space shrinks accordingly.

`FingerprintSpec.safe` overrides the global setting per spec (`None` = global).
The default is **unsafe**, for backward compatibility.

## Wide cipher support (libcrypto)

The **default** engine is the **wide** engine: it completes the suites Go
`crypto/tls` implements (plus uTLS's legacy ChaCha20, the forked finite-field
DHE / PSK / SRP families) *and* links an OpenSSL `libcrypto` (EVP) backend that
adds the ARIA-GCM, AES-CCM / CCM_8, Camellia-CBC and TLS 1.3 CCM families — 66
suites the Go-only engine does not offer — for **144** completable suites. The
Go-only engine (**78** suites) is built as an alternate:

```bash
make native          # default: WIDE engine, static libcrypto (symbol-hidden)
make native-go       # alternate: Go-only engine (no OpenSSL)
make native-dynamic  # dev: wide engine, dynamic system libcrypto
```

`make native` (and `pip install .`) build `native/third_party/openssl` — a pinned
OpenSSL 3.5.5 git submodule — as a static PIC `libcrypto.a`, link it into
`libfreetls.so` with hidden symbols (`-Wl,-Bsymbolic -Wl,--exclude-libs,ALL`),
and depend on no system `libcrypto`. Wheels bundle **both** engines.

Switch engines at runtime (no restart) with the string-free API:

```python
import freetls
freetls.use_engine(freetls.Engine.GO)      # 78 suites
freetls.use_engine(freetls.Engine.WIDE)    # 144 suites (default)
with freetls.engine_context(freetls.Engine.GO):   # scoped, restored on exit
    ...
print(freetls.current_engine())            # EngineInfo(kind, path)
```

Live sessions keep the engine they were created with; new sessions use the
current engine. Offered suites can be inspected with
`freetls.engine.supported_ciphers()`; the safe-mode extension whitelist with
`freetls.engine.supported_extensions()`.

### Updating OpenSSL

The OpenSSL source is a pinned, **shallow** git submodule
(`native/third_party/openssl`). To move to a newer release and rebuild
transparently:

```bash
make update-openssl TAG=openssl-3.5.6
# or: tools/update_openssl.sh openssl-3.5.6
```

This shallow-fetches the tag, updates the submodule pointer, and rebuilds
`libcrypto.a` + the wide engine, printing the old → new version. The Makefile
records the submodule commit + Configure args in a stamp
(`native/third_party/openssl/.freetls-built`), so `make native` **auto-rebuilds**
whenever the submodule commit or the Configure flags change (e.g. after a
`git submodule update`). Always rebuild/republish wheels after bumping OpenSSL so
security fixes are picked up.

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

### HTTP/2 through the transports

When a transport offers `h2` in ALPN and the server selects it, the request is
executed with the Go HTTP/2 client (controllable SETTINGS/pseudo-header order
and all). Otherwise the transport speaks HTTP/1.1:

```python
# requests / httpx: HTTP/2 is chosen automatically when the server negotiates it
spec = modes.baseline_spec(server_name="example.com", alpn=["h2", "http/1.1"])
s = requests.Session()
adapter = freetls.JA4Adapter(spec=spec)
s.mount("https://", adapter)
r = s.get("https://example.com/")
print(adapter.last_session.selected_alpn_protocol())   # "h2" when negotiated
```

### HTTP/2 limitations

The H2 client is purpose-built to make the *fingerprint* controllable, not to be
a general HTTP/2 stack. The current gaps:

- **No frame splitting (known limitation, can break large requests).** The
  request HEADERS block and the request body are each written as a **single
  frame** (`EndHeaders`/`EndStream` set immediately) with no splitting at the
  peer's `SETTINGS_MAX_FRAME_SIZE` (default 16 384 bytes). A request body or
  header block larger than that emits an oversized frame, which a strict server
  rejects with a `FRAME_SIZE_ERROR` connection error. Keep H2 request bodies
  under 16 KB until this is fixed. (Inbound frames *are* handled correctly —
  the reader reassembles `CONTINUATION`.)
- **No HPACK encoding control.** Request headers are encoded with a default
  `hpack.Encoder` (4 KiB dynamic table, Huffman on). HPACK representation
  choices are themselves a fingerprint surface and are not configurable; only
  the SETTINGS values, the connection `WINDOW_UPDATE`, and pseudo-header order
  are.
- **One stream per connection, no multiplexing.** `h2_request` opens stream 1,
  writes the request, and reads frames until that stream ends; there is no
  concurrent-stream support. Request concurrency therefore comes from opening
  more connections, not from multiplexing.
- **No priority, no server push.** Priority signalling (RFC 7540 §5.3) is never
  sent; `PUSH_PROMISE` and `RST_STREAM` frames are ignored by the read loop.
  Server push is disabled by default (`SETTINGS_ENABLE_PUSH=0`) and is not
  handled even if you re-enable it through `h2_settings`.
- **aiohttp cannot speak HTTP/2 at all** (see below) — it is HTTP/1.1-only.

## HTTP/3

HTTP/3 is available on both engines, built on the vendored **uQUIC** fork of
quic-go (itself built on our uTLS fork). Python owns the UDP socket and passes a
dup'd fd to Go; JA4q/JA4Sq are computed from the bytes the stack actually
emitted. HTTP/3 is **opt-in** (Alt-Svc discovery is out of scope), and the
transport multiplexes on the wire, so concurrent requests share one QUIC
connection.

```python
import freetls
from freetls import modes

spec = modes.quic_baseline_spec(server_name="example.com")
with freetls.QUICSession(spec) as s:
    s.connect("example.com", 443, server_hostname="example.com")
    r = s.request("/", headers=[["user-agent", "freetls"], ["accept", "*/*"]])
    print(r["status"], r["body"])
    print(s.ja4q, s.ja4sq)
```

- `QUICSession.request(path, method="GET", headers=None, body=b"")` mirrors
  `h2_request`; it returns `status`, `headers`, `body`, `body_b64` and the JA4H.
- `modes.quic_baseline_spec` / `quic_specific` / `quic_partial_random` /
  `quic_true_random` build TLS-1.3-only, `h3`-ALPN QUIC specs.
- `profiles.get("QUICChrome_146_IPv4")` returns a QUIC profile; the catalog
  merges 28 QUIC entries (7 uQUIC fingerprints × 4 variants) with the TCP ones,
  and `find_ja4`/`search` span both.
- RFC 9297 datagrams are opt-in: set `spec.quic_datagrams = True`, then use
  `open_datagram_flow()` / `send_datagram()` / `recv_datagram()` /
  `close_datagram_flow()`.
- Through the transports, HTTP/3 is opt-in:
  `FreeTLSTransport(..., http3=True)` and `JA4Adapter(..., http3=True)`.

### HTTP/3 limitations

- **No Alt-Svc / HTTPS-RR discovery.** The caller asks for HTTP/3; freetls does
  not discover it.
- **No proxies over QUIC** (CONNECT-UDP/MASQUE).
- **aiohttp stays HTTP/1.1-only** (as it is for HTTP/2).
- **TLS 1.3 CCM is not negotiable end-to-end** against Go/OpenSSL servers (it is
  covered at the AEAD level); see [Limitations](#limitations).
- **Response header order is not preserved** (Go's `http.Header` is a map);
  duplicate values are kept. The H2 path does preserve order.
- **0-RTT and ECH over QUIC are not implemented yet** (designed for; see
  `docs/route-c-plan.md`). Session resumption is **not** deferred: it works
  through the standard spec fields (`session_cache` plus a `pre_shared_key`
  extension), like the TCP path.
- **A custom `transport_parameters=` list must be complete.** uQUIC takes the
  transport parameters from the spec alone, so a partial list (e.g. only
  `max_idle_timeout`) still handshakes but then breaks every HTTP/3 request. Use
  `modes.default_quic_transport_parameters()` as the base; the engine only injects
  `initial_source_connection_id` and, when `quic_datagrams` is set,
  `max_datagram_frame_size`.

## Streaming & content decoding

The httpx transports stream response bodies (HTTP/1.1 chunk-by-chunk, HTTP/2 as
a single body frame) and the aiohttp connector feeds data to the event loop as
it arrives, so `client.stream(...)` / `iter_chunked(...)` work and the loop is
never blocked:

```python
import httpx
from freetls import modes
from freetls.transport.httpx_transport import FreeTLSTransport

t = FreeTLSTransport(spec=modes.baseline_spec(server_name="example.com"))
with httpx.Client(transport=t) as c:
    with c.stream("GET", "https://example.com/") as r:
        for chunk in r.iter_raw():        # incremental bytes
            ...
```

`gzip`, `deflate`, `brotli` and `zstd` bodies are decoded transparently
(`brotli`/`zstd` require the optional `freetls[content]` extra; httpx also
decodes them itself when its extras are installed).

**Response streaming is incremental; request-body streaming is not.** Response
bodies arrive incrementally in every transport (H1 chunk-by-chunk, H2 as DATA
frames as they are read, aiohttp fed to the loop as data lands). Request bodies
are a different story — the engine's `h2_request` and `write` take a **complete
buffer**:

- **HTTP/2:** the body is coerced with `bytes(body)` before the call, so a
  generator/iterator body is **not supported** on the H2 path, and any body is
  buffered in full. Combined with the frame-splitting gap above, H2 request
  bodies are also capped at the 16 KB single-frame budget.
- **httpx (H1 and H2):** the transport calls `request.read()`, so a streaming
  `content=<iterator>` body is **materialised in memory** before it is sent.
- **requests / urllib3 (H1 only):** an iterable body is handed to urllib3, which
  can send it with chunked transfer encoding; this is the one path that streams
  a request body.
- **aiohttp (H1 only):** the connector's transport `write()` forwards whatever
  aiohttp's payload writer hands it, so chunked/streamed request bodies are
  passed through as they are produced.

For large uploads prefer HTTP/1.1, or stream explicitly through the raw
`TLSSession.write`.

### Server-Sent Events

`freetls.sse.iter_sse` parses a `text/event-stream` byte iterable into
`SSEEvent` objects (`data`/`event`/`id`/`retry`, comment handling, multi-line
data):

```python
import freetls

with c.stream("GET", "https://example.com/events") as r:
    for ev in freetls.sse.iter_sse(r.iter_bytes()):
        print(ev.event, ev.data)
```

- **requests** and **httpx** (sync + async) auto-select H2 via ALPN.
- **aiohttp** is HTTP/1.1-only, so `FreeTLSConnector` strips `h2` from the
  offered ALPN (preventing an HTTP/1.1-on-H2 mismatch). Use the httpx async
  transport when you need HTTP/2.
- httpx exposes the negotiated version as `transport.last_http_version`.
- The async transports run the blocking engine call in a worker thread, so the
  asyncio event loop is never blocked.

---

## Certificate verification

The engine verifies with Go `crypto/x509`. **Verification is on by default**
(secure by default, like `requests`/`ssl`):

```python
spec = modes.baseline_spec(server_name="example.com")   # verify defaults to True
spec.root_ca = "/path/to/ca.pem"                         # system roots when omitted
```

For local self-signed servers, opt out explicitly per spec
(`verify=False`) or globally:

```python
import freetls
freetls.set_default_verify(False)   # e.g. in tests / fingerprinting labs
```

> **Important:** for the freetls transports (`JA4Adapter`,
> `FreeTLSTransport`, `FreeTLSConnector`), TLS trust is governed by
> `spec.verify` / `spec.root_ca`, **not** by the host library's `verify=`
> argument. The libraries' `verify=` no longer controls the handshake because
> the freetls engine does the TLS. Set verification on the spec.

Access the peer certificate chain with
`session.getpeercert(binary_form=True)` (DER bytes; the leaf), and an optional
Python (`cryptography`) parity hook for independent validation (see
[Self-verification](#self-verification)).

### Trust, pinning and mTLS

The full certificate suite is configured on the spec (or via `TLSContext`):

```python
spec = modes.baseline_spec(server_name="example.com")
spec.verify = True
spec.system_roots = False            # don't use the OS trust store
spec.root_ca = "/path/ca.pem"        # PEM file
spec.ca_dir = "/path/ca.d"           # directory of PEM certs
spec.cadata = "-----BEGIN CERTIFICATE-----\n..."   # inline PEM bundle
spec.check_hostname = False          # verify the chain but not the name

spec.pinned_sha256 = ["<base64 sha256 of leaf DER or SPKI>"]  # pinning

spec.client_cert = "/path/client.pem"    # mTLS (files) ...
spec.client_key = "/path/client.key"
spec.client_cert_pem = "<PEM text>"      # ... or inline PEM
spec.client_key_pem = "<PEM text>"
```

Equivalent `TLSContext` helpers: `set_verify`, `set_check_hostname`,
`set_system_roots`, `load_verify_locations(cafile, capath, cadata)`,
`set_client_cert(cert, key, cert_pem=..., key_pem=...)`,
`set_pinned_sha256(pins)`.

Inspect the peer chain:

```python
session.getpeercert(binary_form=True)   # leaf DER bytes
session.getpeercert()                   # dict (subject/issuer/SAN/…) via cryptography
session.peer_chain()                    # list[DER], leaf first
```

### Pre-shared keys (PSK), SRP and anonymous suites

The TLS 1.2 PSK family (RFC 4279/5487/5489) is supported by setting both PSK
credential fields on the spec. ``psk`` is hex-encoded. Offer a PSK cipher suite
(see ``freetls.engine.supported_ciphers()``) alongside the credentials:

```python
spec = modes.specific(ciphers=[0x00A8], vers_min=0x0303, vers_max=0x0303)
spec.psk_identity = "client-id"
spec.psk = "0102030405060708090a0b0c0d0e0f10"   # hex
```

Pure PSK / DHE-PSK / ECDHE-PSK / RSA-PSK suites are supported. The TLS 1.2 SRP
family (RFC 5054) uses ``spec.srp_username`` and ``spec.srp_password`` (the
ClientHello carries the ``srp`` username extension). Anonymous (ADH) suites
provide no server authentication and are off by default; opt in with
``spec.anonymous = True``.

---

## Timeouts

Timeouts bound the TLS engine's I/O (not just the TCP socket):

```python
with freetls.TLSSession(modes.baseline_spec(server_name="example.com")) as s:
    s.connect("example.com", 443, timeout=5)   # TCP + handshake
    s.settimeout(2.0)                           # subsequent reads/writes
    s.recv(4096)                                # raises FreeTLSError on timeout
```

- `connect(timeout=...)` covers TCP connect **and** the TLS handshake.
- `settimeout(seconds)` (None = block forever) applies to subsequent reads and
  writes; `gettimeout()` returns the current value.
- A read/write that exceeds the timeout raises `FreeTLSError` (not a silent
  `b""`).
- Sessions are **blocking-only**: `setblocking(False)` raises
  `NotImplementedError`; `pending()` always returns `0` (uTLS does not expose
  buffered counts).

## Self-verification

```python
from freetls import verify

verify.fingerprints(session)         # recompute JA4/JA3/JA4S from emitted bytes
verify.assert_consistent(session)    # raises FingerprintError on any mismatch
fp = verify.probe(spec, "127.0.0.1", port, server_hostname="h")  # connect + return fp
verify.verify_peer_with_python(session, ca_pem, "example.com")   # cryptography parity
```

`session.fingerprints` (and `session.ja4` / `.ja3` / `.ja3n` / `.ja4s`) are always
computed from the bytes the engine emitted (`client_hello`) and received
(`server_hello`), never from the spec. You can inspect those raw handshake bytes
yourself:

```python
session.client_hello    # bytes: the exact ClientHello handshake message sent
session.server_hello    # bytes: the ServerHello received (for JA4S)
```

HTTP/2 adds `resp["akamai_h2"]` (the `1:65536;2:0;…|…|…|m,a,s,p` fingerprint) and
`resp["ja4h"]`; the transports expose `last_ja4h`. To decrypt a session in
Wireshark, set `FingerprintSpec.keylog = "/path/keys.log"` (NSS `SSLKEYLOGFILE`
format; security-sensitive, off by default).

---

## API reference

### Top level — `import freetls`

| Name | Description |
|------|-------------|
| `freetls.JA4Adapter` | requests transport adapter (lazy; needs `requests`) |
| `freetls.transport` | transport package (requests/httpx/aiohttp) |
| `freetls.TLSSession` | socket-like TLS session |
| `freetls.QUICSession` | socket-like QUIC/HTTP-3 session (concurrent; `ja4q`/`ja4sq`) |
| `freetls.TLSContext` | `ssl`-style context with `wrap_socket` |
| `freetls.FingerprintSpec`, `freetls.Extension` | the spec model |
| `freetls.Cipher`, `freetls.ExtensionType`, `freetls.SignatureScheme`, `freetls.NamedGroup` | IANA `IntEnum` constants (int-compatible; names/ints interchangeable) |
| `freetls.modes` | `baseline_spec`, `specific`, `partial_random`, `true_random` |
| `freetls.verify` | self-verification helpers |
| `freetls.engine_version()` | engine version string |
| `freetls.ja4_from_bytes`, `ja3_from_bytes`, `ja4s_from_bytes` | compute from raw handshake bytes |
| `freetls.parse_client_hello`, `parse_server_hello` | parse handshake bytes |
| `freetls.TLS10/11/12/13` | version constants |
| `FreeTLSError`, `EngineError`, `SpecError`, `HandshakeError`, `FingerprintError` | exceptions |

### `TLSSession`

`TLSSession(spec)`; connect with `connect(host, port=443, timeout=None, server_hostname=None)`
or `wrap_socket(sock, server_hostname)`.

- I/O: `sendall`, `send`, `recv`, `recv_into`, `makefile("rb")`, `settimeout`,
  `gettimeout`, `setblocking` (blocking-only), `fileno`, `getpeername`,
  `getsockname`, `pending`, `sendfile`, `shutdown`, `close`, context manager,
  `closed`. `recv`/`send` propagate errors (an engine failure raises
  `FreeTLSError`; only a clean EOF returns `b""`).
- Handshake: `connect(...)` / `wrap_socket(...)` / `do_handshake()` (deferred
  handshakes via `wrap_socket(..., do_handshake_on_connect=False)`).
- Fingerprints: `ja4`, `ja4_r`, `ja3`, `ja4s`, `fingerprints`, `client_hello`,
  `server_hello`.
- TLS info: `version()`, `cipher()` (an `ssl`-shaped `(name, protocol, bits)`
  tuple), `selected_alpn_protocol()`, `server_hostname()`,
  `getpeercert(binary_form=True)` (DER bytes), `state`.
- Response extras: `did_resume`, `ocsp_response`, `signed_certificate_timestamps`,
  `peer_application_settings`.
- HTTP/2: `h2_request(...)`.
- HTTP/3 (`QUICSession`): `request(...)`, `open_datagram_flow(...)`,
  `send_datagram(...)`, `recv_datagram(...)`, `close_datagram_flow(...)`,
  `ja4q`, `ja4q_r`, `ja4sq`.

### `TLSContext`

`TLSContext(spec=None)` or classmethods `baseline/specific/partial_random/true_random(**kwargs)`.
Config: `set_ciphers`, `set_alpn_protocols` / `set_alpn`, `set_versions(min, max)`,
`set_server_name`, `set_verify(verify, root_ca=None)`, `set_check_hostname`,
`set_system_roots`, `load_verify_locations(cafile=None, capath=None, cadata=None)`,
`set_client_cert(cert=None, key=None, *, cert_pem=None, key_pem=None)`,
`set_pinned_sha256(pins)`.
`wrap_socket(sock, server_hostname=None, do_handshake_on_connect=True)` returns a
`TLSSession`.

### `modes`

```python
baseline_spec(server_name=None, ciphers=None, alpn=DEFAULT_ALPN,
              sigalgs=DEFAULT_SIGALGS, groups=DEFAULT_GROUPS,
              vers_min=TLS12, vers_max=TLS13, verify=None,
              grease=False, grease_strategy="random", seed=None)
specific(ciphers=None, extensions=None, server_name=None, ...)
partial_random(server_name=None, ciphers=None, alpn=..., vers_min=..., vers_max=...,
               n_random_ciphers=None, n_random_extensions=None, seed=None, verify=None)
true_random(server_name=None, alpn=..., vers_min=..., vers_max=...,
            n_ciphers=None, n_extensions=None, seed=None, verify=None)
add_grease(spec, ciphers=True, groups=True, versions=True, extensions=True,
           strategy="random", seed=None)   # GREASE_VALUES: the 16 reserved codes

# HTTP/3 (TLS 1.3 only, h3 ALPN, TLS 1.3 cipher pool):
quic_baseline_spec(server_name=None, ciphers=None, alpn=DEFAULT_QUIC_ALPN,
                   ..., transport_parameters=None, quic=None,
                   datagrams=False, verify=None)
quic_specific(...)
quic_partial_random(...)
quic_true_random(...)
default_quic_transport_parameters() -> list[TransportParameter]
```

Leaving `n_random_ciphers`/`n_random_extensions` (and `n_ciphers`/`n_extensions`)
unset draws each count uniformly over the whole feasible range (clamped so the
two-digit `JA4_a` count field never saturates), which maximises the number of
distinct JA4 values: the counts vary per call and the sets are drawn uniformly.

### `profiles`

```python
profiles.names() -> list[str]
profiles.list_profiles() -> list[Profile]      # built-in + registered
profiles.get(name_or_alias) -> Profile | None
profiles.spec(name_or_alias, server_name=None, verify=None) -> FingerprintSpec
profiles.catalog_info() -> {"count", "tcp_count", "quic_count", "distinct_ja4",
                            "distinct_ja4q", "registered", "total", ...}
profiles.add_profile(name, *, alias=None, preset=None, quic_id=None, chlo_json=None,
                     no_sni=False, alpn=None, ja4=None, ja4q=None, ja3=None) -> Profile
profiles.load_file(path) -> int                # register a JSON list of profiles
profiles.find_ja4(query, *, limit=25) -> list[Profile]   # spans JA4 and JA4q
profiles.search(query, *, limit=25) -> list[Profile]
profiles.export(profiles=None) -> list[dict]
profiles.save_file(path, profiles=None) -> int
profiles.h2_bundle(name, *, settings=None, window_update=None,
                   pseudo_header_order=None, ...) -> FingerprintSpec
profiles.h3_bundle(name, *, quic=None, datagrams=False, ...) -> FingerprintSpec
```

### Engine helpers — `freetls.engine`

```python
engine.version() -> str
engine.abi_version() -> int                    # C ABI version (3)
engine.active_sessions() -> int                # live native sessions (leak checks)
engine.preset_list() -> list[str]              # uTLS preset names (generated)
engine.preset_raw(name) -> bytes               # offline ClientHello for a preset
engine.preset_raw_opts(name, no_sni=False, alpn=None) -> bytes
engine.chlo_raw(chlo_json) -> bytes            # offline ClientHello for a JSON spec
engine.spec_raw(spec_json) -> bytes            # offline ClientHello for any spec
engine.supported_ciphers() -> list[int]        # ciphers the engine can complete
engine.supported_extensions() -> list[int]     # extensions safe-mode allows
engine.quic_id_list() -> list[str]             # uQUIC QUIC preset names
engine.quic_id_raw(name, no_sni=False, alpn=None) -> bytes   # offline QUIC ClientHello
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

`ja4_from_bytes(raw)`, `ja3_from_bytes(raw)`, `ja3n_from_bytes(raw)`,
`ja4s_from_bytes(raw)`, `akamai_h2_fingerprint(settings, window_update, order)`,
`ja4_from_spec(spec)` (offline), `first_last_alpn(value)`, plus the raw parser.
The JA4+ report-only calculators are exported both here and at the top level:
`ja4x` / `ja4x_from_cert`, `ja4t` / `ja4ts`, `ja4l`, `ja4h` / `ja4h_from_request`.

## JA4+ report-only calculators

These recompute the corresponding FoxIO JA4+ layer from data you already have;
freetls never spoofs them.

```python
import freetls

# JA4X — X.509 structure, straight from the peer's leaf certificate.
session.ja4x                                   # e.g. "1a2b3c4d5e6f_..._..."
freetls.ja4x_from_cert(der_or_pem)             # offline
freetls.ja4x(["2.5.4.3"], ["2.5.4.3"], ["2.5.29.17"])

# JA4T / JA4TS — TCP SYN / SYN-ACK (window size, option kinds, MSS, window scale).
freetls.ja4t(64240, [2, 4, 8, 1, 1, 4], 1460, 8)     # "64240_2-4-8-1-1-4_1460_8"
freetls.ja4ts(65535, [2, 4, 8, 1, 3], 1460, 8)

# JA4L / JA4LS — handshake latency + TTL.
freetls.ja4l(t_a, t_b, t_c, client_ttl=64, server_ttl=64)   # {"ja4l_c":..., "ja4l_s":...}

# JA4H — the HTTP request actually sent (reported on h2_request responses and on
# the httpx transports as `last_ja4h`).
freetls.ja4h("GET", [("Host", "x"), ("Accept", "*/*")], version="HTTP/1.1")
resp = session.h2_request("/", headers=[["user-agent", "freetls"]])
resp["ja4h"], resp["ja4h_r"], resp["ja4h_ro"]
```

### Transports

- `freetls.JA4Adapter(spec=..., spec_factory=...)` (requests).
- `freetls.transport.httpx_transport.FreeTLSTransport` / `AsyncFreeTLSTransport`.
- `freetls.transport.aiohttp_connector.FreeTLSConnector`.
- `freetls.transport.urllib3_conn.Ja4HTTPSConnection` (the underlying urllib3
  connection class).

Bodies are streamed; `freetls.sse.iter_sse(byte_iterable)` yields `SSEEvent`
objects from a `text/event-stream` response.

Pass a fixed `spec=` for a stable fingerprint, or `spec_factory=` (a callable
returning a fresh spec per connection) for per-connection randomization:

```python
adapter = freetls.JA4Adapter(
    spec_factory=lambda: modes.true_random(server_name="example.com")
)
```

### Proxies, retries and WebSocket

Proxies (HTTP CONNECT, SOCKS5, SOCKS4/4a) tunnel the socket before the TLS
handshake; pass `proxy=` to the httpx transports or use the session helper:

```python
spec = modes.baseline_spec(server_name="example.com")
session = freetls.TLSSession(spec)
session.connect_via_proxy("socks5://user:pass@127.0.0.1:1080", "example.com", 443)

# httpx: FreeTLSTransport(spec=spec, proxy="http://127.0.0.1:8080")
```

`freetls.transport.retry.Retry` provides bounded exponential backoff with a
retryable-status list, usable with any of the transports
(`Retry(total=3).run(lambda: client.get(url), on_status=True)`).

A minimal RFC 6455 client is available for WebSocket endpoints:

```python
from freetls.transport import websocket

ws = websocket.connect(session, "example.com", "/socket")
ws.send("hello")
print(ws.recv())
ws.close()
```

`_http2` is the shared HTTP/2 path and `_http3` the shared HTTP/3 path; the
transports dispatch on the ALPN the handshake negotiated (`_http2.negotiated_protocol`).

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
         freetls.session.TLSSession      freetls.quic.QUICSession
               │  cffi  (freetls.engine._cffi)
Go:      native/engine.go + native/httpx_h2.go + native/quic.go + native/httpx_h3.go
               │  uTLS ClientHello override
               ▼
         crypto/tls (TLS 1.0–1.3) + x/net/http2 + uQUIC (QUIC/HTTP-3)
```

- Python owns the TCP connect and hands a **dup'd fd** to Go; the Go engine
  performs the TLS handshake and owns the encrypted channel. Reads/writes cross
  the cffi boundary.
- The engine takes a JSON spec (mirroring `FingerprintSpec`) and captures the
  emitted ClientHello and received ServerHello for fingerprinting.
- `native/httpx_h2.go` implements HTTP/2 over the same connection using
  `x/net/http2`'s Framer + HPACK, so the H2 fingerprint fields are explicit.
- For QUIC, Python owns the **UDP** socket (passed as a dup'd fd →
  `net.FilePacketConn`); `native/quic.go` drives the handshake through the
  vendored **uQUIC** fork and `native/httpx_h3.go` runs HTTP/3 (requests and RFC
  9297 datagrams) over that one connection via a single `http3.ClientConn`.

### Thread safety and the engine ABI

The native engine keeps a mutex-guarded session registry: all C entrypoints are
safe to call from multiple threads, sessions are independent, and every
entrypoint wraps its body in `recover()` so a Go panic becomes a Python error
instead of aborting the host process. The C surface carries an ABI version
(`engine.abi_version()`, currently `3`); the binding refuses to load an engine
whose ABI version does not match exactly, so a stale `libfreetls.so` fails loudly.

A single `TLSSession` is **not** internally synchronised — use one session per
thread (or the transports, which open a connection per request). `QUICSession`
is safe for concurrent `request()` calls (the Go http3 client multiplexes). Go
fuzz and benchmark targets cover the spec JSON parser:

```bash
cd native && go test ./...                 # includes fuzz seeds + benchmarks
cd native && go test -run '^$' -bench . ./...
cd native && go test -run '^$' -fuzz FuzzParseSpec -fuzztime 30s
```

---

## Development

```bash
make help        # list targets
make venv        # create .venv + install freetls[test] + build the engine
make native      # build native/libfreetls.so (the c-shared engine)
make test        # full suite (unit + conformance + e2e + pcap)
make test-fast   # skip privileged pcap capture
make coverage    # enforce the 85% coverage gate
make gen         # regenerate IANA tables + preset map + profile catalog
make setup-caps  # one-time: make a local tcpdump capable of loopback capture
make build       # build sdist + wheel into dist/
make fmt         # format with black + ruff --fix
make lint        # ruff check
make typecheck   # mypy (src/freetls)
cd native && go test ./...   # Go HTTP/2 wire test
```

The package ships `py.typed` and is checked with ruff, black, and mypy
(`pip install "freetls[dev]"`).

`PY` and `GO` are overridable and auto-detected, so this works on any machine:

```bash
make test PY=python3.12 GO=/usr/local/go/bin/go
```

Environment knobs (all optional):

| Variable | Effect |
|----------|--------|
| `FREETLS_GO` | Path to the Go binary for source builds/tests |
| `FREETLS_LIB` | Explicit path to `libfreetls.so` (skip discovery) |
| `FREETLS_NO_OPENSSL` | Build/install the Go-only engine (no perl/make/OpenSSL) |
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

**"Could not load the freetls engine."**
The engine is built at install time (there is **no** runtime auto-build). Run
`make native` (wide) or `make native-go` (Go-only), install the prebuilt wheel,
or set `FREETLS_LIB=/path/to/libfreetls.so`. Search order: `$FREETLS_LIB` →
`src/freetls/_lib` → `native/` → `build/`.

**Editing `native/*.go` has no effect.**
The `.so` is a build artifact; run `make native` (or `go build -buildmode=c-shared`)
and make sure no stale copy shadows it in `src/freetls/_lib/`.

**`pip install .` fails while building the engine.**
The default wide engine needs Go (1.27+), a C toolchain, `perl`, `make`, and
network the first time (to fetch the OpenSSL submodule). Install them, point at
Go with `FREETLS_GO=/path/to/go`, or build the Go-only engine with
`FREETLS_NO_OPENSSL=1 pip install .`.

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

- **JA4+ report-only variants** — JA4X, JA4T/JA4TS, JA4L/JA4LS and JA4H are
  provided as *calculators* (see below). They report/recompute the corresponding
  layer; freetls does not spoof or emit fake TCP/X.509/HTTP layers, and JA4SSH,
  JA4D/JA4D6 and JA4N are not implemented.
- **No SSLv3.** TLS 1.0/1.1 handshakes only complete against servers that still
  accept them; modern servers will refuse, as expected.
- **JA4 collisions are bounded by the 12-hex truncation**; random modes cannot
  produce more than ~2^48 distinct values per part.
- **Cipher completion is bounded by the backend.** The default (wide) engine
  completes 144 suites; the Go-only alternate completes 78. The wide engine adds
  ARIA-GCM, AES-CCM/CCM_8, Camellia-CBC and TLS 1.3 CCM. Finite-field DHE
  (DHE-RSA/DHE-DSS/ADH), the TLS 1.2 PSK family (PSK/ECDHE-PSK/DHE-PSK/RSA-PSK)
  and SRP (RFC 5054) are implemented in the forked uTLS engine. GOST and suites
  OpenSSL 3.5.5 does not implement are out of scope. TLS 1.3 CCM is implemented
  but no local OpenSSL/Go server negotiates it (covered at the AEAD level); SRP
  is verified at the key-agreement and offer level because OpenSSL 3.5.5's
  deprecated ``s_server -srpvfile`` path does not complete. Of the 144 wide
  suites, ``tests/e2e/test_all_suites.py`` negotiates **129** end-to-end (with an
  application-data round trip) and skips the other 15 with a concrete reason
  (RC4/3DES/TLS 1.3 CCM/legacy-ChaCha not in OpenSSL 3.5.5, plus SRP).
- **Cross-platform builds are not turnkey.** The OpenSSL `Configure` target is
  hardcoded to `linux-x86_64` in both `Makefile` (`OPENSSL_ARGS`) and `setup.py`,
  so building the **wide** engine on macOS/Windows/other architectures requires
  changing that target (the loader already looks for `libfreetls.dylib` /
  `freetls.dll`, but nothing produces them). The **Go-only** engine
  (`make native-go`, `FREETLS_NO_OPENSSL=1`) is portable. This checkout is
  exercised on Linux/CPython 3.14.

### Known gaps

These are deliberately unimplemented areas, documented so they can be planned
around rather than discovered in production.

- **HTTP/3 is supported but not discovered.** The QUIC transport, QUIC
  Initial-packet / transport-parameter control, the TLS-1.3-over-QUIC handshake,
  JA4q/JA4Sq, RFC 9297 datagrams and `h3` ALPN are implemented (see
  [HTTP/3](#http3)); there is no Alt-Svc / HTTPS-RR discovery, no
  CONNECT-UDP/MASQUE, aiohttp stays HTTP/1.1-only, and 0-RTT / ECH over QUIC are
  deferred (designed for). Session resumption works through the standard spec
  fields.
- **HTTP/2 coverage is fingerprint-shaped, not production-shaped.** See
  [HTTP/2 limitations](#http2-limitations) for the detail: single-frame
  HEADERS/DATA writes with no `MAX_FRAME_SIZE` splitting (a **known limitation**
  that breaks request bodies/header blocks over 16 KB), no HPACK encoding
  control, one stream per connection with no multiplexing, no priority or
  server-push handling, and no HTTP/2 at all from the aiohttp connector.
- **Request bodies are not streamed on the HTTP/2 path.** Response bodies stream
  incrementally everywhere, but the engine's `h2_request`/`write` take a complete
  buffer, so the H2 path buffers the whole body (and rejects generator bodies via
  `bytes(body)`); httpx materialises `content=<iterator>` on both H1 and H2. Only
  requests/urllib3 (H1) and aiohttp (H1) stream a request body. The H2 path is
  additionally bounded by the 16 KB single-frame limitation. See
  [Streaming & content decoding](#streaming--content-decoding).
- **`ssl`-API parity is partial.** `TLSContext`/`TLSSession` are `ssl`-*like*
  rather than `ssl`-*compatible*: blocking-only I/O, `pending()` always `0`, no
  memory BIO or `SSLObject`, no `SSLContext` callback surface
  (`set_servername_callback`/`set_ciphers`/`set_alpn_protocols`/…), and no
  non-blocking handshake. Existing `ssl`-based code needs its I/O loop adapted.
- **No certificate revocation checking.** `status_request` captures the peer's
  OCSP response (`state.ocsp_response_b64`) and SCTs, but freetls does not
  validate OCSP/CRL or perform stapling checks; verification is chain + hostname
  + optional pinning only.
- **Session state is process-local.** TLS 1.2/1.3 resumption goes through the
  engine's in-process shared cache; there is no import/export of session tickets
  or `SSL_SESSION` blobs, so resumption state cannot be persisted or replayed.
