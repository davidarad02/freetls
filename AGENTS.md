# AGENTS.md

Guidance for OpenCode/automation agents working in the `freetls` repo.

## What this is

`freetls` is a Python HTTPS/TLS client that controls the **JA4** TLS client
fingerprint (plus JA3 and JA4S). The TLS handshake is done by a Go + uTLS
engine compiled to a native shared library (`libfreetls.so`) and loaded from
Python via `cffi`. Only the ClientHello is overridden; all cryptography is Go
`crypto/tls`. There is no monorepo — one Python package (`src/freetls`) plus a
Go module (`native/`). It is a git repo (`origin` on GitHub), but there is **no
CI** — no `.github/` workflow or equivalent — so `make test` / `make coverage` /
`make lint` / `make typecheck` are run by hand. There is also no `LICENSE` or
`CHANGELOG` file.

## Route B — single engine with a libcrypto (OpenSSL EVP) backend

The approved plan lives in **`docs/route-b-plan.md`**; treat it as the source of
truth (locked decisions D1–D11, fork/registration mechanics, crypto-bridge
scope, safe-mode whitelist, risk table, and measured deviations).

Status: **complete.** The wide engine (**144** suites = 78 Go-only + 66
wide-only) is now the **default**; the Go-only engine is an alternate selected at
runtime via `freetls.use_engine(freetls.Engine.GO)`.

- The uTLS fork is vendored at `native/third_party/utls` (a nested module; the
  top-level `native/go.mod` has the `replace`). Keep fork changes in **new files
  + the documented `patches/` set** and re-run `tools/rebase_utls.sh` after
  bumping uTLS.
- All libcrypto code is behind the `freetls_libcrypto` build tag. `make native`
  builds the **wide** engine by default (statically linked from the
  `native/third_party/openssl` submodule, symbols hidden); `make native-go`
  builds the Go-only engine and `make native-dynamic` a dynamic-libcrypto dev
  build. There is **no runtime auto-build**. Switch engines at runtime with
  `freetls.use_engine(Engine.WIDE | Engine.GO)`, `use_engine_file(path)` or the
  `engine_context(...)` context manager; `current_engine()` returns an
  `EngineInfo(kind, path)`. Run the fork's EVP tests with `make test-libcrypto`.
- Route B e2e tests live in `tests/e2e/test_route_b_suites.py`; they build the
  wide engine and drive it via `tests/_route_b_client.py` in a subprocess (the
  cffi binding loads one engine per process). `tests/e2e/test_full_engine.py`
  covers the static link and interposition with Python `ssl`.
- OpenSSL updates: the submodule is shallow (`.gitmodules` `shallow = true`).
  Bump it with `make update-openssl TAG=openssl-x.y.z` (or
  `tools/update_openssl.sh <tag>`), which shallow-fetches the tag, refreshes the
  gitlink, and rebuilds. A stamp (`native/third_party/openssl/.freetls-built`,
  holding the submodule commit + Configure args) makes `make native`
  auto-rebuild when either changes.
- Safe mode: `freetls.set_safe_mode` / `FingerprintSpec.safe`, validated in
  `src/freetls/safety.py`; the extension whitelist and backed ciphers come from
  the engine (`freetls.engine.supported_ciphers/_extensions`). Default is
  **unsafe**.
- Deviations: Camellia-GCM and ARIA-CBC are absent from OpenSSL 3.5.5 (dropped);
  TLS 1.3 CCM is implemented but not negotiable against local OpenSSL/Go servers
  (AEAD-verified only). See `docs/route-b-plan.md` §0.

## Route C — HTTP/3 + QUIC

The approved plan lives in **`docs/route-c-plan.md`**; treat it as the source of
truth (locked decisions D1–D14, the uQUIC fork, EVP/CCM parity, the spec model +
ABI, ALPN/dispatch, catalog math, testing, out-of-scope and risks).

Status: **complete.** P1 (passive JA4q/JA4Sq calculators), P2 (a spoofed QUIC
Initial + ABI **3**), P3 (HTTP/3 requests + RFC 9297 datagrams + transports) and
P4/P5 (profiles/catalog/modes/docs + deferred hooks) are implemented.

- **uQUIC fork**: `native/third_party/uquic` (a hard fork of quic-go that swaps
  `crypto/tls` → uTLS), wired with
  `replace github.com/refraction-networking/uquic => ./third_party/uquic`.
  Rebase with `tools/rebase_uquic.sh`; documented in
  `native/third_party/uquic/FORK.md`. It builds on **our** uTLS fork, so every
  freetls fork change applies. `native/quic_link.go` blank-imports the stack so
  both engines compile and link it.
- **Engine**: `native/quic.go` (handshake, `net.FilePacketConn`, `dialQUIC`'s
  own deadline) and `native/httpx_h3.go` (`freetls_h3_request` +
  `freetls_h3_datagram_{open,send,recv,close}`). The handshake establishes one
  QUIC connection; HTTP/3 runs over it through **one `http3.ClientConn`** (a
  second would compete for unidirectional streams), so a session has one
  `quic.Transport`/`PacketConn`. `QuicInitialSpec.version` selects QUIC v1
  (default) or v2 (RFC 9369).
- **Python**: `src/freetls/quic.py` (`QUICSession`: `request`, datagram helpers,
  `ja4q`/`ja4q_r`/`ja4sq`); `src/freetls/fingerprint/quic.py` (Initial parsing /
  key schedule). `Extension.quic_transport_parameters` + `QuicInitialSpec` +
  `FingerprintSpec.quic`/`quic_id`/`quic_datagrams`/`quic_early_data`.
- **Transports**: `transport/_http3.py` mirrors `_http2.py`. HTTP/3 is **opt-in**
  (`FreeTLSTransport(..., http3=True)`, `JA4Adapter(..., http3=True)`) because
  Alt-Svc/HTTPS-RR discovery is out of scope; `_http2.negotiated_protocol` drives
  the H2-vs-H1 choice. aiohttp stays HTTP/1.1-only.
- **EVP/CCM parity**: two build-tag-gated hunks in uQUIC
  (`internal/handshake/cipher_suite.go`, `header_protector.go`, in
  `native/third_party/uquic/patches/freetls.patch`) plus a tag-gated AEAD in each
  fork. `make test-uquic` runs both builds. CCM is **not negotiable end-to-end**
  against Go/OpenSSL servers; the QUIC suite matrix skips those rows.
- **Deferred but designed for (D13)**: 0-RTT (`UTransport.DialEarly`) and ECH over
  QUIC. `FingerprintSpec.quic_early_data` is serialised and **ignored** by the
  engine (the handshake always uses `Dial`, not `DialEarly`). Both are additive
  fields/exports → **no ABI bump**. Session resumption is **not** deferred: it
  works through the standard `session_cache` + `pre_shared_key` spec fields.
  WebTransport is out of scope.

### QUIC findings worth carrying forward

1. **`initial_source_connection_id` is mandatory.** Without it a conformant
   server silently drops the Initial (no error). `ensureInitialSourceCID` injects
   it unless explicitly suppressed; it does not change JA4q.
2. **uQUIC's `Dial` can hang forever** with a custom `ClientHelloSpec` (its
   handshake-idle-timeout path never fires). `dialQUIC` enforces the engine's own
   deadline and closes the PacketConn to release the dial.
3. **RFC 9001 §5.2 keys the whole client flight from the *first* Initial's
   DCID.** Later client Initials carry a different DCID but the same keys;
   deriving per packet is wrong (fixed in both `fingerprint/quic.py` and
   `tests/pcap/_quic.py`).
4. **Datagrams need the wire parameter, not just the config.** `quic.Config`
   `EnableDatagrams` alone is not enough: uQUIC takes the transport parameters
   from the `ClientHelloSpec`, so `ensureMaxDatagramFrameSize` injects
   `max_datagram_frame_size` (0x20) when `quic_datagrams` is set, or the peer
   closes with "missing QUIC Datagram support".

## Commands (use these; don't guess)

All Python commands use the project venv (`.venv/`), not the system Python.

- One-command setup: `make venv` (creates `.venv`, installs `.[test]`, builds engine)
- Full suite (unit + conformance + e2e + pcap): `make test`
- Fast suite (skips privileged pcap capture): `make test-fast`
- Coverage gate (enforced at 85%): `make coverage`
- Build the native engine: `make native` (runs `go build -buildmode=c-shared`)
- Go unit tests (HTTP/2 wire fingerprint): `cd native && go test ./...`
- Regenerate IANA tables + profile catalog: `make gen`
- One-time pcap privilege setup: `make setup-caps` (or `sh scripts/setup_capabilities.sh`)
- List targets: `make help`

`Makefile` is the source of truth; `PY`/`GO` are overridable (`make test PY=...
GO=...`) and **auto-detected** (Python: `.venv` else `python3`; Go: `PATH` else
`~/.local/go` and common dirs). The engine is built **only at install**
(`make native` = wide default, `make native-go` = Go-only); the runtime loader
never compiles anything.

Relevant env vars: `FREETLS_LIB` (explicit `.so`), `FREETLS_GO` (Go binary),
`FREETLS_NO_OPENSSL` (build/install the Go-only engine), and `FREETLS_TCPDUMP`
(pcap tests).

Run a single test / file:

```bash
.venv/bin/python -m pytest tests/e2e/test_handshake.py -q
.venv/bin/python -m pytest "tests/unit/test_fingerprint.py::test_ja4_spec_worked_example" -q
```

Note: coverage flags are intentionally **not** in `pyproject.toml` `addopts`
(so single-file runs don't fail the 85% gate). Use `make coverage` for the gate.

## GOTCHAS (an agent will get these wrong)

1. **Dev `.so` shadowing.** Building a wheel copies the engine into
   `src/freetls/_lib/libfreetls.so`, which silently **shadows**
   `native/libfreetls.so` (the loader checks `_lib` first). After any wheel
   build, delete it (`make clean` removes it) or point the loader at the fresh
   build with `FREETLS_LIB=$PWD/native/libfreetls.so`. Symptom: code changes /
   new engine symbols appear missing.
2. **Engine edits need a rebuild.** Editing `native/*.go` does nothing until
   `make native` (wide) or `make native-go` (Go-only). The committed/packaged
   `libfreetls.so` is a build artifact. The pytest `engine_lib` fixture builds
   the wide engine via `make native` if it is missing; there is **no runtime
   auto-build**.
3. **pcap tests need privileges.** Capturing loopback requires a tcpdump with
   `cap_net_raw`. `/tmp` is `nosuid`, so capabilities only work on a copy under
   `$HOME` — `make setup-caps` installs `~/.local/freetls-deps/bin/tcpdump`.
   Without it, `-m pcap` tests **skip** (not fail); they run by default.
4. **Regeneration.** IANA tables (`src/freetls/fingerprint/tables/*.json`) come
   from `tools/gen_tables.py`; the Go preset map
   (`native/preset_map_gen.go`, **generated — do not edit by hand**) from
   `tools/gen_presets.py`, which parses the uTLS version pinned in
   `native/go.mod` and drops presets uTLS cannot build; the profile catalog
   (`src/freetls/profiles/catalog.json`) from `tools/gen_catalog.py`. Run
   `make gen` after touching the universe, presets, or parser/engine output;
   `tool/gen_catalog.py` deliberately **excludes nondeterministic presets**
   (Chrome shufflers whose GREASE-dependent padding changes the JA4), so a
   profile missing from the catalog is expected, not a bug.

## HARD CONSTRAINTS

- **Local-only network.** The `freetls` library runtime and all tests must
  never contact external services or third-party fingerprint APIs. Tests start
  their own TLS servers (OpenSSL, in-process Python `ssl`, Go `net/http`) and
  verify against loopback pcap. `tools/gen_tables.py` may fetch IANA CSVs at
  generation time only.
- **No SSLv3.** Supported offers are TLS 1.0–1.3.
- **JA4+ is report-only.** JA4X, JA4T/JA4TS, JA4L/JA4LS and JA4H are provided as
  *calculators* only (`fingerprint/ja4x.py`, `ja4t.py`, `ja4l.py`, `ja4h.py`);
  freetls never spoofs those layers. JA4SSH, JA4D/JA4D6 and JA4N are out of scope.

## Architecture / where things live

- `native/engine.go` — TLS engine: JSON spec → uTLS `ClientHelloSpec`,
  `GenericExtension` padding, baseline injection, tee'd ClientHello/ServerHello,
  peer cert, read deadlines. C ABI consumed by cffi.
- `native/third_party/utls/ffdhe_*.go` / `psk_*.go` / `srp*.go` — the forked
  uTLS engine's finite-field DHE (DHE-RSA/DHE-DSS/ADH), TLS 1.2 PSK
  (PSK/ECDHE-PSK/DHE-PSK/RSA-PSK) and SRP-6a (RFC 5054) key agreements + suite
  registration; `patches/freetls.patch` carries the upstream
  `common.go`/`handshake_client.go` hunks.
- `native/preset_map_gen.go` — **generated** name→`ClientHelloID` map for the
  pinned uTLS (see `tools/gen_presets.py`). The engine also accepts a full uTLS
  `ClientHelloSpec` JSON via the spec's `chlo_json` field (or `profiles.add_profile`),
  so arbitrary/newer fingerprints need no Go change.
- `native/httpx_h2.go` — Go-side HTTP/2 client (`x/net/http2` Framer + hpack)
  exposing configurable SETTINGS/WINDOW_UPDATE/pseudo-header order.
- `native/quic.go` + `native/httpx_h3.go` — QUIC handshake (uQUIC `UTransport`
  over a `net.FilePacketConn`) and the HTTP/3 client (`http3.ClientConn`; requests
  and RFC 9297 datagrams). `native/quic_id_map.go` maps the uQUIC preset names
  (hand-maintained — uQUIC ships no registry).
- `native/third_party/uquic` — the vendored uQUIC fork (quic-go with uTLS);
  `native/quic_link.go` blank-imports it so both engines link the QUIC stack.
- `native/h2_test.go` / `native/presets_test.go` — assert the exact H2 frames on
  the wire and that every generated preset is buildable.
- `src/freetls/engine/_cffi.py` — cffi binding + `.so` discovery (`FREETLS_LIB`,
  then `src/freetls/_lib`, then `native/`, then `build/`).
- `src/freetls/model.py` — `FingerprintSpec` / `Extension` (the spec model).
- `src/freetls/modes.py` — `baseline_spec` / `specific` / `partial_random` /
  `true_random` (and `quic_baseline_spec` / `quic_specific` /
  `quic_partial_random` / `quic_true_random` for HTTP/3);
  `SAFE_PADDING_EXT_IDS` keeps padding to assigned ext IDs a server ignores.
- `src/freetls/session.py` — `TLSSession` (socket-like; `ja4`/`ja3`/`ja4s`,
  `h2_request`). `src/freetls/quic.py` — `QUICSession` (UDP; `ja4q`/`ja4q_r`/
  `ja4sq`, `request`, datagram helpers). `src/freetls/context.py` — `TLSContext`
  (`ssl`-style `wrap_socket`).
- `src/freetls/fingerprint/` — `ja4.py` (also `ja4_from_spec`), `ja3.py`,
  `ja4s.py`, `quic.py` (QUIC Initial parsing + RFC 9001 key schedule),
  `parse.py` (raw hello parser), `tables/`, and the report-only calculators
  `ja4x.py`, `ja4t.py`, `ja4l.py`, `ja4h.py`.
- `src/freetls/profiles/` — catalog loader + **runtime registration**
  (`get`/`list_profiles`/`spec`/`add_profile`/`load_file`); `catalog.json` merges
  TCP and QUIC profiles (generated by `tools/gen_catalog.py`).
- `src/freetls/transport/` — `requests_adapter.py` (+ `urllib3_conn.py`),
  `httpx_transport.py`, `aiohttp_connector.py`. Bodies are **streamed** (httpx
  chunk-by-chunk over HTTP/1.1; aiohttp feeds the loop as data arrives);
  `transport/_content.py` decodes gzip/deflate/brotli/zstd (optional
  `freetls[content]`); `transport/proxy.py` (HTTP CONNECT + SOCKS4/5),
  `transport/retry.py` (`Retry` backoff) and `transport/websocket.py` (RFC 6455
  client) round out the transport layer. HTTP/3 is opt-in via
  `transport/_http3.py` (see Route C).
- `src/freetls/sse.py` — `iter_sse` / `SSEEvent` (WHATWG event-stream parser).
- `src/freetls/fingerprint/chlo.py` — `chlo_json_from_raw` (captured
  ClientHello -> uTLS ClientHelloSpec JSON, the inverse of the engine's
  `chlo_json` input).
- `src/freetls/verify.py` — self-verification + optional `cryptography` cert
  parity hook.
- `tests/` — `unit/`, `conformance/` (FoxIO vectors), `e2e/`, `pcap/`;
  `tests/_build.py` (raw-hello builders + `CHLO_JSON`), `tests/servers.py`
  (in-process HTTPS app server), `tests/servers/go_https/` (Go h2 test server),
  `tests/servers/go_http3/` (Go HTTP/3 test server, built on **upstream**
  quic-go so the client is validated against an independent stack),
  `tests/pcap/_quic.py` (independent UDP pcap extractor).

## Wiring facts that span files

- **Spec JSON schema is duplicated in three places.** Adding/changing a spec
  field means editing: `model.py::FingerprintSpec.to_engine`,
  `native/engine.go::specJSON`, and the `buildExtension` switch (or `doH2` for
  H2 fields). Keep them in sync. New in P5: `compression`, `session_cache`
  (engine sets `config.ClientSessionCache`, `PreferSkipResumptionOnNilExtension`,
  `OmitEmptyPsk`), `padding_len` (fixed-length padding), and the
  `record_size_limit` / `pre_shared_key` extension kinds. Session resumption
  requires the `session_ticket` (TLS 1.2) or `pre_shared_key` (TLS 1.3, placed
  last) extension in the spec; `stateJSON` now carries `did_resume`,
  `ocsp_response_b64`, `sct_b64`, `peer_alps_b64`. QUIC fields (`transport`,
  `quic`, `quic_id`, `quic_datagrams`, `quic_early_data`) are mirrored in
  `native/quic.go::quicSpecFor` / `httpx_h3.go`; the
  `quic_transport_parameters` extension kind lives in `buildExtension`.
- uTLS's JSON parser can **panic** on a malformed `ClientHelloSpec` document;
  the engine wraps parsing/`ApplyPreset` in `recover()` (see `safeParseChloJSON`)
  so a bad `chlo_json` returns an error instead of crashing the host process.
- Precedence in the engine handshake: `chlo_json` > `preset` > explicit
  `ciphers`/`extensions`.
- **C-string ownership.** Every engine export that returns `char*` allocates
  with `C.CString`; the Python binding reads + frees via `_cffi._cstr()`. When
  you add a new `char*`-returning export, read it with `_cstr` (not
  `ffi.string`) or it leaks.
- **Session lifecycle.** `EngineSession.close()` and `.free()` are distinct;
  `TLSSession.close()` frees the native session, and a **failed handshake frees
  it too** (no registry leak). `engine.active_sessions()` reports the live count
  (used by leak tests).
- **Secure-by-default verification.** `model.DEFAULT_VERIFY` is `True`;
  `FingerprintSpec.verify=None` means "use the default". `freetls.set_default_verify(False)`
  opts out; the test suite does this in `tests/conftest.py` (self-signed servers).
- **Panic safety.** All C entrypoints (`session_new`, `handshake`,
  `quic_handshake`, `read`, `write`, `chlo_raw`, `h2_request`, `h3_request`,
  `h3_datagram_*`, `preset_*`) wrap their bodies in `recover()` so a Go panic
  returns an error instead of aborting the host.
- **C-ABI version.** `freetls_abi_version()` (currently `3`) is checked by
  `_cffi._check_abi()` when an engine is loaded (`_resolve`/`_load_file`); bump
  it on an incompatible export change and update `_EXPECTED_ABI`. Additive
  exports/fields do **not** need a bump.
  `native/fuzz_test.go` (`FuzzParseSpec`, `FuzzChloJSON`) and
  `native/bench_test.go` cover the JSON/spec parsers. The session registry is
  mutex-guarded (thread-safe across sessions); a single `TLSSession` is not, but
  `QUICSession.request` is safe to call concurrently (the Go http3 client
  multiplexes).
- **Timeouts are engine-side.** `freetls_set_timeout` (ms) drives the Go read
  deadline; `TLSSession.settimeout` updates both the Python socket and the
  engine. Sessions are blocking-only (`setblocking(False)` raises).
- **HTTP/2 in the transports is ALPN-driven; HTTP/3 is opt-in.**
  `transport/urllib3_conn.py` (requests) and `transport/httpx_transport.py` call
  the Go H2 client when `selected_alpn_protocol() == "h2"` (via
  `transport/_http2.py`), else HTTP/1.1. HTTP/3 is **opt-in** (`http3=True`): the
  httpx `_open` branches to a `QUICSession` before the TCP connect and
  `urllib3_conn` opens a UDP session, then `transport/_http3.py` runs the request.
  `_http2.negotiated_protocol` centralises the H2-vs-H1 ALPN choice. aiohttp
  cannot speak HTTP/2 (or HTTP/3), so `transport/aiohttp_connector.py` strips `h2`
  from the offered ALPN. Hop-by-hop headers are filtered for H2/H3.
- **Certificate suite.** Trust/verify/pinning/mTLS spec fields
  (`verify`, `check_hostname`, `system_roots`, `root_ca`, `ca_dir`, `cadata`,
  `client_cert[_pem]`, `client_key[_pem]`, `pinned_sha256`) live in
  `model.FingerprintSpec` and `native/engine.go::specJSON`; the engine builds the
  Go `x509` pool, hostname policy, pin callback, and client cert. The full peer
  chain is exposed via `state.peer_certs_der` / `session.peer_chain()`.
- **Key-exchange credentials.** `anonymous` (ADH), `psk_identity`/`psk` (hex)
  and `srp_username`/`srp_password` live in `model.FingerprintSpec` and
  `native/engine.go::specJSON`; the engine sets `Config.Anonymous` /
  `Config.PskIdentity` / `Config.Psk` / `Config.SrpUsername` /
  `Config.SrpPassword` (and injects the RFC 5054 `srp` ClientHello extension
  from `srp_username`). PSK and SRP suites require both credential fields.
  These are additive fields (no ABI bump).
- Fingerprints are always computed **from the bytes the engine emitted/received**
  (`session.fingerprints` / `verify.fingerprints`), never from the spec, except
  `ja4_from_spec` (offline, for range tests) which must agree with the engine
  (covered by `tests/e2e/test_spec_consistency.py`).
- Python owns the TCP connect and passes a **dup'd** fd; Go `net.FileConn`s it
  and closes the dup. Don't reuse the passed fd.
- JA4 value universe is **assigned IANA values only** (currently 356 ciphers /
  64 extensions / 49 signature schemes / 59 named groups; all in `tables/`).
  Note: 49 is the correct signature-scheme count and 59 is the supported-groups
  count — they are different registries; don't conflate them.
- `src/freetls/constants.py` builds the `Cipher`/`ExtensionType`/
  `SignatureScheme`/`NamedGroup` `IntEnum`s from `fingerprint/tables/` at import
  time, so they stay in sync automatically. Value-accepting APIs (modes,
  `Extension.*`) coerce ints, enum members, or case-insensitive name strings via
  `tables.as_cipher`/`as_group`/`as_sigalg`/`as_extension`.

## Testing notes

- Markers: `pcap` (privileged capture). Default run includes it; it skips if no
  capable tcpdump.
- TLS version tests (`tests/e2e/test_versions.py`) cover 1.0–1.3 with
  `SECLEVEL=0` OpenSSL servers; they pass locally. They `skip` only if the local
  OpenSSL refuses a legacy version.
- Tests are local: self-hosted OpenSSL/Python/Go servers + `tests/pcap/_pcap.py`
  (an independent parser). Nothing hits the network.
- The forked key exchanges are covered by `tests/e2e/test_ffdhe_suites.py`
  (39 DHE/ADH suites, `tests/_dhe_client.py`) and `tests/e2e/test_psk_suites.py`
  (48 PSK suites, `tests/_psk_client.py`), each against `openssl s_server`
  (`@SECLEVEL=0` for the 64-bit-tag CCM8 suites). SRP is covered at the
  key-agreement level (`tests/e2e/test_srp_suites.py` + the fork's Go round-trip
  test) because OpenSSL 3.5.5's deprecated `s_server -srpvfile` path does not
  complete. Go unit tests live in the fork (`ffdhe_freetls_test.go`,
  `psk_freetls_test.go`, `srp_freetls_test.go`).
- `tests/e2e/test_all_suites.py` is the coverage matrix: it negotiates every
  registered suite end-to-end (handshake **plus** an HTTP application-data round
  trip) against a per-suite `openssl s_server` built from `openssl ciphers -V`.
  Of the 144 wide suites, **129 negotiate** and **15 are `skip`ped with a
  concrete reason** (9 not in the OpenSSL 3.5.5 default provider — RC4, 3DES,
  TLS 1.3 CCM, the old ChaCha drafts — and 6 SRP). Adding a suite means it must
  either negotiate here or be added to the documented skip set.
- QUIC/HTTP-3 is covered by `tests/unit/test_quic.py` (parser + RFC 9001 A.1
  vectors), `tests/conformance/test_ja4q_vectors.py` (JA4q/JA4Sq vectors),
  `tests/e2e/test_quic_handshake.py`, `tests/e2e/test_http3.py` (app-data,
  concurrency, datagrams, httpx + requests) and `tests/e2e/test_quic_suites.py`
  (the TLS 1.3 suite matrix; the CCM rows skip). The server is
  `tests/servers/go_http3/` (upstream quic-go); `tests/pcap/test_quic_initial.py`
  decrypts the Initial and recomputes JA4q independently. `make test-uquic`
  covers the EVP/CCM patch in both builds.
- Keep the 85% coverage gate green (`make coverage`); if you add code, add tests.

## Conventions

- No comments in code unless they clarify a non-obvious constraint.
- Python: `from __future__ import annotations`; type hints; dataclasses for
  models. `requires-python >= 3.9` (dev venv is 3.14).
- Do not add third-party runtime deps to core `freetls`; HTTP libs are optional
  extras (`requests`/`httpx`/`aiohttp`/`cryptography`) and access via
  `freetls.JA4Adapter` is lazy.
- **Lint/format/types are enforced** (config in `pyproject.toml`): `make lint`
  (ruff), `make typecheck` (mypy, target py3.10 — mypy no longer supports 3.9),
  `make fmt` (black + ruff --fix). Run them before committing; the package ships
  `py.typed`.
