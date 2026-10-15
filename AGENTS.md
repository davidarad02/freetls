# AGENTS.md

Guidance for OpenCode/automation agents working in the `freetls` repo.

## What this is

`freetls` is a Python HTTPS/TLS client that controls the **JA4** TLS client
fingerprint (plus JA3 and JA4S). The TLS handshake is done by a Go + uTLS
engine compiled to a native shared library (`libfreetls.so`) and loaded from
Python via `cffi`. Only the ClientHello is overridden; all cryptography is Go
`crypto/tls`. There is no monorepo — one Python package (`src/freetls`) plus a
Go module (`native/`), and no git repo/CI in the worktree.

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
`~/.local/go` and common dirs). The loader also **auto-builds** the engine from
`native/` on first use when Go is available (`FREETLS_NO_AUTOBUILD=1` disables).

Relevant env vars: `FREETLS_LIB` (explicit `.so`), `FREETLS_GO` (Go binary),
`FREETLS_NO_AUTOBUILD`, `FREETLS_SKIP_NATIVE` (build without engine), and
`FREETLS_TCPDUMP` (pcap tests).

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
   `make native`. The committed/packaged `libfreetls.so` is a build artifact.
   The pytest `engine_lib` fixture builds it on demand if missing and sets
   `FREETLS_LIB` to `native/`; the runtime loader also auto-builds from
   `native/` on first use (disable with `FREETLS_NO_AUTOBUILD=1`).
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
- `native/preset_map_gen.go` — **generated** name→`ClientHelloID` map for the
  pinned uTLS (see `tools/gen_presets.py`). The engine also accepts a full uTLS
  `ClientHelloSpec` JSON via the spec's `chlo_json` field (or `profiles.add_profile`),
  so arbitrary/newer fingerprints need no Go change.
- `native/httpx_h2.go` — Go-side HTTP/2 client (`x/net/http2` Framer + hpack)
  exposing configurable SETTINGS/WINDOW_UPDATE/pseudo-header order.
- `native/h2_test.go` / `native/presets_test.go` — assert the exact H2 frames on
  the wire and that every generated preset is buildable.
- `src/freetls/engine/_cffi.py` — cffi binding + `.so` discovery (`FREETLS_LIB`,
  then `src/freetls/_lib`, then `native/`, then `build/`).
- `src/freetls/model.py` — `FingerprintSpec` / `Extension` (the spec model).
- `src/freetls/modes.py` — `baseline_spec` / `specific` / `partial_random` /
  `true_random`; `SAFE_PADDING_EXT_IDS` keeps padding to assigned ext IDs a
  server ignores.
- `src/freetls/session.py` — `TLSSession` (socket-like; `ja4`/`ja3`/`ja4s`,
  `h2_request`). `src/freetls/context.py` — `TLSContext` (`ssl`-style
  `wrap_socket`).
- `src/freetls/fingerprint/` — `ja4.py` (also `ja4_from_spec`), `ja3.py`,
  `ja4s.py`, `parse.py` (raw hello parser), `tables/`, and the report-only
  calculators `ja4x.py`, `ja4t.py`, `ja4l.py`, `ja4h.py`.
- `src/freetls/profiles/` — catalog loader + **runtime registration**
  (`get`/`list_profiles`/`spec`/`add_profile`/`load_file`).
- `src/freetls/transport/` — `requests_adapter.py` (+ `urllib3_conn.py`),
  `httpx_transport.py`, `aiohttp_connector.py`. Bodies are **streamed** (httpx
  chunk-by-chunk over HTTP/1.1; aiohttp feeds the loop as data arrives);
  `transport/_content.py` decodes gzip/deflate/brotli/zstd (optional
  `freetls[content]`); `transport/proxy.py` (HTTP CONNECT + SOCKS4/5),
  `transport/retry.py` (`Retry` backoff) and `transport/websocket.py` (RFC 6455
  client) round out the transport layer. HTTP/3/QUIC is deferred.
- `src/freetls/sse.py` — `iter_sse` / `SSEEvent` (WHATWG event-stream parser).
- `src/freetls/fingerprint/chlo.py` — `chlo_json_from_raw` (captured
  ClientHello -> uTLS ClientHelloSpec JSON, the inverse of the engine's
  `chlo_json` input).
- `src/freetls/verify.py` — self-verification + optional `cryptography` cert
  parity hook.
- `tests/` — `unit/`, `conformance/` (FoxIO vectors), `e2e/`, `pcap/`;
  `tests/_build.py` (raw-hello builders + `CHLO_JSON`), `tests/servers.py`
  (in-process HTTPS app server), `tests/servers/go_https/` (Go h2 test server).

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
  `ocsp_response_b64`, `sct_b64`, `peer_alps_b64`.
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
- **Panic safety.** All C entrypoints (`session_new`, `handshake`, `read`,
  `write`, `chlo_raw`, `h2_request`, `preset_*`) wrap their bodies in
  `recover()` so a Go panic returns an error instead of aborting the host.
- **C-ABI version.** `freetls_abi_version()` (currently `1`) is checked by
  `_cffi._load()`; bump it on an incompatible export change and update
  `_EXPECTED_ABI`. `native/fuzz_test.go` (`FuzzParseSpec`, `FuzzChloJSON`) and
  `native/bench_test.go` cover the JSON/spec parsers. The session registry is
  mutex-guarded (thread-safe across sessions); a single `TLSSession` is not.
- **Timeouts are engine-side.** `freetls_set_timeout` (ms) drives the Go read
  deadline; `TLSSession.settimeout` updates both the Python socket and the
  engine. Sessions are blocking-only (`setblocking(False)` raises).
- **HTTP/2 in the transports is ALPN-driven.** `transport/urllib3_conn.py`
  (requests) and `transport/httpx_transport.py` call the Go H2 client when
  `selected_alpn_protocol() == "h2"` (via `transport/_http2.py`), else HTTP/1.1.
  aiohttp cannot speak HTTP/2, so `transport/aiohttp_connector.py` strips `h2`
  from the offered ALPN. Hop-by-hop headers are filtered for H2 in `_http2.py`.
- **Certificate suite.** Trust/verify/pinning/mTLS spec fields
  (`verify`, `check_hostname`, `system_roots`, `root_ca`, `ca_dir`, `cadata`,
  `client_cert[_pem]`, `client_key[_pem]`, `pinned_sha256`) live in
  `model.FingerprintSpec` and `native/engine.go::specJSON`; the engine builds the
  Go `x509` pool, hostname policy, pin callback, and client cert. The full peer
  chain is exposed via `state.peer_certs_der` / `session.peer_chain()`.
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
