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
- **JA4H is out of scope** (do not add it).

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
  `ja4s.py`, `parse.py` (raw hello parser), `tables/`.
- `src/freetls/profiles/` — catalog loader + **runtime registration**
  (`get`/`list_profiles`/`spec`/`add_profile`/`load_file`).
- `src/freetls/transport/` — `requests_adapter.py` (+ `urllib3_conn.py`),
  `httpx_transport.py`, `aiohttp_connector.py`.
- `src/freetls/verify.py` — self-verification + optional `cryptography` cert
  parity hook.
- `tests/` — `unit/`, `conformance/` (FoxIO vectors), `e2e/`, `pcap/`;
  `tests/_build.py` (raw-hello builders + `CHLO_JSON`), `tests/servers.py`
  (in-process HTTPS app server), `tests/servers/go_https/` (Go h2 test server).

## Wiring facts that span files

- **Spec JSON schema is duplicated in three places.** Adding/changing a spec
  field means editing: `model.py::FingerprintSpec.to_engine`,
  `native/engine.go::specJSON`, and the `buildExtension` switch (or `doH2` for
  H2 fields). Keep them in sync.
- uTLS's JSON parser can **panic** on a malformed `ClientHelloSpec` document;
  the engine wraps parsing/`ApplyPreset` in `recover()` (see `safeParseChloJSON`)
  so a bad `chlo_json` returns an error instead of crashing the host process.
- Precedence in the engine handshake: `chlo_json` > `preset` > explicit
  `ciphers`/`extensions`.
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
