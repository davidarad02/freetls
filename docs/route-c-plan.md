# Route C — HTTP/3 + QUIC

Status: **complete.** P1 (passive JA4q/JA4Sq calculators), P2 (engine emits a
spoofed QUIC Initial; EVP/CCM parity; ABI **3**), P3 (HTTP/3 application layer +
transports + RFC 9297 datagrams) and P4/P5 (profiles/catalog/modes/docs +
deferred hooks) are implemented, tested and verified. This document is the
source of truth for the work.

Related: `AGENTS.md` (architecture/wiring facts), `README.md`,
`docs/route-b-plan.md` (the TCP engine this builds on).

## 0. Context and goal

freetls was TCP-only: every fingerprint (JA4, JA3, JA4S) came from bytes carried
in TLS records, and HTTP/3/QUIC was out of scope. Route C closes that gap with
the same rigour and feature matrix as the TCP implementation: spec model →
engine emission → fingerprints → profiles/modes → safe mode → transports →
tests → docs.

The two hardest pieces already existed and were unused:

- **In-tree**: the vendored uTLS fork ships `UQUICConn`/`UQUICClient`/
  `ApplyPreset` (`u_quic.go`), the stdlib QUIC API (`quic.go`), typed QUIC
  transport parameters with GREASE and `FakeQUICTransportParameter`
  (`u_quic_transport_parameters.go`), the `QUICTransportParametersExtension`
  (ext 57) and `internal/quicvarint/`.
- **External**: `github.com/refraction-networking/uquic` — a hard fork of
  quic-go that swaps `crypto/tls` → uTLS — supplies the QUIC transport
  (`UTransport` + `QUICSpec`), a production-grade `http3` package, and 7
  built-in browser parrots.

### Success criteria

- JA4q + JA4Sq reported from the bytes the engine actually emitted/received.
- A spoofable QUIC Initial (DCID/SCID length, packet number, token, transport
  parameters), reachable from the spec model.
- Production-shaped HTTP/3 (real multiplexing, dynamic QPACK, flow control)
  reachable from `httpx` and `requests`/`urllib3`.
- RFC 9297 datagrams.
- Profiles/modes/docs at parity with the TCP side.
- No regression to any TCP behaviour; the TCP paths stay byte-identical.

## 1. Locked decisions (D1–D14)

| # | Decision |
|---|---|
| 1 | **Scope**: all four layers, phased — L1 passive calculators → L2 engine emission → L3 HTTP/3 client → L4 profiles/docs. |
| 2 | **Stack**: vendor uQUIC in-tree at `native/third_party/uquic` (`replace`), built on **our** uTLS fork. Compiled into **both** engines. C ABI → **3**. |
| 3 | **HTTP/3 fidelity**: production-shaped — real multiplexing, dynamic QPACK, flow control (uQUIC's `http3`). |
| 4 | **Integrations**: httpx + requests/urllib3. **aiohttp stays HTTP/1.1-only** (documented, as for H2). |
| 5 | **EVP/libcrypto parity**: **full** — TLS 1.3 CCM (0x1304/0x1305) negotiable over QUIC via the fork's EVP AEADs. |
| 6 | **Fingerprints**: **JA4q + JA4Sq**, plus the JA4H HTTP/3 version code. No transport-parameter or Initial-header fingerprint. |
| 7 | **Transport parameters**: typed structured `Extension` kind. |
| 8 | **Profiles**: mirror uTLS-preset behaviour using uQUIC's own parrots (7 fingerprints). |
| 9 | **UDP plumbing**: Python owns the UDP socket, passes a dup'd fd; Go `net.FilePacketConn`. |
| 10 | **Session API**: new `QUICSession`, **concurrent**. |
| 11 | **Tests**: local HTTP/3 server, UDP pcap verification, JA4q/JA4Sq vectors, QUIC suite matrix. |
| 12 | **Out of scope**: proxies over QUIC (CONNECT-UDP/MASQUE); Alt-Svc / HTTPS-RR discovery. |
| 13 | **Deferred, designed for**: 0-RTT, session resumption, ECH over QUIC. |
| 14 | **HTTP/3 datagrams (RFC 9297)**: in scope; WebTransport deferred. |

**Explicit exclusions** (decision 6): no transport-parameter fingerprint
calculator and no Initial-header fingerprint.

## 2. Architecture

```
Python:  QUICSession (UDP socket, dup'd fd)      +  transport/_http3.py
               │  cffi
Go:      native/quic.go (handshake)  +  native/httpx_h3.go (HTTP/3 + datagrams)
               │  uQUIC UTransport / http3.ClientConn
               ▼
         uQUIC (quic-go + uTLS)  →  our uTLS fork  →  crypto/tls
```

- Python resolves the host, opens an **unconnected** UDP socket, and passes a
  dup'd fd. Go wraps it with `net.FilePacketConn` (not `net.FileConn`).
- `native/quic.go` builds the `QUICSpec` (a uQUIC preset or the session's own
  ClientHello + Initial shape), dials through a `UTransport`, and captures the
  ClientHello (offline marshal) and ServerHello (fork hook) for fingerprinting.
- `native/httpx_h3.go` runs HTTP/3 over **that** connection through a single
  `http3.ClientConn` (see §5). Requests and RFC 9297 datagrams share it.

## 3. P1 — passive QUIC fingerprint calculators (pure Python)

- `src/freetls/fingerprint/quic.py` — QUIC varint codec, RFC 9001 Initial key
  schedule (v1 **and** v2 salts/labels), Initial decryption (header protection +
  AEAD), frame walker, cross-packet CRYPTO reassembly,
  `parse_quic_client_hello`, `parse_transport_parameters`,
  `is_grease_transport_parameter`. AES comes from `cryptography` via a **lazy**
  import; HKDF is stdlib, so the core package keeps no third-party runtime dep.
- `ja4.py` / `ja4s.py` gained a `transport=` kwarg (`"t"` default, `"q"` for
  QUIC). `ja4_from_bytes(raw, transport="q")` is the JA4q entry point; the ext-57
  kind is in `ja4._KIND_ID`.
- `fingerprint/chlo.py` rejects ext `0x0039` with a specific `SpecError`: uTLS
  resolves ext 57 *by name* to a non-JSON extension, so `chlo_json` can never
  represent QUIC transport parameters.
- Tests: `tests/unit/test_quic.py` (incl. the RFC 9001 Appendix A.1
  known-answer vector), `tests/conformance/test_ja4q_vectors.py`.

## 4. P2 — engine emits a spoofed QUIC Initial (+ EVP parity)

### Vendoring

- `native/third_party/uquic` (a full copy of `refraction-networking/uquic`) +
  `replace github.com/refraction-networking/uquic => ./third_party/uquic` in
  `native/go.mod`; `tools/rebase_uquic.sh` + `FORK.md`.
- `native/quic_link.go` blank-imports `uquic` and `uquic/http3` so both engines
  compile and link the QUIC stack from the start (a dependency/version problem
  shows up as a build failure, not at first use).

### EVP/CCM parity (decision 5)

- Fork file `native/third_party/utls/freetls_evp_aead.go` (tag
  `freetls_libcrypto`) exports `FreetlsNewEVPCCMAEAD`, plus a `!freetls_libcrypto`
  stub.
- Two build-tag-gated hunks in uQUIC (`internal/handshake/cipher_suite.go`,
  `header_protector.go`; recorded in
  `native/third_party/uquic/patches/freetls.patch`): register 0x1304/0x1305 and
  add them to the AES header-protection case. Header protection needed **no** EVP
  bridge.
- `make test-uquic` runs both builds (tagged + untagged).

### Spec model (three-place sync)

`model.py::to_engine`, `engine.go::specJSON`, `buildExtension` (+
`FingerprintSpec.copy()`):

- `TransportParameter` (typed: `varint`, `grease`, `fake`, `padding`,
  `version_information`, `source_connection_id`, plus empty kinds).
- `QuicInitialSpec` (`version`, `dcid_len`, `scid_len`, `token`,
  `udp_datagram_min_size`, `packet_number`, `packet_number_len`,
  `randomize_transport_parameters`, `suppress_transport_parameters`).
- `Extension.quic_transport_parameters(*params)`.
- `FingerprintSpec.quic` / `.quic_id` / `.quic_datagrams` / `.quic_early_data`.

### Engine + ABI

- `native/quic.go`, `quic_id_map.go` (hand-maintained — uQUIC has no registry),
  `freetls_quic_handshake`, `freetls_quic_id_list`, `freetls_quic_id_raw`;
  QUIC branches in `freetls_get_client_hello` / `get_server_hello` /
  `get_state` / `freetls_close`. `fillState` is shared with TCP.
- **ABI is 3** (`native/engine.go` `abiVersion`, `_cffi.py` `_EXPECTED_ABI`).
- Python `src/freetls/quic.py` → `QUICSession`; `safety.effective_hello` has a
  `quic_id` branch.

### Findings (each cost real debugging time)

1. **`initial_source_connection_id` is mandatory.** A conformant server silently
   drops an Initial that omits it (no error). `ensureInitialSourceCID` appends it
   unless explicitly suppressed. It does not change JA4q (a parameter inside ext
   57).
2. **uQUIC's `Dial` can hang forever** with a custom `ClientHelloSpec` (its
   handshake-idle-timeout path never fires). `dialQUIC` enforces the engine's own
   deadline and closes the PacketConn to release the dial.
3. **RFC 9001 §5.2 keys the whole client flight from the FIRST Initial's DCID.**
   Later client Initials carry a different DCID but the same keys; deriving per
   packet is wrong (fixed in `fingerprint/quic.py` and `tests/pcap/_quic.py`).
4. **Datagrams need the wire parameter, not just the config.** `quic.Config`
   `EnableDatagrams` alone is insufficient: uQUIC takes transport parameters from
   the `ClientHelloSpec`, so `ensureMaxDatagramFrameSize` injects
   `max_datagram_frame_size` (0x20) when `quic_datagrams` is set — otherwise the
   peer closes with "missing QUIC Datagram support".
5. **`net.UDPConn.WriteTo` refuses on a pre-connected socket**, and the failure
   does not surface (it hangs). Python therefore hands over an **unconnected**
   UDP socket and the literal IP + port.
6. **JA4Sq needs a ServerHello capture.** QUIC has no TLS record stream to tee;
   the uTLS fork records the Initial-level handshake bytes
   (`freetls_quic_server_hello.go` + a `u_quic.go` hunk) and uQUIC exposes them
   via `Conn.FreetlsServerHello()`.

## 5. P3 — HTTP/3 application layer + transports

### Connection ownership (the critical design point)

A `PacketConn` can back only one `quic.Transport`. Rather than let
`http3.Transport` dial its own connection, the engine wraps the connection the
handshake already established in **one `http3.ClientConn`** and runs every
request and datagram through it. That keeps exactly one
`quic.Transport`/`PacketConn`, preserves the ClientHello/ServerHello capture, and
avoids a second stream-accept loop (which a `Transport` would start).

- `native/httpx_h3.go` exports `freetls_h3_request` (JSON in/out, mirroring
  `freetls_h2_request`) and `freetls_h3_datagram_{open,send,recv}`. All are
  `recover()`-wrapped and return `C.CString`.
- Per-request `context.WithTimeout` from `timeout_ms`/`timeout`.

### Python

- `_cffi.py`: `_CDEF` entries + `EngineSession.h3_request` /
  `h3_datagram_open` / `h3_datagram_send` / `h3_datagram_recv`.
- `QUICSession.request(path, method, headers, body)` mirrors `h2_request`
  (buffered body) and adds the JA4H. `open_datagram_flow` / `send_datagram` /
  `recv_datagram` expose RFC 9297 datagrams (opt-in via
  `FingerprintSpec.quic_datagrams`).

### Transports

- `transport/_http3.py` mirrors `_http2.py`. HTTP/3 is dispatched by the
  explicit `http3=True` opt-in (not by ALPN), because Alt-Svc discovery is out
  of scope; `_http2.negotiated_protocol` still centralises the H2-vs-H1 choice.
- `httpx_transport._open(..., http3=False)` branches to a `QUICSession` before
  the TCP connect; `FreeTLSTransport(..., http3=True)`.
- `urllib3_conn.Ja4HTTPSConnection` gains an H3 path (`_http3`, UDP, skip TCP,
  `version=30`, `version_string="HTTP/3"`); `JA4Adapter(..., http3=True)`.
- HTTP/3 is **opt-in** (Alt-Svc/HTTPS-RR discovery is out of scope). Proxy + H3
  raises. `_content.py` is reused unchanged; aiohttp stays HTTP/1.1-only.
- `fingerprint/ja4h.py` maps `"HTTP/3"`/`"h3"` → `"30"`.

### Tests

`tests/e2e/test_http3.py` (app-data round trip, JA4H version, headers echo, 16
concurrent requests on one connection, datagram echo, httpx + requests paths,
proxy rejection) and `tests/e2e/test_quic_suites.py` (the TLS 1.3 suite matrix
with app data; the CCM rows skip). The server is `tests/servers/go_http3/`
(upstream quic-go, so the client is validated against an independent stack) with
a `/echo-datagram` handler.

## 6. P4 — profiles, catalog, modes, docs

- `tools/gen_catalog.py` expands the **7** unique uQUIC fingerprints over 4 QUIC
  variants (base `h3`, `_noalpn`, `_nosni`, `_nosni_noalpn`; `_h1` dropped) with
  stable-JA4q pruning, and **merges** them into `catalog.json` (one namespace,
  D8). Measured: **220 TCP + 28 QUIC = 248** profiles; 110 distinct JA4 and 12
  distinct JA4q (the IPv4/IPv6 pairs and Firefox A/B/C differ only in the Initial
  shape, so they share a JA4q). `make gen` regenerates reproducibly.
- `profiles/__init__.py`: `Profile` gains `quic_id`/`ja4q`/`ja4q_a`;
  `Profile.spec()` builds a QUIC spec; `add_profile`/`load_file` accept
  `quic_id`/`ja4q`; `find_ja4`/`search` span TCP and QUIC; `h3_bundle` helper;
  `catalog_info` reports TCP/QUIC and distinct-JA4/JA4q counts.
- `modes.py`: `DEFAULT_QUIC_ALPN = ["h3"]`, `default_quic_transport_parameters`,
  and `quic_baseline_spec` / `quic_specific` / `quic_partial_random` /
  `quic_true_random` (TLS 1.3 only, TLS 1.3 cipher pool). Transport-parameter
  contents/order do **not** change JA4q (it hashes extension types only), so
  randomising them varies the wire, not the fingerprint.

## 7. P5 — deferred hooks

- Datagrams are implemented (P3).
- **Deferred but designed for** (D13): 0-RTT (`UTransport.DialEarly`), session
  resumption/tickets, ECH over QUIC. `FingerprintSpec.quic_early_data` is
  serialised and ignored by the engine; all are additive fields/exports, so they
  need **no** ABI bump.
- **WebTransport** is out of scope (a separate module).

## 8. Testing and verification

- Unit/conformance: `tests/unit/test_quic.py` (RFC 9001 A.1 and RFC 9369 A.1
  known-answer vectors, v1 and v2 Initial round trips), `tests/unit/test_quic_model.py`,
  `tests/unit/test_quic_session.py`, `tests/conformance/test_ja4q_vectors.py`.
- Wire independence (JA4q only): `tests/pcap/_quic.py` (an independent RFC 9001
  implementation, no freetls imports) + `tests/pcap/test_quic_initial.py`
  (including the SNI-less case, where the reported JA4q must equal the wire).
  ⚠️ JA4Sq is **not** pcap-verifiable (the ServerHello rides under handshake
  keys); it is verified from the engine's captured ServerHello
  (`test_quic_handshake.py` asserts `server_hello()` and `ja4sq`).
- End-to-end: `tests/servers/go_http3/` (upstream quic-go), driven by
  `tests/e2e/test_quic_handshake.py`, `test_http3.py`, `test_quic_suites.py`.
- Suite matrix: every QUIC-capable TLS 1.3 suite with app data. CCM is **not**
  negotiable against Go/OpenSSL servers (the same deviation as Route B §0); the
  rows skip with that reason and are covered at the AEAD level by `make
  test-uquic`. The Go-only engine skips CCM entirely.
- Gates: `make test`, `make coverage` (85%), `make lint`, `make typecheck`,
  `make test-uquic`, `make test-libcrypto`, `make gen` (catalog reproducibility).
- Regression: the TCP paths stay byte-identical; QUIC is additive.

## 9. Out of scope

- Proxies over QUIC (CONNECT-UDP/MASQUE).
- Alt-Svc / HTTPS-RR discovery (HTTP/3 is opt-in).
- WebTransport.
- GOST/SEED, native ECH/ALPS/trust_anchors semantics (as in Route B).
- A transport-parameter or Initial-header fingerprint (D6).
- JA4SSH, JA4D/JA4D6, JA4N.

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| **uTLS version skew** — uQUIC pins an older uTLS. | Built against our fork first; the main module's `replace` wins and there was no API drift. |
| **Dependency reconciliation** (x/net, x/crypto, qpack). | `go mod tidy`; MVS picks the max; the fork's `go.mod` still resolves. |
| **Build size/time** — a large dep tree in both engines. | Accepted; `.so` sizes documented. |
| **EVP patch drift** — patching uQUIC. | Documented `patches/` hunk re-applied by `rebase_uquic.sh`, build-tag gated. |
| **Spec-schema triplication.** | Followed the convention; spec-consistency test. |
| **Production-shaped H3 is new territory.** | Used uQUIC's `http3` (real multiplexing/QPACK) rather than extending `doH2`. |
| **Concurrency safety.** | One `http3.ClientConn` (thread-safe `RoundTrip`); the registry is mutex-guarded; the request path is stateless per call. |
| **Non-constant-time `math/big`** for ephemeral DH/SRP. | Documented; acceptable for a fingerprinting client. |

## 11. Measured deviations

- TLS 1.3 CCM is implemented but **not negotiable end-to-end** against local
  OpenSSL/Go servers (AEAD-verified only, as in Route B §0).
- `initial_source_connection_id` and `max_datagram_frame_size` are injected into
  the spec's transport parameters when required; neither changes JA4q.
- The QUIC catalog holds 28 entries but only 12 distinct JA4q (the Initial shape
  is a real signal JA4q cannot see).
