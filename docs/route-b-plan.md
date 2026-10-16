# Route B — Single forked Go TLS engine with a libcrypto (OpenSSL EVP) backend

Status: **complete.** M1 (fork scaffolding), M2 (EVP AEAD + P1 + TLS 1.3 CCM),
M3 (P2 Camellia-CBC), M4 (safe/unsafe mode + ABI 2) and M5 (packaging) are
implemented, tested and verified. This document is the source of truth for the
work.

Related: `AGENTS.md` (architecture/wiring facts), `README.md`.

## 0. Status and deviations (measured against OpenSSL 3.5.5)

Two assumptions in the original plan turned out to be wrong; the scope is
adjusted to match what OpenSSL 3.5.5 actually implements (per D1):

- **Camellia-GCM is not in OpenSSL 3.5.5** (only Camellia-CBC). Dropped from P1.
- **ARIA-CBC is not in OpenSSL 3.5.5's TLS cipher list** (its EVP `ARIA-*-CBC`
  primitive exists, but the SSL layer does not wire an ARIA-CBC suite). Dropped
  from P2, consistent with D1.
- **TLS 1.3 CCM is not in OpenSSL 3.5.5's TLS stack** (only AES-GCM and
  ChaCha20 for TLS 1.3). Its EVP `AES-128-CCM` *is* available, so
  `TLS_AES_128_CCM[_8]_SHA256` remains implemented (record framing is ours) and
  is validated at the AEAD/framing level, but **no local OpenSSL or Go server
  negotiates it**, so there is no end-to-end handshake test.

Resulting scope: **P1 = 14 TLS 1.0–1.2 suites** (6 ARIA-GCM + 8 AES-CCM/CCM_8)
plus **2 TLS 1.3 CCM**; **P2 = 8 Camellia-CBC suites**. Go native 25 + 24 = **49
completable suites**.

### Implemented so far
- `native/third_party/utls/` fork + `replace` + `tools/rebase_utls.sh` +
  `FORK.md` + `freetls_libcrypto` build tag (M1).
- `evp_cgo.go`, `aead_evp.go`, `cipher_evp_register.go`: EVP GCM/CCM AEAD bridge
  and suite registration (M2).
- `block_evp.go`: EVP `cipher.Block` wrapper (ECB) reused by Go's CBC/MAC/record
  logic, plus the 8 Camellia-CBC suites (M3).
- `make libcrypto` builds the wide engine; `make test-libcrypto` runs the fork's
  EVP tests; `tests/e2e/test_route_b_suites.py` verifies each TLS 1.2/1.0/1.1
  suite against `openssl s_server` plus preset JA4 parity (27 tests).
- Safe/unsafe mode (M4): engine exports `freetls_supported_ciphers` /
  `freetls_supported_extensions` / `freetls_spec_raw`; C-ABI bumped to **2**;
  `freetls.set_safe_mode` / `get_safe_mode` and `FingerprintSpec.safe`;
  `freetls/safety.py` validates the effective hello (spec/preset/chlo_json)
  against the whitelist; `modes.safe_random` (and `safe=` on the random modes)
  draws only from backed ciphers + whitelisted extensions. Catalog: **75/220**
  profiles pass (unchanged with the wide engine, since the failures are ECH /
  trust_anchors / generic extensions, not ciphers).
- The wide engine completes **51** cipher suites (25 Go + 2 legacy ChaCha20 +
  24 Route B), up from 27.
- Packaging (M5): the OpenSSL 3.5.5 source is a git submodule at
  `native/third_party/openssl`; `make full` builds it as a static PIC
  `libcrypto.a` and links it into `libfreetls.so` with
  `-Wl,-Bsymbolic -Wl,--exclude-libs,ALL` (no `libcrypto` DT_NEEDED, no exported
  OpenSSL symbols). `FREETLS_FULL=1 pip wheel .` bundles that engine. The
  interposition test (`tests/e2e/test_full_engine.py`) runs Python `ssl` and the
  static engine concurrently without a crash. A plain clone still builds Go-only.

---

## 1. Context and goal

Today `freetls` has one engine: Go + uTLS (a fork of Go `crypto/tls`) compiled to
`libfreetls.so` and loaded via cffi. It controls the ClientHello arbitrarily
(browser presets **and** random/custom specs), but it can only *complete* the
**25** cipher suites that Go `crypto/tls` implements. Everything else it offers
is "unbacked": the handshake fails if a server selects a suite the engine can't
finish.

**Goal:** keep the single arbitrary-ClientHello engine, but widen the set of
cipher suites it can actually negotiate by routing the cryptographic primitives
through **libcrypto (OpenSSL EVP)** via cgo. Add a Python **safe/unsafe mode**
that verifies a spec is fully backed before use.

### Success criteria
- One engine does browser presets and arbitrary/random hellos (unchanged API).
- The engine can complete **P1 + P2 + TLS 1.3 CCM** suites (target ≈47 suites)
  in addition to Go's native 25, over **TLS 1.0–1.3**.
- Existing browser presets produce **byte-identical** ClientHellos and
  JA4/JA3/JA4S (no regression); the default offered cipher list is unchanged.
- New `freetls` **safe mode** rejects any spec whose effective ClientHello
  contains a cipher/extension the engine cannot directly support.
- Clone → works with Go alone; the wide pool is one command (`make full`).
- Coverage gate stays ≥85%; all tests local.

---

## 2. Locked decisions

| # | Decision |
|---|---|
| D1 | Target = **OpenSSL 3.5.5's implemented set** (92 distinct suites: 89 TLS 1.0–1.2 + 3 TLS 1.3). Unassigned/never-implemented IANA entries are out of scope. |
| D2 | Crypto widened via **libcrypto (EVP)** only — **P1 (AEAD extras) + P2 (CBC extras) + TLS 1.3 CCM**. No P3 (DHE/DSS), no P4 (anon), no P5 (PSK/SRP/GOST). |
| D3 | CBC block ciphers use **EVP `cipher.Block` wrappers** (per-block cgo), reusing Go's CBC/MAC/record logic. |
| D4 | libcrypto is **statically linked** into `libfreetls.so`. |
| D5 | The uTLS fork lives **in-module** at `native/third_party/utls` via a `replace` directive. |
| D6 | OpenSSL is an in-repo **git submodule**, **unmodified** (we patch nothing in OpenSSL/libcrypto). |
| D7 | **Linux only** for now. |
| D8 | **TLS 1.0/1.1 enabled** (build/`SECLEVEL=0`). |
| D9 | C-ABI version bumped **1 → 2** (old engines rejected). |
| D10 | Default mode = **unsafe** (current behavior); safe is opt-in. Big README warning. |
| D11 | Portability: default clone/build uses **Go only**; `make full` enables the wide pool. |

---

## 3. Architecture

```
Python (unchanged API + new safe mode)
   │ cffi  (libfreetls.so)
Go engine (native/engine.go, httpx_h2.go)  — JSON spec → ClientHelloSpec, H2, cert suite, tee
   │
forked uTLS (native/third_party/utls)  — arbitrary ClientHello + handshake
   │  cipher / aead / mac / ka hooks
cgo bridge  ──►  libcrypto (OpenSSL EVP, static)   [ARIA/Camellia/CCM/...]
```

Both browser presets and random/custom specs are the *same* engine; only the
`ClientHelloSpec` differs. H2, cert handling, resumption, timeouts, and the cffi
boundary are untouched.

---

## 4. Fork and suite registration

### 4.1 Layout
- `native/third_party/utls/` — a full copy of the pinned uTLS, kept as a nested
  module whose `go.mod` still declares `module github.com/refraction-networking/utls`.
- `native/go.mod` gains `replace github.com/refraction-networking/utls => ./third_party/utls`.
- `docs/route-b-plan.md` (this file) + `native/third_party/utls/FORK.md`
  (diff description) + `tools/rebase_utls.sh` (re-copy upstream, reapply our
  new files, rebuild).

### 4.2 Minimal, rebasable diff
Our changes live in **new files** inside the package (same package ⇒ private
symbols are reachable). New files:
- `cipher_evp_register.go` — the `init()` that registers P1/P2/CCM suites.
- `aead_evp.go` — EVP AEAD wrappers (GCM/CCM/CCM8) implementing `aead`.
- `block_evp.go` — EVP `cipher.Block` wrappers (ARIA/Camellia) for CBC.
- `evp_cgo.go` — the cgo/`libcrypto` bridge (contexts, error handling).

No edits to upstream files are expected; only new files.

### 4.3 Registration correctness (CRITICAL)
`utlsSupportedCipherSuites` is built in `u_common.go`'s `init()` as
`append(cipherSuites, …)`, and `EnableWeakCiphers()` **reassigns** it from
`cipherSuites`. Therefore:
- Register suites into the canonical **`cipherSuites`** slice, **and**
- ensure `utlsSupportedCipherSuites` contains them **order-independently**
  (append to both, nil-guard), never relying on Go init file order.
- TLS 1.3 suites are added to `cipherSuitesTLS13` (looked up directly, no
  snapshot).

New suites are flagged **`suiteDefaultOff`** and are **not** added to
`cipherSuitesPreferenceOrder*`, so the default offered list and browser presets
are unchanged.

---

## 5. Crypto bridge (P1 + P2 + TLS 1.3 CCM)

| Phase | Suites added | New code | Risk |
|---|---|---|---|
| **P1** | AEAD extras reusing existing ECDHE/RSA kex: ARIA-128/256-GCM (6 suites) and AES-128/256-CCM + CCM_8 (8 suites). Camellia-GCM dropped (not in OpenSSL 3.5.5). | EVP AEAD wrappers + table entries | low |
| **P2** | CBC extras reusing existing kex: ARIA/Camellia-CBC + SHA1/256/384 | EVP `cipher.Block` wrappers | low–med |
| **CCM (TLS1.3)** | `1304`/`1305` (`TLS_AES_128_CCM[_8]_SHA256`) | `cipherSuitesTLS13` entries (SHA256) + EVP CCM | low |

Details:
- **AEAD:** implement `aead` (`cipher.AEAD` + `explicitNonceLen()`). CCM requires
  setting the total plaintext length before AAD/update; CCM_8 has an 8-byte tag.
  Match Go's nonce/prefix scheme (`prefixNonceAEAD`, 4-byte explicit nonce for
  TLS 1.2 GCM; 12-byte for TLS 1.3).
- **CBC:** EVP `cipher.Block`; reuse Go's `mac` (SHA-1/256/384) and CBC record
  logic; handle TLS 1.0/1.1 implicit IV vs TLS 1.2 explicit IV.
- **Lifecycle:** per-connection EVP contexts; free on `close()`; capture
  `ERR_get_error` immediately and `ERR_clear_error` between ops (OpenSSL's error
  queue is thread-local while Go goroutines migrate).
- **Build tag** `freetls_libcrypto` gates all of the above; without it the fork
  builds Go-only (today's behavior).

---

## 6. Safe / unsafe mode (Python)

### 6.1 Engine surface
New C exports (ABI 2):
- `freetls_supported_ciphers()` → JSON array of completable suite IDs
  (Go-native ∪ libcrypto-added).
- `freetls_supported_extensions()` → JSON array of supported extension type IDs.

### 6.2 API
- `freetls.set_safe_mode(bool)` / `freetls.get_safe_mode()`.
- `FingerprintSpec.safe: bool | None` per-spec override (None = global).
- Default = **unsafe** (backward compatible).

### 6.3 Rule (strict)
Validate the **effective** ClientHello (after preset / `chlo_json` / random
expansion):
- Every cipher ∈ `supported_ciphers`.
- Every JA4-counted extension ∈ the **supported-extension whitelist**.
- **GREASE is exempt** (JA4 excludes it).
- Violations raise `SpecError` listing offenders.

**Whitelist (pass):** `sni, alpn, supported_versions, supported_curves,
ec_point_formats, signature_algorithms, key_share, psk_key_exchange_modes,
extended_master_secret, renegotiation_info, session_ticket, status_request, sct,
compress_certificate, padding, application_settings (ALPS), pre_shared_key,
record_size_limit`.

**Fail:** `generic` (arbitrary ids), **ECH `0xfe0d`**, **trust_anchors
`0xca34`**, delegated_credentials, and any unknown id.

**Consequence:** modern **browser presets fail safe mode** (they carry GREASE
ECH / trust_anchors). Safe mode is for fully-backed custom/simple configs.

### 6.4 Random modes under safe mode
The current `partial_random` / `true_random` pad with **generic** extensions
(`SAFE_PADDING_EXT_IDS`) and draw ciphers from the full 356-entry pool — both
fail safe mode. Safe mode therefore requires a **new "safe randomization"**:
draw ciphers from `supported_ciphers` and extensions from the whitelist. This is
new functionality, added as part of this work.

The safe defaults are **adaptive**: the cipher count defaults to about half the
backed pool (which maximises `C(n, k)`, and hence the number of distinct
`JA4_b` values — drawing the whole pool would be deterministic), and the
extension count defaults to a random subset of the whitelist's free extensions.
The unsafe extension default was also corrected from 8 / 40 to `⌊47/2⌋ = 23`
(the `C(47, k)` maximum). Measured distinct JA4s over 800 seeds: safe
`partial_random`/`safe_random` 785 (was 66/1) and `true_random` 800 (was 1) on
the Go-only engine; 800 on the wide engine.

### 6.5 What safe mode loses (measured)
Against the current catalog: **75 / 220 profiles pass; 145 fail** (50 unsupported
ciphers; 15 ECH; 10 trust_anchors; the rest preset-specific ids such as
`0x7550`, `0x0022` delegated_credentials, `0x3374`, `0x754f`).

| mode | cipher-hash (b) | ext factor | total S | n₅₀ | P(collision @10k) |
|---|---|---|---|---|---|
| unsafe `partial_random` / `true_random` | ≤2^48 | C(47,23)=1.6e13 | ~4.5e27 | ~7.9e13 | ~0 |
| safe, Go-only (27 backed) | C(12,6)=924 … C(22,11)=7.1e5 | 2^5 | ~3e4 … 2.3e7 | 202 … 5.6e3 | high |
| safe, wide (51 backed) | C(36,18)=9.1e9 … C(46,23)=8.2e12 | 2^5 | ~2.9e11 … 2.6e14 | 6.3e5 … 1.9e7 | ≤1.7e-4 |

(`specific` mode over the backed pool reaches `C(51,k)` up to 2.5e14 on the wide
engine, i.e. near the 2^48 cipher-hash cap.)

**Not lost in safe mode:** GREASE control, padding, ALPS, cert compression,
record_size_limit, OCSP/SCT, resumption/PSK, PQ groups, extension order control,
all transports/cert-suite/H2/timeouts, and the 75 backed profiles.

---

## 7. Build, packaging, portability

- **Default (Go-only):** `make venv` / `pip install` builds the engine as today
  (25 suites). Clone → works with just Go. The loader's auto-build stays Go-only
  and never triggers an OpenSSL build.
- **Full:** `make full` → build the pinned OpenSSL submodule as a **static PIC
  `libcrypto.a`** → rebuild `libfreetls.so` with `-tags freetls_libcrypto`.
  Requires Go + perl + make. Cached.
- **Wheels:** ship the full (wide) engine, statically linked, so `pip install`
  users need no build.
- **Symbol hygiene (CRITICAL):** Python's `_ssl` already links the system
  `libcrypto.so.3`. The embedded libcrypto must not interpose:
  `-fvisibility=hidden`, `-Wl,--exclude-libs,ALL`, `-Wl,-Bsymbolic`, and a
  version script exporting only `freetls_*`.
- OpenSSL source comes from the submodule (network at clone time); the submodule
  is only needed for `make full`, not for the default build.

---

## 8. Testing and verification

- **Per-suite negotiation:** local `openssl s_server` forced to each added suite
  (`-cipher` / `-ciphersuites`); assert completion + JA4.
- **Byte-parity regression:** all existing presets produce identical
  ClientHello/JA4/JA3/JA4S with and without `freetls_libcrypto`; default offered
  list unchanged.
- **Interposition test:** import `ssl` + `freetls`, run concurrent handshakes,
  no crash.
- **Safe-mode tests:** every whitelisted element passes; ECH/trust_anchors/
  generic fail; presets fail; the 75 passing profiles pass; random modes use
  safe randomization.
- **Lifecycle/leak:** EVP contexts freed on close (extend `active_sessions`
  leak tests); fuzz the EVP bridge (`native/fuzz_test.go`).
- **Consistency:** extend `tests/e2e/test_spec_consistency.py` to random subsets
  of the widened pool.
- Keep coverage ≥85% (`make coverage`); Go tests + fuzz seeds pass.

---

## 9. Milestones

1. **Fork scaffolding** — `third_party/utls` + `replace` + `rebase_utls.sh` +
   `freetls_libcrypto` build tag. Engine builds and all tests pass unchanged
   (no new suites yet).
2. **EVP AEAD bridge + P1 + TLS 1.3 CCM** — table entries, AEAD wrappers,
   per-suite tests.
3. **P2 CBC** — EVP `cipher.Block` wrappers.
4. **Safe/unsafe mode** — engine exports, ABI bump to 2, whitelist validation,
   safe randomization, tests.
5. **Packaging & docs** — `make full`, static symbol-hidden build, wheel,
   README warning + AGENTS updates, coverage gate.

---

## 10. Out of scope
P3 (DHE/DSS), P4 (anonymous suites), P5 (PSK/SRP/GOST/SEED); Windows/macOS;
arbitrary extension-order / GREASE control changes (Gaps 1–2 unaffected for
JA4); native ECH/ALPS/trust_anchors/record_size_limit semantics; HTTP/3.

---

## 11. Edge cases and risks (from the pre-implementation audit)

| ID | Risk | Mitigation |
|---|---|---|
| A1 | `utlsSupportedCipherSuites` init snapshot / `EnableWeakCiphers` rebuild | register into `cipherSuites` + both, order-independent |
| A2 | default list must not change | `suiteDefaultOff` + keep out of preference order |
| A4 | double fork rebase drift | new-files-only diff + `rebase_utls.sh` |
| A5 | tooling (`gen_presets.py`) must target the fork | point tooling at `third_party/utls` |
| B1 | **two OpenSSL copies** (Python `_ssl`) | hide symbols (see §7); interposition test |
| B2 | static libcrypto must be PIC | OpenSSL configure with `-fPIC` |
| B3 | OpenSSL thread-local error queue vs goroutine migration | capture errors immediately |
| B5 | legacy provider (RC4/GOST) unavailable statically | RC4/3DES stay Go-native; GOST deferred |
| C1 | EVP CCM length-before-AAD; CCM_8 tag | correct AEAD wrapper |
| C2 | nonce/tag scheme must match Go | reuse Go's wrappers |
| C3 | CBC implicit vs explicit IV; per-block cgo | reuse Go CBC; accept slowness |
| C8 | TLS 1.3 CCM hash selection | table entry with `crypto.SHA256` |
| D1 | JA4 caps: `b` = 2^48; counts 2-digit (max 99) | document; don't exceed 99 |
| E2 | safe-mode semantics | strict whitelist (§6.3) |
| F4 | cross-platform builds | Linux only |

---

## 12. Appendix — coverage math

- OpenSSL 3.5.5 families: RSA 19, DH 39 (DHE-RSA 17 / DHE-DSS 12 / ADH 10),
  ECDH 31 (ECDSA 16 / RSA 12 / anon 3), TLS 1.3 3 → **92 total**.
- Go native = **25**; P1+P2 target ≈ **47** (ECDHE non-anon 28 + RSA 19).
  Actual P1 (after dropping Camellia-GCM) = **16** (14 TLS 1.2 + 2 TLS 1.3 CCM);
  Go 25 + 16 = **41** completable suites.
- Cipher hash saturates at 2^48 only for N≥76 (k=14) / N=92 (k=12); P1+P2 alone
  tops out at C(47,23)=2^43.9.
- Full S = min(C(N,k),2^48) × min(C(M,j),2^48), M = 47 safe padding ids.
- Birthday: n₅₀ ≈ 1.1774·√S; P(repeat among n) ≈ n²/(2S).

---

## 13. Open items
- None blocking. All prior decisions (D1–D11, whitelist, default unsafe,
  record_size_limit passes) are locked.
- README must carry a **prominent warning** that the default is unsafe.
