# freetls uQUIC fork

This directory is a **full copy of upstream `refraction-networking/uquic`** at the
version pinned in `native/go.mod`, vendored in-tree so freetls can drive the QUIC
Initial flight and HTTP/3 client from the same engine as its TLS-over-TCP path.

- Upstream module path: `github.com/refraction-networking/uquic`
- `native/go.mod` maps it here with:
  `replace github.com/refraction-networking/uquic => ./third_party/uquic`
- Upstream is a hard fork of `quic-go` that swaps `crypto/tls` for uTLS, so this
  fork is built against **our** vendored uTLS (`../utls`) — and therefore against
  every freetls addition to it (the libcrypto/EVP cipher backend, FFDHE, PSK,
  SRP). `go.mod` carries a `replace ... => ../utls` so the module also builds
  standalone for its own tests; the *engine* build is governed by the main
  module's replace, which wins regardless.

## What we add

freetls changes are **new files**, plus a small, documented **patch set**
(`patches/`) for the few behaviours that cannot be added from a new file.

| File | Purpose |
|---|---|
| `internal/handshake/freetls_evp_ccm.go` | TLS 1.3 CCM/CCM_8 packet-protection AEADs backed by OpenSSL EVP, registered behind `-tags freetls_libcrypto` *(Route C)* |
| `internal/handshake/freetls_evp_ccm_stub.go` | Go-only build: both hooks report "no such suite", so upstream's panics stand *(Route C)* |
| `internal/handshake/freetls_evp_ccm_test.go` | Go tests for the CCM AEAD and header protection *(Route C)* |
| `internal/handshake/freetls_evp_ccm_stub_test.go` | Asserts CCM is unavailable (panics) without the libcrypto backend *(Route C)* |
| `internal/handshake/freetls_server_hello.go` | Exposes the uTLS fork's ServerHello capture through the crypto setup *(Route C)* |
| `u_server_hello.go` | `Conn.FreetlsServerHello()`: the raw ServerHello, for JA4Sq *(Route C)* |

`FORK.md` is also ours.

Upstream's `.claude/` directory (a committed tooling lock file, not source) is
deliberately omitted from the copy.

## Patches (upstream files)

`patches/freetls.patch` edits upstream files; `tools/rebase_uquic.sh` re-applies
it after each re-copy:

- `internal/handshake/cipher_suite.go`: `getCipherSuite` **panics** for any suite
  other than the three Go-native TLS 1.3 suites. Extend it (build-tag gated) to
  return the EVP-backed CCM suites.
- `internal/handshake/header_protector.go`: `newHeaderProtector` panics on
  `default`. CCM uses AES-ECB header protection like GCM, so the two CCM suite
  IDs must join the AES case.

Both are no-ops in the Go-only engine (no `freetls_libcrypto` tag), which is why
CCM is negotiable only in the wide engine.

## Rebase

Run `tools/rebase_uquic.sh` to re-copy the upstream module at the version pinned
in `native/go.mod`, restore our new files, re-apply `patches/*.patch`, re-point
the module at `../utls`, tidy, and rebuild both engines.
