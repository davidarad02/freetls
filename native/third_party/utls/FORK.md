# freetls uTLS fork

This directory is a **full copy of the upstream `refraction-networking/utls`
module** at the version pinned in `native/go.mod`, vendored in-tree so freetls
can add cipher suites backed by OpenSSL `libcrypto` without patching upstream.

- Upstream module path: `github.com/refraction-networking/utls`
- `native/go.mod` maps it here with:
  `replace github.com/refraction-networking/utls => ./third_party/utls`

## What we add

freetls changes are **new files** in the `tls` package, plus a small, documented
**patch set** (`patches/`) for the few behaviours that cannot be added from a new
file (see below). Both are rebasable (see `tools/rebase_utls.sh`).

| File | Purpose |
|---|---|
| `freetls_buildtag.go` | `const freetlsLibcrypto = false` (default, Go-only build) |
| `freetls_buildtag_libcrypto.go` | `const freetlsLibcrypto = true` (`-tags freetls_libcrypto`) |
| `cipher_evp_register.go` | `init()` registering P1/P2/TLS1.3-CCM suites *(M2/M3)* |
| `aead_evp.go` | EVP AEAD wrappers (GCM/CCM/CCM8) implementing `aead` *(M2)* |
| `block_evp.go` | EVP `cipher.Block` wrappers (ARIA/Camellia CBC) *(M3)* |
| `evp_cgo.go` | cgo `libcrypto` bridge (contexts, error handling) *(M2)* |
| `freetls_supported.go` | `FreetlsSupportedCipherSuiteIDs()` for safe-mode validation *(M4)* |
| `evp_freetls_test.go` | Go tests for the EVP AEAD/block bridge *(M2/M3)* |
| `freetls_evp_aead.go` | `FreetlsNewEVPCCMAEAD()`: exports the EVP CCM AEAD as a `cipher.AEAD` for the QUIC packet-protection layer (uQUIC) *(Route C)* |
| `freetls_evp_aead_stub.go` | Go-only build's stub: returns an error, so CCM over QUIC is wide-engine only *(Route C)* |
| `freetls_quic_server_hello.go` | Captures the ServerHello from QUIC Initial-level handshake data, for JA4Sq *(Route C)* |
| `ffdhe_key_agreement.go` | `dhKeyAgreement`: FFDHE (DHE) client key exchange *(P1)* |
| `ffdhe_dsa.go` | DSA (DSS) signature verification for DHE-DSS *(P1)* |
| `ffdhe_ciphers.go` | DHE-RSA/DHE-DSS suite registration (Go-native ciphers) *(P1)* |
| `ffdhe_ciphers_evp.go` | DHE suites backed by the EVP bridge (ARIA-GCM/AES-CCM/Camellia-CBC) *(P1)* |
| `ffdhe_freetls_test.go` | Go tests for the FFDHE key agreement *(P1)* |
| `psk_key_agreement.go` | `pskKeyAgreement`: pure PSK / DHE-PSK / ECDHE-PSK / RSA-PSK client key exchange *(P2)* |
| `psk_ciphers.go` | PSK suite registration (Go-native AES-GCM/CBC/ChaCha) *(P2)* |
| `psk_ciphers_evp.go` | PSK suites backed by the EVP bridge (ARIA-GCM/AES-CCM/Camellia-CBC) *(P2)* |
| `psk_freetls_test.go` | Go tests for the PSK premaster/CKE *(P2)* |
| `srp.go` | `srpKeyAgreement`: SRP-6a client key exchange (RFC 5054) *(P2)* |
| `srp_ciphers.go` | SRP suite registration (Go-native AES-CBC) *(P2)* |
| `srp_freetls_test.go` | Go tests for the SRP-6a key agreement *(P2)* |

`FORK.md` is also ours.

## Patches (upstream files)

A few behaviours cannot be added from a new file, so `patches/freetls.patch`
edits upstream files; `tools/rebase_utls.sh` re-applies it after each re-copy:

- `handshake_client.go`: allow `*dsa.PublicKey` server certificates (DHE-DSS);
  skip the Certificate message + `verifyServerCertificate` for certless suites
  (anonymous ADH, PSK, SRP) and gate anonymous suites behind
  `Config.Anonymous`.
- `common.go`: add `Config.Anonymous`, `Config.PskIdentity`, `Config.Psk`,
  `Config.SrpUsername` and `Config.SrpPassword`.
- `u_quic.go`: one call in `UQUICConn.HandleData` recording the Initial-level
  handshake bytes (the ServerHello), so the engine can report JA4Sq for QUIC —
  there is no TLS record stream to tee.

## Registration rules (do not break these)

`utlsSupportedCipherSuites` is built in `u_common.go`'s `init()` and reassigned
by `EnableWeakCiphers()` from `cipherSuites`. New suites must therefore be
registered into **`cipherSuites`** *and* `utlsSupportedCipherSuites`
order-independently, flagged `suiteDefaultOff`, and kept out of
`cipherSuitesPreferenceOrder*` so the default offered list and browser presets
are byte-identical. TLS 1.3 suites go into `cipherSuitesTLS13`.

## Rebase

Run `tools/rebase_utls.sh` to re-copy the upstream module at the version pinned
in `native/go.mod`, restore our new files, re-apply `patches/*.patch`, and
rebuild.
