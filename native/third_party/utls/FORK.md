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
| `ffdhe_key_agreement.go` | `dhKeyAgreement`: FFDHE (DHE) client key exchange *(P1)* |
| `ffdhe_dsa.go` | DSA (DSS) signature verification for DHE-DSS *(P1)* |
| `ffdhe_ciphers.go` | DHE-RSA/DHE-DSS suite registration (Go-native ciphers) *(P1)* |
| `ffdhe_ciphers_evp.go` | DHE suites backed by the EVP bridge (ARIA-GCM/AES-CCM/Camellia-CBC) *(P1)* |
| `ffdhe_freetls_test.go` | Go tests for the FFDHE key agreement *(P1)* |

`FORK.md` is also ours.

## Patches (upstream files)

A few behaviours cannot be added from a new file, so `patches/freetls.patch`
edits upstream files; `tools/rebase_utls.sh` re-applies it after each re-copy:

- `handshake_client.go`: allow `*dsa.PublicKey` server certificates (DHE-DSS);
  skip the Certificate message + `verifyServerCertificate` for anonymous (ADH)
  suites and gate them behind `Config.Anonymous`.
- `common.go`: add `Config.Anonymous`.

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
