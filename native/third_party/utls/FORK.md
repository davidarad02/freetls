# freetls uTLS fork

This directory is a **full copy of the upstream `refraction-networking/utls`
module** at the version pinned in `native/go.mod`, vendored in-tree so freetls
can add cipher suites backed by OpenSSL `libcrypto` without patching upstream.

- Upstream module path: `github.com/refraction-networking/utls`
- `native/go.mod` maps it here with:
  `replace github.com/refraction-networking/utls => ./third_party/utls`

## What we add (new files only)

All freetls changes are **new files** in the `tls` package; upstream files are
never edited. This keeps the diff rebasable (see `tools/rebase_utls.sh`).

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

`FORK.md` is also ours.

## Registration rules (do not break these)

`utlsSupportedCipherSuites` is built in `u_common.go`'s `init()` and reassigned
by `EnableWeakCiphers()` from `cipherSuites`. New suites must therefore be
registered into **`cipherSuites`** *and* `utlsSupportedCipherSuites`
order-independently, flagged `suiteDefaultOff`, and kept out of
`cipherSuitesPreferenceOrder*` so the default offered list and browser presets
are byte-identical. TLS 1.3 suites go into `cipherSuitesTLS13`.

## Rebase

Run `tools/rebase_utls.sh` to re-copy the upstream module at the version pinned
in `native/go.mod`, restore our new files, and rebuild.
