//go:build !freetls_libcrypto

package tls

// freetlsLibcrypto reports whether this build of the engine includes the
// libcrypto (OpenSSL EVP) backend that widens the completable cipher-suite set.
// It is false in the default, Go-only build.
const freetlsLibcrypto = false
