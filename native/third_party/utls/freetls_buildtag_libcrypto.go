//go:build freetls_libcrypto

package tls

// freetlsLibcrypto reports whether this build of the engine includes the
// libcrypto (OpenSSL EVP) backend that widens the completable cipher-suite set.
// It is true when the engine is built with `-tags freetls_libcrypto`.
const freetlsLibcrypto = true
