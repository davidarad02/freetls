//go:build freetls_libcrypto && freetls_static_openssl

package tls

// freetlsStaticOpenSSL marks a build that links libcrypto statically. The
// static link flags and symbol-hygiene flags (-Wl,-Bsymbolic,
// -Wl,--exclude-libs,ALL) are supplied by `make full` via CGO_LDFLAGS, since
// cgo's directive flag allowlist rejects them.
const freetlsStaticOpenSSL = true
