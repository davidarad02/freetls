//go:build freetls_libcrypto && !freetls_static_openssl

package tls

// #cgo pkg-config: libcrypto
import "C"
