//go:build !freetls_libcrypto

package tls

import (
	"crypto/cipher"
	"errors"
)

// FreetlsNewEVPCCMAEAD is the Go-only build's stub: TLS 1.3 CCM exists only in
// the libcrypto backend, so callers get a clear error instead of a panic.
//
// This file is part of the freetls fork (new file; upstream is never edited).
func FreetlsNewEVPCCMAEAD(key []byte, tagLen int) (cipher.AEAD, error) {
	return nil, errors.New("freetls: TLS 1.3 CCM requires the libcrypto backend")
}
