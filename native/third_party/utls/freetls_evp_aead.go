//go:build freetls_libcrypto

package tls

import "crypto/cipher"

// FreetlsNewEVPCCMAEAD returns an AES-128-CCM AEAD backed by OpenSSL EVP, as a
// plain cipher.AEAD.
//
// The QUIC packet-protection layer (the uQUIC fork) lives outside this package
// and cannot reach the unexported evpAEAD, so it needs this constructor to make
// the TLS 1.3 CCM suites negotiable over QUIC. tagLen is 16 for CCM and 8 for
// CCM_8.
//
// This file is part of the freetls fork (new file; upstream is never edited).
func FreetlsNewEVPCCMAEAD(key []byte, tagLen int) (cipher.AEAD, error) {
	return newEVPAEAD("AES-128-CCM", key, tagLen, true), nil
}
