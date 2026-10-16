//go:build !freetls_libcrypto

package handshake

// Go-only build: TLS 1.3 CCM exists only in the libcrypto backend, so the
// upstream default arms keep panicking exactly as before.

func freetlsExtraCipherSuite(id uint16) (cipherSuite, bool) {
	return cipherSuite{}, false
}

func freetlsExtraHeaderProtector(
	suite cipherSuite, trafficSecret []byte, isLongHeader bool, hkdfLabel string,
) (headerProtector, bool) {
	return nil, false
}
