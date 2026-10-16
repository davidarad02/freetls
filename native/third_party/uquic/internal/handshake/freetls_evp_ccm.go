//go:build freetls_libcrypto

package handshake

import (
	"crypto"

	tls "github.com/refraction-networking/utls"
)

// TLS 1.3 CCM suites, which Go's crypto/tls does not implement. The freetls
// libcrypto backend adds them to the handshake via OpenSSL EVP; these IDs are
// what the packet-protection layer must be able to key for the QUIC handshake
// to complete on such a suite.
const (
	freetlsTLS13AES128CCM  uint16 = 0x1304
	freetlsTLS13AES128CCM8 uint16 = 0x1305
)

// freetlsExtraCipherSuite is consulted from getCipherSuite's default arm, so the
// Go-only build (the stub file) keeps upstream's panic unchanged.
func freetlsExtraCipherSuite(id uint16) (cipherSuite, bool) {
	switch id {
	case freetlsTLS13AES128CCM:
		return cipherSuite{ID: id, Hash: crypto.SHA256, KeyLen: 16, AEAD: freetlsCCMAEAD(16)}, true
	case freetlsTLS13AES128CCM8:
		return cipherSuite{ID: id, Hash: crypto.SHA256, KeyLen: 16, AEAD: freetlsCCMAEAD(8)}, true
	default:
		return cipherSuite{}, false
	}
}

func freetlsCCMAEAD(tagLen int) func(key, nonceMask []byte) *xorNonceAEAD {
	return func(key, nonceMask []byte) *xorNonceAEAD {
		if len(nonceMask) != aeadNonceLength {
			panic("tls: internal error: wrong nonce length")
		}
		aead, err := tls.FreetlsNewEVPCCMAEAD(key, tagLen)
		if err != nil {
			panic(err)
		}
		ret := &xorNonceAEAD{aead: aead}
		copy(ret.nonceMask[:], nonceMask)
		return ret
	}
}

// freetlsExtraHeaderProtector routes the CCM suites to the AES header protector.
// RFC 9001 §5.4.1 header protection is AES-ECB for every AES-based suite,
// independent of the packet AEAD, so no EVP bridge is needed here.
func freetlsExtraHeaderProtector(
	suite cipherSuite, trafficSecret []byte, isLongHeader bool, hkdfLabel string,
) (headerProtector, bool) {
	switch suite.ID {
	case freetlsTLS13AES128CCM, freetlsTLS13AES128CCM8:
		return newAESHeaderProtector(suite, trafficSecret, isLongHeader, hkdfLabel), true
	default:
		return nil, false
	}
}
