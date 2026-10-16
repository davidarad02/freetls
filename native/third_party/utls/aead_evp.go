//go:build freetls_libcrypto

package tls

// evpGCM returns an aead constructor for a TLS 1.2 GCM suite backed by the
// named OpenSSL EVP cipher (e.g. "ARIA-128-GCM"). The 16-byte tag and the
// 4-byte fixed nonce prefix match RFC 5288 / Go's prefixNonceAEAD.
func evpGCM(name string) func(key, noncePrefix []byte) aead {
	return func(key, noncePrefix []byte) aead {
		if len(noncePrefix) != noncePrefixLength {
			panic("tls: internal error: wrong nonce length")
		}
		ret := &prefixNonceAEAD{aead: newEVPAEAD(name, key, 16, false)}
		copy(ret.nonce[:], noncePrefix)
		return ret
	}
}

// evpCCM12 returns an aead constructor for a TLS 1.2 CCM/CCM_8 suite
// (RFC 6655). tagLen is 16 for CCM and 8 for CCM_8.
func evpCCM12(name string, tagLen int) func(key, noncePrefix []byte) aead {
	return func(key, noncePrefix []byte) aead {
		if len(noncePrefix) != noncePrefixLength {
			panic("tls: internal error: wrong nonce length")
		}
		ret := &prefixNonceAEAD{aead: newEVPAEAD(name, key, tagLen, true)}
		copy(ret.nonce[:], noncePrefix)
		return ret
	}
}

// evpTLS13CCM returns an aead constructor for a TLS 1.3 CCM/CCM_8 suite
// (RFC 8446). The nonce is the static IV XORed with the record sequence number,
// matching Go's xorNonceAEAD.
func evpTLS13CCM(name string, tagLen int) func(key, nonceMask []byte) aead {
	return func(key, nonceMask []byte) aead {
		if len(nonceMask) != aeadNonceLength {
			panic("tls: internal error: wrong nonce length")
		}
		ret := &xorNonceAEAD{aead: newEVPAEAD(name, key, tagLen, true)}
		copy(ret.nonceMask[:], nonceMask)
		return ret
	}
}
