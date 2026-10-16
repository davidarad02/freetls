//go:build freetls_libcrypto

package tls

import "crypto"

// Cipher suite IDs backed by libcrypto (OpenSSL EVP), within the Route B P1
// scope (AEAD extras) plus the two TLS 1.3 CCM suites.
const (
	// ARIA-GCM (RFC 6209).
	tlsRSAWithARIA128GCM        uint16 = 0xc050
	tlsRSAWithARIA256GCM        uint16 = 0xc051
	tlsECDHEECDSAWithARIA128GCM uint16 = 0xc05c
	tlsECDHEECDSAWithARIA256GCM uint16 = 0xc05d
	tlsECDHERSAWithARIA128GCM   uint16 = 0xc060
	tlsECDHERSAWithARIA256GCM   uint16 = 0xc061

	// AES-CCM / AES-CCM_8 (RFC 6655). DHE and PSK variants are out of scope.
	tlsRSAWithAES128CCM         uint16 = 0xc09c
	tlsRSAWithAES256CCM         uint16 = 0xc09d
	tlsRSAWithAES128CCM8        uint16 = 0xc0a0
	tlsRSAWithAES256CCM8        uint16 = 0xc0a1
	tlsECDHEECDSAWithAES128CCM  uint16 = 0xc0ac
	tlsECDHEECDSAWithAES256CCM  uint16 = 0xc0ad
	tlsECDHEECDSAWithAES128CCM8 uint16 = 0xc0ae
	tlsECDHEECDSAWithAES256CCM8 uint16 = 0xc0af

	// TLS 1.3 CCM (RFC 8446).
	tlsAES128CCMSHA256  uint16 = 0x1304
	tlsAES128CCM8SHA256 uint16 = 0x1305

	// Camellia-CBC (RFC 5932). DHE/DSS/anon/PSK variants are out of scope.
	tlsRSAWithCAMELLIA128CBCSHA           uint16 = 0x0041
	tlsRSAWithCAMELLIA256CBCSHA           uint16 = 0x0084
	tlsRSAWithCAMELLIA128CBCSHA256        uint16 = 0x00ba
	tlsRSAWithCAMELLIA256CBCSHA256        uint16 = 0x00c0
	tlsECDHEECDSAWithCAMELLIA128CBCSHA256 uint16 = 0xc072
	tlsECDHEECDSAWithCAMELLIA256CBCSHA384 uint16 = 0xc073
	tlsECDHERSAWithCAMELLIA128CBCSHA256   uint16 = 0xc076
	tlsECDHERSAWithCAMELLIA256CBCSHA384   uint16 = 0xc077
)

// evpCipherSuites are the TLS 1.0-1.2 suites added by the libcrypto backend.
// They are appended to cipherSuites (so EnableWeakCiphers preserves them) and
// to utlsSupportedCipherSuites, but are NOT added to the preference-order
// lists, so the default offered list and browser presets are unchanged.
var evpCipherSuites = []*cipherSuite{
	// ARIA-GCM.
	{tlsRSAWithARIA128GCM, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsRSAWithARIA256GCM, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	{tlsECDHEECDSAWithARIA128GCM, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsECDHEECDSAWithARIA256GCM, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	{tlsECDHERSAWithARIA128GCM, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsECDHERSAWithARIA256GCM, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},

	// AES-CCM.
	{tlsRSAWithAES128CCM, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 16)},
	{tlsRSAWithAES256CCM, 32, 0, 4, rsaKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 16)},
	{tlsRSAWithAES128CCM8, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 8)},
	{tlsRSAWithAES256CCM8, 32, 0, 4, rsaKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 8)},
	{tlsECDHEECDSAWithAES128CCM, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 16)},
	{tlsECDHEECDSAWithAES256CCM, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 16)},
	{tlsECDHEECDSAWithAES128CCM8, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 8)},
	{tlsECDHEECDSAWithAES256CCM8, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 8)},

	// Camellia-CBC (RFC 5932). CBC chaining/MAC stay in Go.
	{tlsRSAWithCAMELLIA128CBCSHA, 16, 20, 16, rsaKA, 0, evpCBC("CAMELLIA-128-ECB"), macSHA1, nil},
	{tlsRSAWithCAMELLIA256CBCSHA, 32, 20, 16, rsaKA, 0, evpCBC("CAMELLIA-256-ECB"), macSHA1, nil},
	{tlsRSAWithCAMELLIA128CBCSHA256, 16, 32, 16, rsaKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsRSAWithCAMELLIA256CBCSHA256, 32, 32, 16, rsaKA, suiteTLS12, evpCBC("CAMELLIA-256-ECB"), macSHA256, nil},
	{tlsECDHEECDSAWithCAMELLIA128CBCSHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsECDHEECDSAWithCAMELLIA256CBCSHA384, 32, 48, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
	{tlsECDHERSAWithCAMELLIA128CBCSHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsECDHERSAWithCAMELLIA256CBCSHA384, 32, 48, 16, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
}

// evpTLS13CipherSuites are the TLS 1.3 suites added by the libcrypto backend.
var evpTLS13CipherSuites = []*cipherSuiteTLS13{
	{tlsAES128CCMSHA256, 16, evpTLS13CCM("AES-128-CCM", 16), crypto.SHA256},
	{tlsAES128CCM8SHA256, 16, evpTLS13CCM("AES-128-CCM", 8), crypto.SHA256},
}

// init registers the libcrypto suites. It is order-independent with respect to
// u_common.go's init(): appending to cipherSuites means u_common.go's
// utlsSupportedCipherSuites snapshot (taken from cipherSuites) includes them
// regardless of which init runs first, and appending directly to
// utlsSupportedCipherSuites covers the case where u_common.go ran first.
func init() {
	cipherSuites = append(cipherSuites, evpCipherSuites...)
	utlsSupportedCipherSuites = append(utlsSupportedCipherSuites, evpCipherSuites...)
	cipherSuitesTLS13 = append(cipherSuitesTLS13, evpTLS13CipherSuites...)
}