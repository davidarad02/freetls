// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// DHE (FFDHE) cipher suites. The Go-native ones live here (always built); the
// EVP-backed ones (ARIA-GCM, AES-CCM, Camellia-CBC) live in
// ffdhe_ciphers_evp.go behind the freetls_libcrypto build tag.

// DHE-RSA / DHE-DSS suite IDs (IANA).
const (
	tlsDHE_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0x009e
	tlsDHE_RSA_WITH_AES_256_GCM_SHA384 uint16 = 0x009f
	tlsDHE_DSS_WITH_AES_128_GCM_SHA256 uint16 = 0x00a2
	tlsDHE_DSS_WITH_AES_256_GCM_SHA384 uint16 = 0x00a3

	tlsDHE_RSA_WITH_AES_128_CBC_SHA    uint16 = 0x0033
	tlsDHE_RSA_WITH_AES_256_CBC_SHA    uint16 = 0x0039
	tlsDHE_DSS_WITH_AES_128_CBC_SHA    uint16 = 0x0032
	tlsDHE_DSS_WITH_AES_256_CBC_SHA    uint16 = 0x0038
	tlsDHE_RSA_WITH_AES_128_CBC_SHA256 uint16 = 0x0067
	tlsDHE_RSA_WITH_AES_256_CBC_SHA256 uint16 = 0x006b
	tlsDHE_DSS_WITH_AES_128_CBC_SHA256 uint16 = 0x0040
	tlsDHE_DSS_WITH_AES_256_CBC_SHA256 uint16 = 0x006a

	tlsDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xccaa

	// EVP-backed (freetls_libcrypto).
	tlsDHE_RSA_WITH_AES_128_CCM   uint16 = 0xc09e
	tlsDHE_RSA_WITH_AES_256_CCM   uint16 = 0xc09f
	tlsDHE_RSA_WITH_AES_128_CCM_8 uint16 = 0xc0a2
	tlsDHE_RSA_WITH_AES_256_CCM_8 uint16 = 0xc0a3

	tlsDHE_RSA_WITH_ARIA_128_GCM_SHA256 uint16 = 0xc052
	tlsDHE_RSA_WITH_ARIA_256_GCM_SHA384 uint16 = 0xc053
	tlsDHE_DSS_WITH_ARIA_128_GCM_SHA256 uint16 = 0xc056
	tlsDHE_DSS_WITH_ARIA_256_GCM_SHA384 uint16 = 0xc057

	tlsDHE_RSA_WITH_CAMELLIA_128_CBC_SHA    uint16 = 0x0045
	tlsDHE_RSA_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0088
	tlsDHE_DSS_WITH_CAMELLIA_128_CBC_SHA    uint16 = 0x0044
	tlsDHE_DSS_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0087
	tlsDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00be
	tlsDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00c4
	tlsDHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00bd
	tlsDHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00c3

	// Anonymous DH (ADH).
	tlsDH_anon_WITH_AES_128_GCM_SHA256 uint16 = 0x00a6
	tlsDH_anon_WITH_AES_256_GCM_SHA384 uint16 = 0x00a7
	tlsDH_anon_WITH_AES_128_CBC_SHA    uint16 = 0x0034
	tlsDH_anon_WITH_AES_256_CBC_SHA    uint16 = 0x003a
	tlsDH_anon_WITH_AES_128_CBC_SHA256 uint16 = 0x006c
	tlsDH_anon_WITH_AES_256_CBC_SHA256 uint16 = 0x006d

	tlsDH_anon_WITH_CAMELLIA_128_CBC_SHA    uint16 = 0x0046
	tlsDH_anon_WITH_CAMELLIA_256_CBC_SHA    uint16 = 0x0089
	tlsDH_anon_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0x00bf
	tlsDH_anon_WITH_CAMELLIA_256_CBC_SHA256 uint16 = 0x00c5
)

// ffdheGoSuites are the DHE suites using Go-native symmetric ciphers.
var ffdheGoSuites = []*cipherSuite{
	// DHE-RSA
	{tlsDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, dhRSAKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, dhRSAKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, dhRSAKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, dhRSAKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, dhRSAKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsDHE_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, dhRSAKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, dhRSAKA, suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	// DHE-DSS
	{tlsDHE_DSS_WITH_AES_128_GCM_SHA256, 16, 0, 4, dhDSSKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsDHE_DSS_WITH_AES_256_GCM_SHA384, 32, 0, 4, dhDSSKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsDHE_DSS_WITH_AES_128_CBC_SHA, 16, 20, 16, dhDSSKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_DSS_WITH_AES_256_CBC_SHA, 32, 20, 16, dhDSSKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_DSS_WITH_AES_128_CBC_SHA256, 16, 32, 16, dhDSSKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsDHE_DSS_WITH_AES_256_CBC_SHA256, 32, 32, 16, dhDSSKA, suiteTLS12, cipherAES, macSHA256, nil},
	// Anonymous DH
	{tlsDH_anon_WITH_AES_128_GCM_SHA256, 16, 0, 4, dhAnonKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsDH_anon_WITH_AES_256_GCM_SHA384, 32, 0, 4, dhAnonKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsDH_anon_WITH_AES_128_CBC_SHA, 16, 20, 16, dhAnonKA, 0, cipherAES, macSHA1, nil},
	{tlsDH_anon_WITH_AES_256_CBC_SHA, 32, 20, 16, dhAnonKA, 0, cipherAES, macSHA1, nil},
	{tlsDH_anon_WITH_AES_128_CBC_SHA256, 16, 32, 16, dhAnonKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsDH_anon_WITH_AES_256_CBC_SHA256, 32, 32, 16, dhAnonKA, suiteTLS12, cipherAES, macSHA256, nil},
}

// registerFFDHESuites appends suites to the canonical list and the supported
// list, order-independently (see cipher_evp_register.go for the rationale).
func registerFFDHESuites(suites []*cipherSuite) {
	cipherSuites = append(cipherSuites, suites...)
	utlsSupportedCipherSuites = append(utlsSupportedCipherSuites, suites...)
}

func init() {
	registerFFDHESuites(ffdheGoSuites)
}
