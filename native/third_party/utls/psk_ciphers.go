// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// PSK cipher suites (RFC 4279/5487/5489). Go-native ciphers live here; the
// EVP-backed ones (ARIA-GCM, AES-CCM, Camellia-CBC) live in
// psk_ciphers_evp.go behind the freetls_libcrypto build tag.

const (
	// pure PSK
	tlsPSK_WITH_AES_128_GCM_SHA256 uint16 = 0x00a8
	tlsPSK_WITH_AES_256_GCM_SHA384 uint16 = 0x00a9
	tlsPSK_WITH_AES_128_CBC_SHA    uint16 = 0x008c
	tlsPSK_WITH_AES_256_CBC_SHA    uint16 = 0x008d
	tlsPSK_WITH_AES_128_CBC_SHA256 uint16 = 0x00ae
	tlsPSK_WITH_AES_256_CBC_SHA384 uint16 = 0x00af
	tlsPSK_WITH_CHACHA20_POLY1305  uint16 = 0xccab
	// DHE-PSK
	tlsDHE_PSK_WITH_AES_128_GCM_SHA256 uint16 = 0x00aa
	tlsDHE_PSK_WITH_AES_256_GCM_SHA384 uint16 = 0x00ab
	tlsDHE_PSK_WITH_AES_128_CBC_SHA    uint16 = 0x0090
	tlsDHE_PSK_WITH_AES_256_CBC_SHA    uint16 = 0x0091
	tlsDHE_PSK_WITH_AES_128_CBC_SHA256 uint16 = 0x00b2
	tlsDHE_PSK_WITH_AES_256_CBC_SHA384 uint16 = 0x00b3
	tlsDHE_PSK_WITH_CHACHA20_POLY1305  uint16 = 0xccad
	// ECDHE-PSK
	tlsECDHE_PSK_WITH_AES_128_CBC_SHA    uint16 = 0xc035
	tlsECDHE_PSK_WITH_AES_256_CBC_SHA    uint16 = 0xc036
	tlsECDHE_PSK_WITH_AES_128_CBC_SHA256 uint16 = 0xc037
	tlsECDHE_PSK_WITH_AES_256_CBC_SHA384 uint16 = 0xc038
	tlsECDHE_PSK_WITH_CHACHA20_POLY1305  uint16 = 0xccac
	// RSA-PSK
	tlsRSA_PSK_WITH_AES_128_GCM_SHA256 uint16 = 0x00ac
	tlsRSA_PSK_WITH_AES_256_GCM_SHA384 uint16 = 0x00ad
	tlsRSA_PSK_WITH_AES_128_CBC_SHA    uint16 = 0x0094
	tlsRSA_PSK_WITH_AES_256_CBC_SHA    uint16 = 0x0095
	tlsRSA_PSK_WITH_AES_128_CBC_SHA256 uint16 = 0x00b6
	tlsRSA_PSK_WITH_AES_256_CBC_SHA384 uint16 = 0x00b7
	tlsRSA_PSK_WITH_CHACHA20_POLY1305  uint16 = 0xccae

	// EVP-backed (freetls_libcrypto).
	tlsPSK_WITH_ARIA_128_GCM_SHA256     uint16 = 0xc06a
	tlsPSK_WITH_ARIA_256_GCM_SHA384     uint16 = 0xc06b
	tlsPSK_WITH_AES_128_CCM             uint16 = 0xc0a4
	tlsPSK_WITH_AES_256_CCM             uint16 = 0xc0a5
	tlsPSK_WITH_AES_128_CCM_8           uint16 = 0xc0a8
	tlsPSK_WITH_AES_256_CCM_8           uint16 = 0xc0a9
	tlsPSK_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0xc094
	tlsPSK_WITH_CAMELLIA_256_CBC_SHA384 uint16 = 0xc095

	tlsDHE_PSK_WITH_ARIA_128_GCM_SHA256     uint16 = 0xc06c
	tlsDHE_PSK_WITH_ARIA_256_GCM_SHA384     uint16 = 0xc06d
	tlsDHE_PSK_WITH_AES_128_CCM             uint16 = 0xc0a6
	tlsDHE_PSK_WITH_AES_256_CCM             uint16 = 0xc0a7
	tlsPSK_DHE_WITH_AES_128_CCM_8           uint16 = 0xc0aa
	tlsPSK_DHE_WITH_AES_256_CCM_8           uint16 = 0xc0ab
	tlsDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0xc096
	tlsDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 uint16 = 0xc097

	tlsECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0xc09a
	tlsECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 uint16 = 0xc09b

	tlsRSA_PSK_WITH_ARIA_128_GCM_SHA256     uint16 = 0xc06e
	tlsRSA_PSK_WITH_ARIA_256_GCM_SHA384     uint16 = 0xc06f
	tlsRSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 uint16 = 0xc098
	tlsRSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 uint16 = 0xc099
)

var pskGoSuites = []*cipherSuite{
	// pure PSK
	{tlsPSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsPSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsPSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, 0, cipherAES, macSHA1, nil},
	{tlsPSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, 0, cipherAES, macSHA1, nil},
	{tlsPSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsPSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, pskKA, suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	{tlsPSK_WITH_CHACHA20_POLY1305, 32, 0, 12, pskKA, suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	// DHE-PSK
	{tlsDHE_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, dhePSKKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsDHE_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, dhePSKKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsDHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, dhePSKKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, dhePSKKA, 0, cipherAES, macSHA1, nil},
	{tlsDHE_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, dhePSKKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsDHE_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, dhePSKKA, suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	{tlsDHE_PSK_WITH_CHACHA20_POLY1305, 32, 0, 12, dhePSKKA, suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	// ECDHE-PSK
	{tlsECDHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdhePSKKA, suiteECDHE, cipherAES, macSHA1, nil},
	{tlsECDHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdhePSKKA, suiteECDHE, cipherAES, macSHA1, nil},
	{tlsECDHE_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdhePSKKA, suiteECDHE | suiteTLS12, cipherAES, macSHA256, nil},
	{tlsECDHE_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdhePSKKA, suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	{tlsECDHE_PSK_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdhePSKKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	// RSA-PSK
	{tlsRSA_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaPSKKA, suiteTLS12, nil, nil, aeadAESGCM},
	{tlsRSA_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaPSKKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	{tlsRSA_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaPSKKA, 0, cipherAES, macSHA1, nil},
	{tlsRSA_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaPSKKA, 0, cipherAES, macSHA1, nil},
	{tlsRSA_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaPSKKA, suiteTLS12, cipherAES, macSHA256, nil},
	{tlsRSA_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, rsaPSKKA, suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	{tlsRSA_PSK_WITH_CHACHA20_POLY1305, 32, 0, 12, rsaPSKKA, suiteTLS12, nil, nil, aeadChaCha20Poly1305},
}

func registerPSKSuites(suites []*cipherSuite) {
	cipherSuites = append(cipherSuites, suites...)
	utlsSupportedCipherSuites = append(utlsSupportedCipherSuites, suites...)
}

func init() {
	registerPSKSuites(pskGoSuites)
}
