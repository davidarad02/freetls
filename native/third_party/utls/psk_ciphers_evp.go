//go:build freetls_libcrypto

// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// PSK suites backed by the libcrypto (OpenSSL EVP) bridge: ARIA-GCM, AES-CCM
// and Camellia-CBC. Built only with the freetls_libcrypto tag.

var pskEVPSuites = []*cipherSuite{
	// pure PSK
	{tlsPSK_WITH_ARIA_128_GCM_SHA256, 16, 0, 4, pskKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsPSK_WITH_ARIA_256_GCM_SHA384, 32, 0, 4, pskKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	{tlsPSK_WITH_AES_128_CCM, 16, 0, 4, pskKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 16)},
	{tlsPSK_WITH_AES_256_CCM, 32, 0, 4, pskKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 16)},
	{tlsPSK_WITH_AES_128_CCM_8, 16, 0, 4, pskKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 8)},
	{tlsPSK_WITH_AES_256_CCM_8, 32, 0, 4, pskKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 8)},
	{tlsPSK_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, pskKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsPSK_WITH_CAMELLIA_256_CBC_SHA384, 32, 48, 16, pskKA, suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
	// DHE-PSK
	{tlsDHE_PSK_WITH_ARIA_128_GCM_SHA256, 16, 0, 4, dhePSKKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsDHE_PSK_WITH_ARIA_256_GCM_SHA384, 32, 0, 4, dhePSKKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	{tlsDHE_PSK_WITH_AES_128_CCM, 16, 0, 4, dhePSKKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 16)},
	{tlsDHE_PSK_WITH_AES_256_CCM, 32, 0, 4, dhePSKKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 16)},
	{tlsPSK_DHE_WITH_AES_128_CCM_8, 16, 0, 4, dhePSKKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 8)},
	{tlsPSK_DHE_WITH_AES_256_CCM_8, 32, 0, 4, dhePSKKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 8)},
	{tlsDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, dhePSKKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384, 32, 48, 16, dhePSKKA, suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
	// ECDHE-PSK
	{tlsECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, ecdhePSKKA, suiteECDHE | suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384, 32, 48, 16, ecdhePSKKA, suiteECDHE | suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
	// RSA-PSK
	{tlsRSA_PSK_WITH_ARIA_128_GCM_SHA256, 16, 0, 4, rsaPSKKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsRSA_PSK_WITH_ARIA_256_GCM_SHA384, 32, 0, 4, rsaPSKKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	{tlsRSA_PSK_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, rsaPSKKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsRSA_PSK_WITH_CAMELLIA_256_CBC_SHA384, 32, 48, 16, rsaPSKKA, suiteTLS12 | suiteSHA384, evpCBC("CAMELLIA-256-ECB"), utlsMacSHA384, nil},
}

func init() {
	registerPSKSuites(pskEVPSuites)
}
