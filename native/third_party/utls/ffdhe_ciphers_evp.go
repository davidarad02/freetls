//go:build freetls_libcrypto

// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// DHE suites backed by the libcrypto (OpenSSL EVP) bridge: ARIA-GCM, AES-CCM
// and Camellia-CBC. Built only with the freetls_libcrypto tag.

var ffdheEVPSuites = []*cipherSuite{
	// DHE-RSA AES-CCM / CCM_8
	{tlsDHE_RSA_WITH_AES_128_CCM, 16, 0, 4, dhRSAKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 16)},
	{tlsDHE_RSA_WITH_AES_256_CCM, 32, 0, 4, dhRSAKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 16)},
	{tlsDHE_RSA_WITH_AES_128_CCM_8, 16, 0, 4, dhRSAKA, suiteTLS12, nil, nil, evpCCM12("AES-128-CCM", 8)},
	{tlsDHE_RSA_WITH_AES_256_CCM_8, 32, 0, 4, dhRSAKA, suiteTLS12, nil, nil, evpCCM12("AES-256-CCM", 8)},
	// DHE-RSA ARIA-GCM
	{tlsDHE_RSA_WITH_ARIA_128_GCM_SHA256, 16, 0, 4, dhRSAKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsDHE_RSA_WITH_ARIA_256_GCM_SHA384, 32, 0, 4, dhRSAKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	// DHE-DSS ARIA-GCM
	{tlsDHE_DSS_WITH_ARIA_128_GCM_SHA256, 16, 0, 4, dhDSSKA, suiteTLS12, nil, nil, evpGCM("ARIA-128-GCM")},
	{tlsDHE_DSS_WITH_ARIA_256_GCM_SHA384, 32, 0, 4, dhDSSKA, suiteTLS12 | suiteSHA384, nil, nil, evpGCM("ARIA-256-GCM")},
	// DHE-RSA Camellia-CBC
	{tlsDHE_RSA_WITH_CAMELLIA_128_CBC_SHA, 16, 20, 16, dhRSAKA, 0, evpCBC("CAMELLIA-128-ECB"), macSHA1, nil},
	{tlsDHE_RSA_WITH_CAMELLIA_256_CBC_SHA, 32, 20, 16, dhRSAKA, 0, evpCBC("CAMELLIA-256-ECB"), macSHA1, nil},
	{tlsDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, dhRSAKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256, 32, 32, 16, dhRSAKA, suiteTLS12, evpCBC("CAMELLIA-256-ECB"), macSHA256, nil},
	// DHE-DSS Camellia-CBC
	{tlsDHE_DSS_WITH_CAMELLIA_128_CBC_SHA, 16, 20, 16, dhDSSKA, 0, evpCBC("CAMELLIA-128-ECB"), macSHA1, nil},
	{tlsDHE_DSS_WITH_CAMELLIA_256_CBC_SHA, 32, 20, 16, dhDSSKA, 0, evpCBC("CAMELLIA-256-ECB"), macSHA1, nil},
	{tlsDHE_DSS_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, dhDSSKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsDHE_DSS_WITH_CAMELLIA_256_CBC_SHA256, 32, 32, 16, dhDSSKA, suiteTLS12, evpCBC("CAMELLIA-256-ECB"), macSHA256, nil},
	// Anonymous DH Camellia-CBC
	{tlsDH_anon_WITH_CAMELLIA_128_CBC_SHA, 16, 20, 16, dhAnonKA, 0, evpCBC("CAMELLIA-128-ECB"), macSHA1, nil},
	{tlsDH_anon_WITH_CAMELLIA_256_CBC_SHA, 32, 20, 16, dhAnonKA, 0, evpCBC("CAMELLIA-256-ECB"), macSHA1, nil},
	{tlsDH_anon_WITH_CAMELLIA_128_CBC_SHA256, 16, 32, 16, dhAnonKA, suiteTLS12, evpCBC("CAMELLIA-128-ECB"), macSHA256, nil},
	{tlsDH_anon_WITH_CAMELLIA_256_CBC_SHA256, 32, 32, 16, dhAnonKA, suiteTLS12, evpCBC("CAMELLIA-256-ECB"), macSHA256, nil},
}

func init() {
	registerFFDHESuites(ffdheEVPSuites)
}
