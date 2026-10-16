// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// SRP cipher suites (RFC 5054). Only the AES-128/256 CBC-SHA1 variants are
// registered; the 3DES ones are obsolete. Ciphers are Go-native.

const (
	tlsSRP_SHA_WITH_AES_128_CBC_SHA     uint16 = 0xc01d
	tlsSRP_SHA_RSA_WITH_AES_128_CBC_SHA uint16 = 0xc01e
	tlsSRP_SHA_DSS_WITH_AES_128_CBC_SHA uint16 = 0xc01f
	tlsSRP_SHA_WITH_AES_256_CBC_SHA     uint16 = 0xc020
	tlsSRP_SHA_RSA_WITH_AES_256_CBC_SHA uint16 = 0xc021
	tlsSRP_SHA_DSS_WITH_AES_256_CBC_SHA uint16 = 0xc022
)

var srpSuites = []*cipherSuite{
	{tlsSRP_SHA_WITH_AES_128_CBC_SHA, 16, 20, 16, srpKA, 0, cipherAES, macSHA1, nil},
	{tlsSRP_SHA_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, srpRSAKA, 0, cipherAES, macSHA1, nil},
	{tlsSRP_SHA_DSS_WITH_AES_128_CBC_SHA, 16, 20, 16, srpDSSKA, 0, cipherAES, macSHA1, nil},
	{tlsSRP_SHA_WITH_AES_256_CBC_SHA, 32, 20, 16, srpKA, 0, cipherAES, macSHA1, nil},
	{tlsSRP_SHA_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, srpRSAKA, 0, cipherAES, macSHA1, nil},
	{tlsSRP_SHA_DSS_WITH_AES_256_CBC_SHA, 32, 20, 16, srpDSSKA, 0, cipherAES, macSHA1, nil},
}

func init() {
	registerPSKSuites(srpSuites)
}
