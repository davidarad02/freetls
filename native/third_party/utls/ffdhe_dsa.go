// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// DSA (DSS) signature verification for the DHE-DSS cipher suites. Go's
// crypto/tls dropped DSA support, so the freetls fork implements it here.

import (
	"crypto"
	"crypto/dsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// DSA signature schemes (RFC 5246 / RFC 5754). TLS 1.2 only supports SHA-1 and
// SHA-256 for DSA.
const (
	dsaWithSHA1   SignatureScheme = 0x0202
	dsaWithSHA256 SignatureScheme = 0x0402
)

// dsaTruncate returns the leftmost min(q bits, len(hashed)*8) bits of a digest,
// as required by FIPS 186 for DSA. Go's crypto/dsa does not do this itself, so a
// DSA key with a 224-bit q (common for 2048-bit DSA) would otherwise fail.
func dsaTruncate(hashed []byte, q *big.Int) []byte {
	qbits := q.BitLen()
	if qbits >= len(hashed)*8 {
		return hashed
	}
	n := (qbits + 7) / 8
	out := make([]byte, n)
	copy(out, hashed[:n])
	if rem := qbits % 8; rem != 0 {
		out[0] &= byte(0xff << (8 - rem))
	}
	return out
}

func verifyDSASignature(pub crypto.PublicKey, sigAlg SignatureScheme, signed, sig []byte) error {
	dsaPub, ok := pub.(*dsa.PublicKey)
	if !ok {
		return fmt.Errorf("tls: expected a DSA public key, got %T", pub)
	}
	var hashFunc crypto.Hash
	switch sigAlg {
	case dsaWithSHA1:
		hashFunc = crypto.SHA1
	case dsaWithSHA256:
		hashFunc = crypto.SHA256
	default:
		return fmt.Errorf("tls: unsupported DSA signature algorithm %#04x", uint16(sigAlg))
	}
	if !hashFunc.Available() {
		return fmt.Errorf("tls: hash function unavailable: %v", hashFunc)
	}
	h := hashFunc.New()
	h.Write(signed)
	digest := dsaTruncate(h.Sum(nil), dsaPub.Q)

	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return errors.New("tls: invalid DSA signature encoding")
	}
	if parsed.R == nil || parsed.S == nil {
		return errors.New("tls: invalid DSA signature")
	}
	if !dsa.Verify(dsaPub, digest, parsed.R, parsed.S) {
		return errors.New("tls: DSA verification failure")
	}
	return nil
}
