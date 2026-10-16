// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestFFDHESharedSecret(t *testing.T) {
	p := big.NewInt(23)
	g := big.NewInt(5)
	xa, Ya, err := generateDHKey(rand.Reader, p, g)
	if err != nil {
		t.Fatal(err)
	}
	xb, Yb, err := generateDHKey(rand.Reader, p, g)
	if err != nil {
		t.Fatal(err)
	}
	za := new(big.Int).Exp(Yb, xa, p)
	zb := new(big.Int).Exp(Ya, xb, p)
	if za.Cmp(zb) != 0 {
		t.Fatalf("DH shared secret mismatch: %v != %v", za, zb)
	}
}

func TestFFDHEValidateDHParams(t *testing.T) {
	small := big.NewInt(0x10001) // 17-bit modulus
	if err := validateDHParams(small, big.NewInt(2), big.NewInt(3)); err == nil {
		t.Fatal("expected small modulus to be rejected")
	}
	p := new(big.Int).Lsh(big.NewInt(1), 2047) // 2048-bit modulus
	p.Add(p, big.NewInt(1))
	g := big.NewInt(2)
	ys := new(big.Int).Lsh(big.NewInt(1), 1000)
	if err := validateDHParams(p, g, ys); err != nil {
		t.Fatalf("unexpected rejection of valid params: %v", err)
	}
	if err := validateDHParams(p, big.NewInt(1), ys); err == nil {
		t.Fatal("expected bad generator to be rejected")
	}
	if err := validateDHParams(p, g, big.NewInt(1)); err == nil {
		t.Fatal("expected bad public value to be rejected")
	}
}

func TestFFDHEParseServerDHParams(t *testing.T) {
	// p=0x010203, g=0x02, Ys=0xdeadbeef
	raw := []byte{
		0x00, 0x03, 0x01, 0x02, 0x03,
		0x00, 0x01, 0x02,
		0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
	}
	p, g, ys, off, err := parseServerDHParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Int64() != 0x010203 || g.Int64() != 2 || ys.Int64() != 0xdeadbeef {
		t.Fatalf("bad parse: p=%v g=%v ys=%v", p, g, ys)
	}
	if off != len(raw) {
		t.Fatalf("bad offset: %d != %d", off, len(raw))
	}
}

func TestFFDHESuitesRegistered(t *testing.T) {
	// Go-native DHE suites are always registered.
	for _, id := range []uint16{
		tlsDHE_RSA_WITH_AES_128_GCM_SHA256,
		tlsDHE_RSA_WITH_AES_256_GCM_SHA384,
		tlsDHE_RSA_WITH_AES_128_CBC_SHA,
		tlsDHE_RSA_WITH_AES_128_CBC_SHA256,
		tlsDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tlsDHE_DSS_WITH_AES_128_GCM_SHA256,
		tlsDHE_DSS_WITH_AES_128_CBC_SHA,
	} {
		if cipherSuiteByID(id) == nil {
			t.Fatalf("DHE suite %#04x not registered", id)
		}
	}
}
