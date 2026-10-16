// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"
)

// RFC 5054 Appendix A, 2048-bit group (g = 2).
const rfc5054Group2048 = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
	"544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
	"AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
	"94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

func srpU16(b []byte) []byte {
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	return out
}

// TestSRPRoundTrip drives the client key agreement and a reference SRP-6a server
// and checks that both derive the same premaster secret.
func TestSRPRoundTrip(t *testing.T) {
	N, ok := new(big.Int).SetString(rfc5054Group2048, 16)
	if !ok {
		t.Fatal("bad group constant")
	}
	g := big.NewInt(2)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	user, pass := "alice", "password123"

	// Reference server: x, verifier v, ephemeral b, public B.
	inner := srpSHA1([]byte(user), []byte(":"), []byte(pass))
	x := new(big.Int).SetBytes(srpSHA1(salt, inner))
	v := new(big.Int).Exp(g, x, N)
	bBytes := make([]byte, 32)
	if _, err := rand.Read(bBytes); err != nil {
		t.Fatal(err)
	}
	b := new(big.Int).SetBytes(bBytes)
	n := (N.BitLen() + 7) / 8
	k := new(big.Int).SetBytes(srpSHA1(srpPad(N, n), srpPad(g, n)))
	gb := new(big.Int).Exp(g, b, N)
	kv := new(big.Int).Mul(k, v)
	kv.Mod(kv, N)
	B := new(big.Int).Add(gb, kv)
	B.Mod(B, N)

	// ServerKeyExchange: N (u16) || g (u16) || s (u8) || B (u16).
	raw := append(srpU16(N.Bytes()), srpU16(g.Bytes())...)
	raw = append(raw, byte(len(salt)))
	raw = append(raw, salt...)
	raw = append(raw, srpU16(B.Bytes())...)

	cfg := &Config{Rand: rand.Reader, SrpUsername: user, SrpPassword: pass}
	ka := srpKA(VersionTLS12).(*srpKeyAgreement)
	if err := ka.processServerKeyExchange(cfg, &clientHelloMsg{}, &serverHelloMsg{}, nil, &serverKeyExchangeMsg{key: raw}); err != nil {
		t.Fatalf("processServerKeyExchange: %v", err)
	}

	// Extract the client's public A from the ClientKeyExchange.
	ct := ka.ckx.ciphertext
	aLen := int(binary.BigEndian.Uint16(ct[:2]))
	if aLen != len(ct)-2 {
		t.Fatalf("bad CKE length: %d vs %d", aLen, len(ct)-2)
	}
	A := new(big.Int).SetBytes(ct[2:])

	// Reference server derives S = (A * v^u)^b mod N.
	u := new(big.Int).SetBytes(srpSHA1(srpPad(A, n), srpPad(B, n)))
	vu := new(big.Int).Exp(v, u, N)
	Avu := new(big.Int).Mul(A, vu)
	Avu.Mod(Avu, N)
	Sserver := new(big.Int).Exp(Avu, b, N)

	if !bytes.Equal(ka.preMasterSecret, Sserver.Bytes()) {
		t.Fatalf("SRP premaster mismatch:\n client %x\n server %x", ka.preMasterSecret, Sserver.Bytes())
	}
}

func TestSRPRejectsBadParams(t *testing.T) {
	small := new(big.Int).Lsh(big.NewInt(1), 512)
	raw := append(srpU16(small.Bytes()), srpU16([]byte{2})...)
	raw = append(raw, 1, 0x01)
	raw = append(raw, srpU16([]byte{3})...)
	cfg := &Config{Rand: rand.Reader, SrpUsername: "u", SrpPassword: "p"}
	ka := srpKA(VersionTLS12)
	if err := ka.processServerKeyExchange(cfg, &clientHelloMsg{}, &serverHelloMsg{}, nil, &serverKeyExchangeMsg{key: raw}); err == nil {
		t.Fatal("expected small SRP modulus to be rejected")
	}
}

func TestSRPRequiresCredentials(t *testing.T) {
	N, _ := new(big.Int).SetString(rfc5054Group2048, 16)
	g := big.NewInt(2)
	salt := []byte{1, 2, 3}
	B := big.NewInt(5)
	raw := append(srpU16(N.Bytes()), srpU16(g.Bytes())...)
	raw = append(raw, byte(len(salt)))
	raw = append(raw, salt...)
	raw = append(raw, srpU16(B.Bytes())...)
	ka := srpKA(VersionTLS12)
	if err := ka.processServerKeyExchange(&Config{Rand: rand.Reader}, &clientHelloMsg{}, &serverHelloMsg{}, nil, &serverKeyExchangeMsg{key: raw}); err == nil {
		t.Fatal("expected missing SRP credentials to be rejected")
	}
}

func TestSRPSuitesRegistered(t *testing.T) {
	for _, id := range []uint16{
		tlsSRP_SHA_WITH_AES_128_CBC_SHA,
		tlsSRP_SHA_RSA_WITH_AES_128_CBC_SHA,
		tlsSRP_SHA_DSS_WITH_AES_128_CBC_SHA,
		tlsSRP_SHA_WITH_AES_256_CBC_SHA,
		tlsSRP_SHA_RSA_WITH_AES_256_CBC_SHA,
		tlsSRP_SHA_DSS_WITH_AES_256_CBC_SHA,
	} {
		if cipherSuiteByID(id) == nil {
			t.Fatalf("SRP suite %#04x not registered", id)
		}
	}
}
