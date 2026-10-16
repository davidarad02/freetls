// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"testing"
)

func pskTestConfig() *Config {
	return &Config{
		Rand:        rand.Reader,
		Psk:         bytes.Repeat([]byte{0xAB}, 16),
		PskIdentity: "freetls",
	}
}

func TestPSKPremasterPure(t *testing.T) {
	cfg := pskTestConfig()
	pms, err := pskPremaster(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// uint16(16) || 16 zero bytes || uint16(16) || psk
	want := make([]byte, 0, 4+16+16)
	want = append(want, 0x00, 0x10)
	want = append(want, make([]byte, 16)...)
	want = append(want, 0x00, 0x10)
	want = append(want, cfg.Psk...)
	if !bytes.Equal(pms, want) {
		t.Fatalf("pure PSK premaster mismatch:\n got %x\nwant %x", pms, want)
	}
}

func TestPSKPremasterOtherSecret(t *testing.T) {
	cfg := pskTestConfig()
	other := []byte{0x01, 0x02, 0x03}
	pms, err := pskPremaster(cfg, other)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x10}
	want = append(want, cfg.Psk...)
	if !bytes.Equal(pms, want) {
		t.Fatalf("PSK premaster mismatch:\n got %x\nwant %x", pms, want)
	}
}

func TestPSKPremasterRequiresKey(t *testing.T) {
	if _, err := pskPremaster(&Config{}, nil); err == nil {
		t.Fatal("expected error when Config.Psk is empty")
	}
}

func TestPSKSplitHint(t *testing.T) {
	raw := []byte{0x00, 0x03, 'a', 'b', 'c', 0xde, 0xad}
	hint, rest, err := splitPSKHint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(hint) != "abc" || !bytes.Equal(rest, []byte{0xde, 0xad}) {
		t.Fatalf("bad split: hint=%q rest=%x", hint, rest)
	}
	if _, _, err := splitPSKHint([]byte{0x00, 0x05, 'a'}); err == nil {
		t.Fatal("expected truncated hint to be rejected")
	}
}

func TestPSKPureClientKeyExchange(t *testing.T) {
	cfg := pskTestConfig()
	_, ckx, err := pskKA(VersionTLS12).generateClientKeyExchange(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ckx.ciphertext) < 2 {
		t.Fatal("short CKE")
	}
	n := int(binary.BigEndian.Uint16(ckx.ciphertext[:2]))
	if n != len(cfg.PskIdentity) || string(ckx.ciphertext[2:2+n]) != cfg.PskIdentity {
		t.Fatalf("bad CKE identity: %x", ckx.ciphertext)
	}
}

func TestPSKRSAClientKeyExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	cfg := pskTestConfig()
	pms, ckx, err := rsaPSKKA(VersionTLS12).generateClientKeyExchange(cfg, nil, cert)
	if err != nil {
		t.Fatal(err)
	}
	// CKE = uint16(idlen) || id || uint16(enclen) || enc
	ct := ckx.ciphertext
	idLen := int(binary.BigEndian.Uint16(ct[:2]))
	off := 2 + idLen
	encLen := int(binary.BigEndian.Uint16(ct[off : off+2]))
	off += 2
	enc := ct[off : off+encLen]
	other, err := rsa.DecryptPKCS1v15(rand.Reader, key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 48 {
		t.Fatalf("other_secret length = %d, want 48", len(other))
	}
	if other[0] != 0x03 || other[1] != 0x03 {
		t.Fatalf("other_secret version prefix = %x, want 0303", other[:2])
	}
	wantPms, _ := pskPremaster(cfg, other)
	if !bytes.Equal(pms, wantPms) {
		t.Fatalf("RSA-PSK premaster mismatch:\n got %x\nwant %x", pms, wantPms)
	}
}

func TestPSKSuitesRegistered(t *testing.T) {
	for _, id := range []uint16{
		tlsPSK_WITH_AES_128_GCM_SHA256,
		tlsPSK_WITH_AES_128_CBC_SHA,
		tlsPSK_WITH_CHACHA20_POLY1305,
		tlsDHE_PSK_WITH_AES_128_GCM_SHA256,
		tlsDHE_PSK_WITH_AES_128_CBC_SHA256,
		tlsECDHE_PSK_WITH_AES_128_CBC_SHA,
		tlsECDHE_PSK_WITH_CHACHA20_POLY1305,
		tlsRSA_PSK_WITH_AES_128_GCM_SHA256,
		tlsRSA_PSK_WITH_AES_128_CBC_SHA,
	} {
		if cipherSuiteByID(id) == nil {
			t.Fatalf("PSK suite %#04x not registered", id)
		}
	}
}
