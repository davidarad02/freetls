//go:build freetls_libcrypto

package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func evpRandBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// EVP GCM must produce byte-identical output to Go's AES-GCM.
func TestEVPGCMMatchesGoAESGCM(t *testing.T) {
	for i := 0; i < 24; i++ {
		key := evpRandBytes(16)
		nonce := evpRandBytes(12)
		aad := evpRandBytes(i)
		pt := evpRandBytes(i * 5)
		evp := newEVPAEAD("AES-128-GCM", key, 16, false)
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		want := gcm.Seal(nil, nonce, pt, aad)
		got := evp.Seal(nil, nonce, pt, aad)
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: EVP GCM output != Go GCM", i)
		}
		out, err := evp.Open(nil, nonce, got, aad)
		if err != nil || !bytes.Equal(out, pt) {
			t.Fatalf("case %d: EVP GCM open failed: %v", i, err)
		}
	}
}

// The TLS 1.2 prefix-nonce framing around EVP GCM must match the native
// aeadAESGCM (prefixNonceAEAD).
func TestEVPPrefixFramingMatchesNative(t *testing.T) {
	key := evpRandBytes(16)
	prefix := evpRandBytes(4)
	ours := evpGCM("AES-128-GCM")(key, prefix)
	ref := aeadAESGCM(key, prefix)
	for i := 0; i < 16; i++ {
		nonce := evpRandBytes(8)
		aad := evpRandBytes(5)
		pt := evpRandBytes(17)
		if !bytes.Equal(ours.Seal(nil, nonce, pt, aad), ref.Seal(nil, nonce, pt, aad)) {
			t.Fatalf("case %d: prefix framing mismatch", i)
		}
	}
}

// The TLS 1.3 xor-nonce framing around EVP GCM must match the native
// aeadAESGCMTLS13 (xorNonceAEAD).
func TestEVPXorFramingMatchesNative(t *testing.T) {
	key := evpRandBytes(16)
	mask := evpRandBytes(12)
	ours := &xorNonceAEAD{aead: newEVPAEAD("AES-128-GCM", key, 16, false)}
	copy(ours.nonceMask[:], mask)
	ref := aeadAESGCMTLS13(key, mask)
	for i := 0; i < 16; i++ {
		nonce := evpRandBytes(8)
		aad := evpRandBytes(5)
		pt := evpRandBytes(17)
		if !bytes.Equal(ours.Seal(nil, nonce, pt, aad), ref.Seal(nil, nonce, pt, aad)) {
			t.Fatalf("case %d: xor framing mismatch", i)
		}
	}
}

func TestEVPCCMRoundTrip(t *testing.T) {
	for _, tagLen := range []int{16, 8} {
		for _, tc := range []struct {
			name   string
			keyLen int
		}{
			{"AES-128-CCM", 16},
			{"AES-256-CCM", 32},
			{"ARIA-128-CCM", 16},
		} {
			key := evpRandBytes(tc.keyLen)
			nonce := evpRandBytes(12)
			aad := evpRandBytes(9)
			pt := evpRandBytes(21)
			a := newEVPAEAD(tc.name, key, tagLen, true)
			ct := a.Seal(nil, nonce, pt, aad)
			if len(ct) != len(pt)+tagLen {
				t.Fatalf("%s tag=%d: bad ciphertext length %d", tc.name, tagLen, len(ct))
			}
			out, err := a.Open(nil, nonce, ct, aad)
			if err != nil || !bytes.Equal(out, pt) {
				t.Fatalf("%s tag=%d: open failed: %v", tc.name, tagLen, err)
			}
			ct[0] ^= 1
			if _, err := a.Open(nil, nonce, ct, aad); err == nil {
				t.Fatalf("%s tag=%d: tampered ciphertext accepted", tc.name, tagLen)
			}
		}
	}
}

func TestEVPARIAGCMRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyLen int
	}{{"ARIA-128-GCM", 16}, {"ARIA-256-GCM", 32}} {
		key := evpRandBytes(tc.keyLen)
		nonce := evpRandBytes(12)
		aad := evpRandBytes(4)
		pt := evpRandBytes(40)
		a := newEVPAEAD(tc.name, key, 16, false)
		ct := a.Seal(nil, nonce, pt, aad)
		out, err := a.Open(nil, nonce, ct, aad)
		if err != nil || !bytes.Equal(out, pt) {
			t.Fatalf("%s: round trip failed: %v", tc.name, err)
		}
	}
}

func TestEVPBlockCBCRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyLen int
	}{{"CAMELLIA-128-ECB", 16}, {"CAMELLIA-256-ECB", 32}, {"ARIA-128-ECB", 16}} {
		key := evpRandBytes(tc.keyLen)
		iv := evpRandBytes(16)
		pt := evpRandBytes(64)
		enc := cipher.NewCBCEncrypter(newEVPBlock(tc.name, key), iv)
		ct := make([]byte, len(pt))
		enc.CryptBlocks(ct, pt)
		dec := cipher.NewCBCDecrypter(newEVPBlock(tc.name, key), iv)
		out := make([]byte, len(ct))
		dec.CryptBlocks(out, ct)
		if !bytes.Equal(out, pt) {
			t.Fatalf("%s: CBC round trip failed", tc.name)
		}
	}
}

func TestEVPSuitesRegistered(t *testing.T) {
	tls12 := []uint16{0xc050, 0xc051, 0xc05c, 0xc05d, 0xc060, 0xc061,
		0xc09c, 0xc09d, 0xc0a0, 0xc0a1, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
		0x0041, 0x0084, 0x00ba, 0x00c0, 0xc072, 0xc073, 0xc076, 0xc077}
	for _, id := range tls12 {
		if cipherSuiteByID(id) == nil {
			t.Fatalf("TLS 1.2 suite %#04x not registered", id)
		}
	}
	for _, id := range []uint16{0x1304, 0x1305} {
		if cipherSuiteTLS13ByID(id) == nil {
			t.Fatalf("TLS 1.3 suite %#04x not registered", id)
		}
	}
}
