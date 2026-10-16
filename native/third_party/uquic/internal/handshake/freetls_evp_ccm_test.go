//go:build freetls_libcrypto

package handshake

import (
	"bytes"
	"testing"

	"github.com/refraction-networking/uquic/internal/protocol"
)

func TestFreetlsCCMCipherSuiteRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		id     uint16
		tagLen int
	}{
		{"CCM", freetlsTLS13AES128CCM, 16},
		{"CCM_8", freetlsTLS13AES128CCM8, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := getCipherSuite(tc.id)
			if cs.ID != tc.id {
				t.Fatalf("id = %#x, want %#x", cs.ID, tc.id)
			}
			if cs.KeyLen != 16 {
				t.Fatalf("key len = %d, want 16", cs.KeyLen)
			}
			aead := cs.AEAD(bytes.Repeat([]byte{0x2a}, cs.KeyLen), make([]byte, aeadNonceLength))
			if got := aead.Overhead(); got != tc.tagLen {
				t.Fatalf("overhead = %d, want %d", got, tc.tagLen)
			}

			nonce := []byte{0, 0, 0, 0, 0, 0, 0, 1}
			plaintext := []byte("freetls quic ccm round trip")
			aad := []byte("packet header")
			sealed := aead.Seal(nil, nonce, plaintext, aad)
			if len(sealed) != len(plaintext)+tc.tagLen {
				t.Fatalf("sealed len = %d, want %d", len(sealed), len(plaintext)+tc.tagLen)
			}
			opened, err := aead.Open(nil, nonce, sealed, aad)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("round trip mismatch: %q != %q", opened, plaintext)
			}
			if _, err := aead.Open(nil, nonce, sealed, []byte("other header")); err == nil {
				t.Fatal("open with wrong AAD should fail")
			}
		})
	}
}

func TestFreetlsCCMHeaderProtection(t *testing.T) {
	cs := getCipherSuite(freetlsTLS13AES128CCM)
	hp := newHeaderProtector(cs, bytes.Repeat([]byte{0x11}, 32), true, protocol.Version1)

	sample := bytes.Repeat([]byte{0x5a}, 16)
	first := byte(0xc3)
	original := first
	hdr := []byte{0x00, 0x00, 0x00, 0x01}

	hp.EncryptHeader(sample, &first, hdr)
	if first == original {
		t.Fatal("encrypt did not mask the first byte")
	}
	hp.DecryptHeader(sample, &first, hdr)
	if first != original {
		t.Fatalf("decrypt did not restore the first byte: %#x, want %#x", first, original)
	}
}
