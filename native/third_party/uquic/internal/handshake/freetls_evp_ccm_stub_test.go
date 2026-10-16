//go:build !freetls_libcrypto

package handshake

import "testing"

// The Go-only build must keep upstream's behaviour: TLS 1.3 CCM is not
// available, so asking for it panics rather than silently mis-keying a packet.
func TestFreetlsCCMUnavailableWithoutLibcrypto(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("getCipherSuite(0x1304) should panic without the libcrypto backend")
		}
	}()
	getCipherSuite(0x1304)
}
