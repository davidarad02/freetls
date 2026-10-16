//go:build freetls_libcrypto

package tls

/*
#cgo CFLAGS: -Wno-deprecated-declarations

#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/cipher"
	"fmt"
	"unsafe"
)

// evpBlock implements cipher.Block using an OpenSSL EVP block cipher in ECB
// mode with padding disabled. It backs the P2 CBC cipher suites: the CBC
// chaining, MAC and TLS record framing stay in Go (reusing Go's cipher.CBC and
// crypto/tls record logic), exactly as for the native AES-CBC suites.
type evpBlock struct {
	cipher *C.EVP_CIPHER
	name   string
	key    []byte
}

func newEVPBlock(name string, key []byte) *evpBlock {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	c := C.EVP_get_cipherbyname(cName)
	if c == nil {
		panic(fmt.Sprintf("freetls: unknown EVP block cipher %q", name))
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &evpBlock{cipher: c, name: name, key: k}
}

func (b *evpBlock) BlockSize() int { return 16 }

func (b *evpBlock) Encrypt(dst, src []byte) { b.crypt(true, dst, src) }
func (b *evpBlock) Decrypt(dst, src []byte) { b.crypt(false, dst, src) }

func (b *evpBlock) crypt(enc bool, dst, src []byte) {
	const bs = 16
	if len(src) < bs || len(dst) < bs {
		panic("freetls: EVP block input smaller than block size")
	}

	evpClearErrors()
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		panic("freetls: EVP_CIPHER_CTX_new failed")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	var ok C.int
	if enc {
		ok = C.EVP_EncryptInit_ex(ctx, b.cipher, nil, evpBytes(b.key), nil)
	} else {
		ok = C.EVP_DecryptInit_ex(ctx, b.cipher, nil, evpBytes(b.key), nil)
	}
	if ok != 1 {
		panic(fmt.Sprintf("freetls: EVP %s init failed: %v", b.name, evpError("init")))
	}
	C.EVP_CIPHER_CTX_set_padding(ctx, 0)

	// Encrypt/decrypt into a scratch buffer so in-place (dst == src) calls are
	// safe regardless of EVP aliasing rules.
	tmp := make([]byte, bs)
	var outl C.int
	if enc {
		if C.EVP_EncryptUpdate(ctx, evpBytes(tmp), &outl, evpBytes(src), bs) != 1 || int(outl) != bs {
			panic(fmt.Sprintf("freetls: EVP %s encrypt failed: %v", b.name, evpError("update")))
		}
	} else {
		if C.EVP_DecryptUpdate(ctx, evpBytes(tmp), &outl, evpBytes(src), bs) != 1 || int(outl) != bs {
			panic(fmt.Sprintf("freetls: EVP %s decrypt failed: %v", b.name, evpError("update")))
		}
	}
	copy(dst, tmp)
}

// evpCBC returns a cipherSuite.cipher constructor for a CBC suite backed by the
// named OpenSSL EVP block cipher (e.g. "CAMELLIA-128-ECB").
func evpCBC(name string) func(key, iv []byte, isRead bool) any {
	return func(key, iv []byte, isRead bool) any {
		block := newEVPBlock(name, key)
		if isRead {
			return cipher.NewCBCDecrypter(block, iv)
		}
		return cipher.NewCBCEncrypter(block, iv)
	}
}
