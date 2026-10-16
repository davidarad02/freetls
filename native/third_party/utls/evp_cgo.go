//go:build freetls_libcrypto

package tls

/*
#cgo CFLAGS: -Wno-deprecated-declarations

#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL control codes (EVP_CTRL_CCM_* alias EVP_CTRL_AEAD_*). Expose them to
// cgo as simple integer macros so cgo evaluates them correctly.
#define FREETLS_CTRL_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define FREETLS_CTRL_GET_TAG   EVP_CTRL_AEAD_GET_TAG
#define FREETLS_CTRL_SET_TAG   EVP_CTRL_AEAD_SET_TAG
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// evpAEAD is a cipher.AEAD backed by an OpenSSL EVP AEAD cipher (GCM or CCM).
// It is used by the freetls libcrypto cipher suites; the TLS record/nonce
// framing is handled by the Go side (prefixNonceAEAD / xorNonceAEAD).
type evpAEAD struct {
	name   string
	key    []byte
	tagLen int
	ccm    bool
}

func newEVPAEAD(name string, key []byte, tagLen int, ccm bool) *evpAEAD {
	k := make([]byte, len(key))
	copy(k, key)
	return &evpAEAD{name: name, key: k, tagLen: tagLen, ccm: ccm}
}

func (a *evpAEAD) NonceSize() int { return aeadNonceLength }
func (a *evpAEAD) Overhead() int  { return a.tagLen }

func (a *evpAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out, err := evpSeal(a.name, a.ccm, a.tagLen, a.key, nonce, plaintext, additionalData)
	if err != nil {
		panic(fmt.Sprintf("freetls: EVP AEAD seal: %v", err))
	}
	return append(dst, out...)
}

func (a *evpAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	out, err := evpOpen(a.name, a.ccm, a.tagLen, a.key, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

func evpClearErrors() {
	for C.ERR_get_error() != 0 {
	}
}

func evpError(prefix string) error {
	var buf [256]C.char
	e := C.ERR_get_error()
	if e == 0 {
		return fmt.Errorf("freetls: %s", prefix)
	}
	C.ERR_error_string_n(e, &buf[0], C.size_t(len(buf)))
	evpClearErrors()
	return fmt.Errorf("freetls: %s: %s", prefix, C.GoString(&buf[0]))
}

// evpBytes returns a C pointer to b, or nil for an empty slice.
func evpBytes(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// evpCipher resolves an EVP cipher by OpenSSL name (e.g. "ARIA-128-GCM").
func evpCipher(name string) (*C.EVP_CIPHER, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cipher := C.EVP_get_cipherbyname(cName)
	if cipher == nil {
		return nil, fmt.Errorf("freetls: unknown EVP cipher %q", name)
	}
	return cipher, nil
}

func evpSeal(name string, ccm bool, tagLen int, key, nonce, plaintext, aad []byte) ([]byte, error) {
	cipher, err := evpCipher(name)
	if err != nil {
		return nil, err
	}

	evpClearErrors()
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("freetls: EVP_CIPHER_CTX_new failed")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	if C.EVP_EncryptInit_ex(ctx, cipher, nil, nil, nil) != 1 {
		return nil, evpError("EVP_EncryptInit_ex")
	}
	if ccm {
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_SET_IVLEN, C.int(len(nonce)), nil) != 1 {
			return nil, evpError("EVP ctrl SET_IVLEN")
		}
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_SET_TAG, C.int(tagLen), nil) != 1 {
			return nil, evpError("EVP ctrl SET_TAG(len)")
		}
	}
	if C.EVP_EncryptInit_ex(ctx, nil, nil, evpBytes(key), evpBytes(nonce)) != 1 {
		return nil, evpError("EVP_EncryptInit_ex key/iv")
	}

	var outl C.int
	if ccm {
		// CCM requires the total plaintext length before any AAD/data.
		if C.EVP_EncryptUpdate(ctx, nil, &outl, nil, C.int(len(plaintext))) != 1 {
			return nil, evpError("EVP_EncryptUpdate(len)")
		}
	}
	if len(aad) > 0 {
		if C.EVP_EncryptUpdate(ctx, nil, &outl, evpBytes(aad), C.int(len(aad))) != 1 {
			return nil, evpError("EVP_EncryptUpdate(aad)")
		}
	}

	out := make([]byte, len(plaintext)+tagLen)
	var n C.int
	if len(plaintext) > 0 {
		if C.EVP_EncryptUpdate(ctx, evpBytes(out), &n, evpBytes(plaintext), C.int(len(plaintext))) != 1 {
			return nil, evpError("EVP_EncryptUpdate(data)")
		}
	}
	total := int(n)
	var fn C.int
	if C.EVP_EncryptFinal_ex(ctx, evpBytes(out[total:]), &fn) != 1 {
		return nil, evpError("EVP_EncryptFinal_ex")
	}
	total += int(fn)
	if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_GET_TAG, C.int(tagLen), unsafe.Pointer(&out[total])) != 1 {
		return nil, evpError("EVP ctrl GET_TAG")
	}
	return out[:total+tagLen], nil
}

func evpOpen(name string, ccm bool, tagLen int, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < tagLen {
		return nil, fmt.Errorf("freetls: ciphertext shorter than tag")
	}
	ct := ciphertext[:len(ciphertext)-tagLen]
	tag := ciphertext[len(ciphertext)-tagLen:]

	cipher, err := evpCipher(name)
	if err != nil {
		return nil, err
	}

	evpClearErrors()
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("freetls: EVP_CIPHER_CTX_new failed")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	if C.EVP_DecryptInit_ex(ctx, cipher, nil, nil, nil) != 1 {
		return nil, evpError("EVP_DecryptInit_ex")
	}
	if ccm {
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_SET_IVLEN, C.int(len(nonce)), nil) != 1 {
			return nil, evpError("EVP ctrl SET_IVLEN")
		}
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_SET_TAG, C.int(tagLen), unsafe.Pointer(&tag[0])) != 1 {
			return nil, evpError("EVP ctrl SET_TAG")
		}
	}
	if C.EVP_DecryptInit_ex(ctx, nil, nil, evpBytes(key), evpBytes(nonce)) != 1 {
		return nil, evpError("EVP_DecryptInit_ex key/iv")
	}

	var outl C.int
	if ccm {
		if C.EVP_DecryptUpdate(ctx, nil, &outl, nil, C.int(len(ct))) != 1 {
			return nil, evpError("EVP_DecryptUpdate(len)")
		}
	}
	if len(aad) > 0 {
		if C.EVP_DecryptUpdate(ctx, nil, &outl, evpBytes(aad), C.int(len(aad))) != 1 {
			return nil, evpError("EVP_DecryptUpdate(aad)")
		}
	}

	// Allocate tagLen bytes of slack so the pointer handed to
	// EVP_DecryptFinal_ex is never NULL: OpenSSL's CCM path rejects an empty
	// output buffer even though CCM's final step emits no bytes.
	out := make([]byte, len(ct)+tagLen)
	var n C.int
	if len(ct) > 0 {
		if C.EVP_DecryptUpdate(ctx, evpBytes(out), &n, evpBytes(ct), C.int(len(ct))) != 1 {
			return nil, evpError("EVP_DecryptUpdate(data)")
		}
	}
	total := int(n)
	if !ccm {
		if C.EVP_CIPHER_CTX_ctrl(ctx, C.FREETLS_CTRL_SET_TAG, C.int(tagLen), unsafe.Pointer(&tag[0])) != 1 {
			return nil, evpError("EVP ctrl SET_TAG")
		}
	}
	var fn C.int
	if C.EVP_DecryptFinal_ex(ctx, evpBytes(out[total:]), &fn) != 1 {
		return nil, evpError("EVP_DecryptFinal_ex (authentication failed)")
	}
	total += int(fn)
	return out[:total], nil
}
