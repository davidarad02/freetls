// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Finite-field (FFDHE) Diffie-Hellman client key agreement for TLS 1.0-1.2.
//
// Go's crypto/tls only implements RSA and ECDHE key exchange; the freetls crypto
// bridge swaps the symmetric cipher but cannot add a key exchange. This file
// (part of the freetls fork) adds the client side of DHE so the DHE-RSA/DHE-DSS
// (and, later, ADH/DHE-PSK) cipher suites can complete.

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
)

// DHE authentication modes.
const (
	dhAuthAnon = iota // ADH (no certificate)
	dhAuthRSA         // DHE-RSA
	dhAuthDSS         // DHE-DSS
)

type dhKeyAgreement struct {
	version uint16
	auth    uint8

	// Set by processServerKeyExchange and returned by generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte

	// Server-side state (tests only).
	priv    *big.Int
	p, g, y *big.Int
}

func dhRSAKA(version uint16) keyAgreement {
	return &dhKeyAgreement{version: version, auth: dhAuthRSA}
}

func dhDSSKA(version uint16) keyAgreement {
	return &dhKeyAgreement{version: version, auth: dhAuthDSS}
}

func dhAnonKA(version uint16) keyAgreement {
	return &dhKeyAgreement{version: version, auth: dhAuthAnon}
}

// parseServerDHParams reads ServerDHParams (p, g, Ys) from a ServerKeyExchange
// and returns the offset at which the signature begins.
func parseServerDHParams(raw []byte) (p, g, ys *big.Int, off int, err error) {
	read := func() ([]byte, error) {
		if off+2 > len(raw) {
			return nil, errServerKeyExchange
		}
		n := int(raw[off])<<8 | int(raw[off+1])
		off += 2
		if off+n > len(raw) {
			return nil, errServerKeyExchange
		}
		b := raw[off : off+n]
		off += n
		return b, nil
	}
	pb, err := read()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	gb, err := read()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	yb, err := read()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if len(pb) == 0 || len(gb) == 0 || len(yb) == 0 {
		return nil, nil, nil, 0, errServerKeyExchange
	}
	return new(big.Int).SetBytes(pb), new(big.Int).SetBytes(gb), new(big.Int).SetBytes(yb), off, nil
}

// validateDHParams applies basic sanity checks to the server's DH parameters.
// RFC 7919 named-group exact matching is not enforced (arbitrary RFC 5246 params
// are accepted); the modulus size and the public value are range-checked.
func validateDHParams(p, g, ys *big.Int) error {
	bits := p.BitLen()
	if bits < 1024 || bits > 8192 {
		return fmt.Errorf("tls: unsupported DH modulus size %d bits", bits)
	}
	two := big.NewInt(2)
	hi := new(big.Int).Sub(p, two)
	if g.Cmp(two) < 0 || g.Cmp(hi) > 0 {
		return errors.New("tls: invalid DH generator")
	}
	if ys.Cmp(two) < 0 || ys.Cmp(hi) > 0 {
		return errors.New("tls: invalid DH public value")
	}
	return nil
}

// generateDHKey returns a fresh private exponent x in [2, p-2) and g^x mod p.
func generateDHKey(rnd io.Reader, p, g *big.Int) (priv, pub *big.Int, err error) {
	if p == nil || g == nil || p.Sign() <= 0 {
		return nil, nil, errors.New("tls: missing DH parameters")
	}
	limit := new(big.Int).Sub(p, big.NewInt(3)) // x in [0, p-3) then +2 -> [2, p-2)
	x, err := rand.Int(rnd, limit)
	if err != nil {
		return nil, nil, err
	}
	x.Add(x, big.NewInt(2))
	return x, new(big.Int).Exp(g, x, p), nil
}

func (ka *dhKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	p, g, ys, off, err := parseServerDHParams(skx.key)
	if err != nil {
		return err
	}
	if err := validateDHParams(p, g, ys); err != nil {
		return err
	}
	params := skx.key[:off]
	rest := skx.key[off:]

	if ka.auth != dhAuthAnon {
		var sigAlg SignatureScheme
		var sig []byte
		if ka.version >= VersionTLS12 {
			if len(rest) < 4 {
				return errServerKeyExchange
			}
			sigAlg = SignatureScheme(rest[0])<<8 | SignatureScheme(rest[1])
			n := int(rest[2])<<8 | int(rest[3])
			if 4+n != len(rest) {
				return errServerKeyExchange
			}
			sig = rest[4:]
		} else {
			if len(rest) < 2 {
				return errServerKeyExchange
			}
			n := int(rest[0])<<8 | int(rest[1])
			if 2+n != len(rest) {
				return errServerKeyExchange
			}
			sig = rest[2:]
		}
		if err := ka.verifyServerSignature(cert, clientHello, serverHello, params, sigAlg, sig); err != nil {
			return err
		}
	}

	priv, pub, err := generateDHKey(config.rand(), p, g)
	if err != nil {
		return err
	}
	z := new(big.Int).Exp(ys, priv, p)
	ka.preMasterSecret = z.Bytes()

	yc := pub.Bytes()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 2+len(yc))
	ka.ckx.ciphertext[0] = byte(len(yc) >> 8)
	ka.ckx.ciphertext[1] = byte(len(yc))
	copy(ka.ckx.ciphertext[2:], yc)
	return nil
}

func (ka *dhKeyAgreement) verifyServerSignature(cert *x509.Certificate, clientHello *clientHelloMsg, serverHello *serverHelloMsg, params []byte, sigAlg SignatureScheme, sig []byte) error {
	if cert == nil {
		return errors.New("tls: missing server certificate")
	}
	if ka.version >= VersionTLS12 {
		switch ka.auth {
		case dhAuthRSA:
			sigType, hashFunc, err := typeAndHashFromSignatureScheme(sigAlg)
			if err != nil {
				return err
			}
			if sigType != signaturePKCS1v15 && sigType != signatureRSAPSS {
				return errors.New("tls: DHE-RSA requires an RSA signature")
			}
			signed := slices.Concat(clientHello.random, serverHello.random, params)
			return verifyHandshakeSignature(sigType, cert.PublicKey, hashFunc, signed, sig)
		case dhAuthDSS:
			signed := slices.Concat(clientHello.random, serverHello.random, params)
			return verifyDSASignature(cert.PublicKey, sigAlg, signed, sig)
		default:
			return errors.New("tls: internal error: unknown DHE authentication mode")
		}
	}
	// TLS 1.0/1.1 (DHE-RSA only; DSA is not supported pre-1.2).
	sigType, hashFunc, err := legacyTypeAndHashFromPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if sigType != signaturePKCS1v15 {
		return errors.New("tls: DHE with TLS 1.0/1.1 requires an RSA signature")
	}
	hashed := hashForServerKeyExchange(sigType, clientHello.random, serverHello.random, params)
	return verifyLegacyHandshakeSignature(sigType, cert.PublicKey, hashFunc, hashed, sig)
}

func (ka *dhKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}
	return ka.preMasterSecret, ka.ckx, nil
}

// Server-side DHE is not implemented (freetls is a client).
func (ka *dhKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, errors.New("tls: DHE server side is not implemented")
}

func (ka *dhKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, errors.New("tls: DHE server side is not implemented")
}
