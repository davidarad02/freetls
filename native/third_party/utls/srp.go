// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// TLS 1.2 SRP key agreement (RFC 5054, SRP-6a). Go's crypto/tls has no SRP
// cipher suites, so the freetls fork implements the client side here. The
// credentials come from Config.SrpUsername / Config.SrpPassword.
//
// The wire format and the exact hashing follow OpenSSL (ssl/tls_srp.c,
// crypto/srp/srp_lib.c), which is the interop target:
//
//	x = SHA1(s || SHA1(user || ":" || pass))
//	k = SHA1(N || PAD(g))
//	u = SHA1(PAD(A) || PAD(B))
//	S = (B - k*g^x)^(a + u*x) mod N
//
// where PAD(x) left-pads x to the byte length of N. The premaster secret is the
// big-endian encoding of S. The ephemeral exponent a is 48 random bytes.
//
// NOTE: math/big is not constant-time; like the DHE path this is acceptable for
// a fingerprinting client but should not be treated as side-channel hardened.

import (
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"math/big"
	"slices"
)

// SRP authentication modes.
const (
	srpAuthSRP = iota // TLS_SRP_SHA_* (no certificate)
	srpAuthRSA        // TLS_SRP_SHA_RSA_*
	srpAuthDSS        // TLS_SRP_SHA_DSS_*
)

type srpKeyAgreement struct {
	version uint16
	auth    uint8

	// Set by processServerKeyExchange and returned by generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte

	// Server-side state (tests only).
	N, g, s, B, a *big.Int
}

func srpKA(version uint16) keyAgreement {
	return &srpKeyAgreement{version: version, auth: srpAuthSRP}
}

func srpRSAKA(version uint16) keyAgreement {
	return &srpKeyAgreement{version: version, auth: srpAuthRSA}
}

func srpDSSKA(version uint16) keyAgreement {
	return &srpKeyAgreement{version: version, auth: srpAuthDSS}
}

// srpPad left-pads x to exactly n bytes.
func srpPad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func srpSHA1(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// parseServerSRPParams reads ServerSRPParams (N, g, s, B) and returns the offset
// at which an (optional) signature begins. Lengths: N/g/B are uint16-prefixed,
// s is uint8-prefixed (RFC 5054 §2.4).
func parseServerSRPParams(raw []byte) (N, g, s, B *big.Int, off int, err error) {
	read16 := func() ([]byte, error) {
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
	read8 := func() ([]byte, error) {
		if off+1 > len(raw) {
			return nil, errServerKeyExchange
		}
		n := int(raw[off])
		off++
		if off+n > len(raw) {
			return nil, errServerKeyExchange
		}
		b := raw[off : off+n]
		off += n
		return b, nil
	}
	Nb, err := read16()
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	gb, err := read16()
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	sb, err := read8()
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	Bb, err := read16()
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	if len(Nb) == 0 || len(gb) == 0 || len(Bb) == 0 {
		return nil, nil, nil, nil, 0, errServerKeyExchange
	}
	return new(big.Int).SetBytes(Nb), new(big.Int).SetBytes(gb),
		new(big.Int).SetBytes(sb), new(big.Int).SetBytes(Bb), off, nil
}

func validateSRPParams(N, g, B *big.Int) error {
	if N.BitLen() < 1024 {
		return errors.New("tls: SRP modulus too small")
	}
	if g.Sign() <= 0 || g.Cmp(N) >= 0 {
		return errors.New("tls: invalid SRP generator")
	}
	if B.Sign() <= 0 || B.Cmp(N) >= 0 {
		return errors.New("tls: invalid SRP server public value")
	}
	return nil
}

// srpClientKey computes the SRP-6a premaster secret S for the given server
// parameters and credentials, returning S and the client public value A.
func srpClientKey(rnd interface{ Read([]byte) (int, error) }, N, g, s, B *big.Int, username, password string) (S, A *big.Int, err error) {
	// x = SHA1(s || SHA1(user || ":" || pass))
	inner := srpSHA1([]byte(username), []byte(":"), []byte(password))
	x := new(big.Int).SetBytes(srpSHA1(s.Bytes(), inner))

	// a = 48 random bytes (matches OpenSSL's ssl_srp_calc_a_param_intern).
	rndBytes := make([]byte, 48)
	if _, err := rnd.Read(rndBytes); err != nil {
		return nil, nil, err
	}
	a := new(big.Int).SetBytes(rndBytes)
	if a.Sign() == 0 {
		a.SetInt64(1)
	}

	A = new(big.Int).Exp(g, a, N)
	if A.Sign() == 0 {
		return nil, nil, errors.New("tls: SRP client public value is zero")
	}

	n := (N.BitLen() + 7) / 8
	// k = SHA1(N || PAD(g))
	k := new(big.Int).SetBytes(srpSHA1(srpPad(N, n), srpPad(g, n)))
	// u = SHA1(PAD(A) || PAD(B))
	u := new(big.Int).SetBytes(srpSHA1(srpPad(A, n), srpPad(B, n)))
	if u.Sign() == 0 {
		return nil, nil, errors.New("tls: SRP u is zero")
	}

	// S = (B - k*g^x)^(a + u*x) mod N
	gx := new(big.Int).Exp(g, x, N)
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, N)
	base := new(big.Int).Sub(B, kgx)
	base.Mod(base, N)
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, a)
	S = new(big.Int).Exp(base, exp, N)
	return S, A, nil
}

func (ka *srpKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	N, g, s, B, off, err := parseServerSRPParams(skx.key)
	if err != nil {
		return err
	}
	if err := validateSRPParams(N, g, B); err != nil {
		return err
	}
	params := skx.key[:off]

	if ka.auth != srpAuthSRP {
		rest := skx.key[off:]
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

	if config.SrpUsername == "" || config.SrpPassword == "" {
		return errors.New("tls: SRP cipher suite requires Config.SrpUsername and Config.SrpPassword")
	}
	S, A, err := srpClientKey(config.rand(), N, g, s, B, config.SrpUsername, config.SrpPassword)
	if err != nil {
		return err
	}
	ka.N, ka.g, ka.s, ka.B = N, g, s, B
	ka.preMasterSecret = S.Bytes()

	ab := A.Bytes()
	ka.ckx = &clientKeyExchangeMsg{ciphertext: pskAppendU16(nil, len(ab))}
	ka.ckx.ciphertext = append(ka.ckx.ciphertext, ab...)
	return nil
}

func (ka *srpKeyAgreement) verifyServerSignature(cert *x509.Certificate, clientHello *clientHelloMsg, serverHello *serverHelloMsg, params []byte, sigAlg SignatureScheme, sig []byte) error {
	if cert == nil {
		return errors.New("tls: missing server certificate")
	}
	if ka.version >= VersionTLS12 {
		signed := slices.Concat(clientHello.random, serverHello.random, params)
		switch ka.auth {
		case srpAuthRSA:
			sigType, hashFunc, err := typeAndHashFromSignatureScheme(sigAlg)
			if err != nil {
				return err
			}
			if sigType != signaturePKCS1v15 && sigType != signatureRSAPSS {
				return errors.New("tls: SRP-RSA requires an RSA signature")
			}
			return verifyHandshakeSignature(sigType, cert.PublicKey, hashFunc, signed, sig)
		case srpAuthDSS:
			return verifyDSASignature(cert.PublicKey, sigAlg, signed, sig)
		}
		return errors.New("tls: internal error: unknown SRP authentication mode")
	}
	sigType, hashFunc, err := legacyTypeAndHashFromPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	if sigType != signaturePKCS1v15 {
		return errors.New("tls: SRP with TLS 1.0/1.1 requires an RSA signature")
	}
	hashed := hashForServerKeyExchange(sigType, clientHello.random, serverHello.random, params)
	return verifyLegacyHandshakeSignature(sigType, cert.PublicKey, hashFunc, hashed, sig)
}

func (ka *srpKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}
	return ka.preMasterSecret, ka.ckx, nil
}

// Server-side SRP is not implemented (freetls is a client).
func (ka *srpKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, errors.New("tls: SRP server side is not implemented")
}

func (ka *srpKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, errors.New("tls: SRP server side is not implemented")
}
