// Copyright 2026 freetls authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// TLS 1.2 pre-shared-key key agreement (RFC 4279): pure PSK, DHE-PSK, ECDHE-PSK
// and RSA-PSK. Go's crypto/tls has no PSK cipher suites, so the freetls fork
// implements the client side here. Credentials come from Config.PskIdentity /
// Config.Psk.

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
)

func pskAppendU16(b []byte, v int) []byte {
	return append(b, byte(v>>8), byte(v))
}

// pskPremaster builds the RFC 4279 premaster secret:
//
//	struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; }
//
// For pure PSK, otherSecret is nil and becomes len(psk) zero bytes.
func pskPremaster(config *Config, otherSecret []byte) ([]byte, error) {
	if len(config.Psk) == 0 {
		return nil, errors.New("tls: PSK cipher suite requires Config.Psk")
	}
	if otherSecret == nil {
		otherSecret = make([]byte, len(config.Psk))
	}
	out := make([]byte, 0, 4+len(otherSecret)+len(config.Psk))
	out = pskAppendU16(out, len(otherSecret))
	out = append(out, otherSecret...)
	out = pskAppendU16(out, len(config.Psk))
	out = append(out, config.Psk...)
	return out, nil
}

func pskIdentityBytes(config *Config) ([]byte, error) {
	id := []byte(config.PskIdentity)
	if len(id) == 0 {
		return nil, errors.New("tls: PSK cipher suite requires Config.PskIdentity")
	}
	return id, nil
}

// splitPSKHint splits an optional psk_identity_hint from the front of a
// ServerKeyExchange, returning the remainder.
func splitPSKHint(raw []byte) (hint, rest []byte, err error) {
	if len(raw) < 2 {
		return nil, nil, errServerKeyExchange
	}
	n := int(raw[0])<<8 | int(raw[1])
	if 2+n > len(raw) {
		return nil, nil, errServerKeyExchange
	}
	return raw[2 : 2+n], raw[2+n:], nil
}

func pskServerKeyExchangeError() error {
	return errors.New("tls: PSK server side is not implemented")
}

// --- pure PSK (TLS_PSK_*) ---

type pskKeyAgreement struct {
	version uint16
}

func pskKA(version uint16) keyAgreement { return &pskKeyAgreement{version: version} }

func (ka *pskKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	// An optional psk_identity_hint may be sent; ignore it.
	if len(skx.key) > 0 {
		if _, _, err := splitPSKHint(skx.key); err != nil {
			return err
		}
	}
	return nil
}

func (ka *pskKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	pms, err := pskPremaster(config, nil)
	if err != nil {
		return nil, nil, err
	}
	id, err := pskIdentityBytes(config)
	if err != nil {
		return nil, nil, err
	}
	ckx := &clientKeyExchangeMsg{ciphertext: pskAppendU16(nil, len(id))}
	ckx.ciphertext = append(ckx.ciphertext, id...)
	return pms, ckx, nil
}

func (ka *pskKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, pskServerKeyExchangeError()
}

func (ka *pskKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, pskServerKeyExchangeError()
}

// --- DHE-PSK (TLS_DHE_PSK_*) ---

type dhePSKKeyAgreement struct {
	version         uint16
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte
}

func dhePSKKA(version uint16) keyAgreement { return &dhePSKKeyAgreement{version: version} }

func (ka *dhePSKKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	_, rest, err := splitPSKHint(skx.key)
	if err != nil {
		return err
	}
	p, g, ys, off, err := parseServerDHParams(rest)
	if err != nil {
		return err
	}
	if off != len(rest) { // PSK params are unsigned
		return errServerKeyExchange
	}
	if err := validateDHParams(p, g, ys); err != nil {
		return err
	}
	priv, pub, err := generateDHKey(config.rand(), p, g)
	if err != nil {
		return err
	}
	z := new(big.Int).Exp(ys, priv, p)
	pms, err := pskPremaster(config, z.Bytes())
	if err != nil {
		return err
	}
	id, err := pskIdentityBytes(config)
	if err != nil {
		return err
	}
	yc := pub.Bytes()
	ckx := pskAppendU16(nil, len(id))
	ckx = append(ckx, id...)
	ckx = pskAppendU16(ckx, len(yc))
	ckx = append(ckx, yc...)
	ka.preMasterSecret = pms
	ka.ckx = &clientKeyExchangeMsg{ciphertext: ckx}
	return nil
}

func (ka *dhePSKKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}
	return ka.preMasterSecret, ka.ckx, nil
}

func (ka *dhePSKKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, pskServerKeyExchangeError()
}

func (ka *dhePSKKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, pskServerKeyExchangeError()
}

// --- ECDHE-PSK (TLS_ECDHE_PSK_*) ---

type ecdhePSKKeyAgreement struct {
	version            uint16
	curveID            CurveID
	signatureAlgorithm SignatureScheme
	key                *ecdh.PrivateKey
	ckx                *clientKeyExchangeMsg
	preMasterSecret    []byte
}

func ecdhePSKKA(version uint16) keyAgreement { return &ecdhePSKKeyAgreement{version: version} }

func (ka *ecdhePSKKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	_, rest, err := splitPSKHint(skx.key)
	if err != nil {
		return err
	}
	if len(rest) < 4 || rest[0] != 3 { // named curve
		return errServerKeyExchange
	}
	ka.curveID = CurveID(rest[1])<<8 | CurveID(rest[2])
	n := int(rest[3])
	if 4+n != len(rest) { // PSK params are unsigned
		return errServerKeyExchange
	}
	if !slicesContainsCurve(clientHello.supportedCurves, ka.curveID) {
		return errors.New("tls: server selected unoffered curve")
	}
	key, err := generateECDHEKey(config.rand(), ka.curveID)
	if err != nil {
		return err
	}
	peerKey, err := key.Curve().NewPublicKey(rest[4 : 4+n])
	if err != nil {
		return errServerKeyExchange
	}
	shared, err := key.ECDH(peerKey)
	if err != nil {
		return errServerKeyExchange
	}
	pms, err := pskPremaster(config, shared)
	if err != nil {
		return err
	}
	id, err := pskIdentityBytes(config)
	if err != nil {
		return err
	}
	ourPub := key.PublicKey().Bytes()
	ckx := pskAppendU16(nil, len(id))
	ckx = append(ckx, id...)
	ckx = append(ckx, byte(len(ourPub))) // ECPoint: 1-byte length (RFC 5489)
	ckx = append(ckx, ourPub...)
	ka.key = key
	ka.preMasterSecret = pms
	ka.ckx = &clientKeyExchangeMsg{ciphertext: ckx}
	return nil
}

func (ka *ecdhePSKKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}
	return ka.preMasterSecret, ka.ckx, nil
}

func (ka *ecdhePSKKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, pskServerKeyExchangeError()
}

func (ka *ecdhePSKKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, pskServerKeyExchangeError()
}

// --- RSA-PSK (TLS_RSA_PSK_*) ---

type rsaPSKKeyAgreement struct {
	version uint16
}

func rsaPSKKA(version uint16) keyAgreement { return &rsaPSKKeyAgreement{version: version} }

func (ka *rsaPSKKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

func (ka *rsaPSKKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if cert == nil {
		return nil, nil, errors.New("tls: RSA-PSK requires a server certificate")
	}
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("tls: RSA-PSK requires an RSA server certificate")
	}
	// RFC 5246 §7.4.7.1: the RSA-encrypted premaster is 48 bytes whose first
	// two bytes are the client's advertised version; the server validates them.
	otherSecret := make([]byte, 48)
	otherSecret[0] = byte(ka.version >> 8)
	otherSecret[1] = byte(ka.version)
	if _, err := rand.Read(otherSecret[2:]); err != nil {
		return nil, nil, err
	}
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), rsaKey, otherSecret)
	if err != nil {
		return nil, nil, err
	}
	pms, err := pskPremaster(config, otherSecret)
	if err != nil {
		return nil, nil, err
	}
	id, err := pskIdentityBytes(config)
	if err != nil {
		return nil, nil, err
	}
	ckx := pskAppendU16(nil, len(id))
	ckx = append(ckx, id...)
	ckx = pskAppendU16(ckx, len(encrypted))
	ckx = append(ckx, encrypted...)
	return pms, &clientKeyExchangeMsg{ciphertext: ckx}, nil
}

func (ka *rsaPSKKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, pskServerKeyExchangeError()
}

func (ka *rsaPSKKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, pskServerKeyExchangeError()
}

// certlessKA reports whether a key agreement's cipher suite does not send a
// server Certificate (anonymous DH, PSK, SRP). RSA-PSK and the DHE-RSA/DHE-DSS
// suites do send one.
func certlessKA(ka keyAgreement) bool {
	switch k := ka.(type) {
	case *dhKeyAgreement:
		return k.auth == dhAuthAnon
	case *pskKeyAgreement, *dhePSKKeyAgreement, *ecdhePSKKeyAgreement:
		return true
	default:
		return false
	}
}

// isAnonymousKA reports whether the key agreement is the anonymous (ADH) variant.
func isAnonymousKA(ka keyAgreement) bool {
	if k, ok := ka.(*dhKeyAgreement); ok {
		return k.auth == dhAuthAnon
	}
	return false
}

func slicesContainsCurve(curves []CurveID, id CurveID) bool {
	for _, c := range curves {
		if c == id {
			return true
		}
	}
	return false
}
