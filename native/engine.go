package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

// ---------------------------------------------------------------------------
// JSON spec model
// ---------------------------------------------------------------------------

// extJSON is a single ClientHello extension request from Python.
//
// The "type" field selects a typed uTLS extension (so the handshake engine can
// use it functionally), or "generic" to inject an arbitrary extension ID with
// raw bytes (used for JA4 padding).
type extJSON struct {
	Type       string   `json:"type"`
	ID         *uint16  `json:"id,omitempty"`
	Data       string   `json:"data,omitempty"` // hex
	Values     []uint16 `json:"values,omitempty"`
	Strings    []string `json:"strings,omitempty"`
	Modes      []uint8  `json:"modes,omitempty"`
	Points     []uint8  `json:"points,omitempty"`
	ServerName string   `json:"server_name,omitempty"`
	Algorithms []uint16 `json:"algorithms,omitempty"`
	// PaddingLen, when > 0, requests a fixed-length padding extension.
	PaddingLen int `json:"padding_len,omitempty"`
}

type specJSON struct {
	// Preset selects a built-in uTLS ClientHelloID (e.g. "HelloChrome_133").
	// When set, it is used instead of the explicit Extensions list.
	Preset string `json:"preset,omitempty"`
	// Overrides applied to a preset before the handshake.
	PresetNoSNI      bool     `json:"preset_no_sni,omitempty"`
	PresetALPN       []string `json:"preset_alpn,omitempty"`
	PresetALPNRemove bool     `json:"preset_alpn_remove,omitempty"`

	// ChloJSON is a uTLS ClientHelloSpec JSON document. When set it takes
	// precedence over Preset and the explicit Extensions list.
	ChloJSON string `json:"chlo_json,omitempty"`

	Ciphers     []uint16  `json:"ciphers"`
	Compression []uint8   `json:"compression,omitempty"`
	Extensions  []extJSON `json:"extensions,omitempty"`

	VersMin uint16 `json:"vers_min,omitempty"`
	VersMax uint16 `json:"vers_max,omitempty"`

	Verify     bool   `json:"verify"`
	RootCA     string `json:"root_ca,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	// Certificate suite options.
	CheckHostname *bool    `json:"check_hostname,omitempty"` // default true
	SystemRoots   *bool    `json:"system_roots,omitempty"`   // default true
	CADir         string   `json:"ca_dir,omitempty"`         // dir of PEM certs
	CAData        string   `json:"cadata,omitempty"`         // PEM text
	ClientCert    string   `json:"client_cert,omitempty"`    // PEM file (mTLS)
	ClientKey     string   `json:"client_key,omitempty"`     // PEM file (mTLS)
	ClientCertPEM string   `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string   `json:"client_key_pem,omitempty"`
	PinnedSHA256  []string `json:"pinned_sha256,omitempty"` // base64 sha256 of leaf DER

	// SessionCache, when > 0, enables TLS session resumption through a shared
	// process-wide LRU session cache (TLS 1.2 tickets and TLS 1.3 PSKs).
	SessionCache int `json:"session_cache,omitempty"`

	TimeoutMS int `json:"timeout_ms,omitempty"`
}

// presetByName is generated from the pinned uTLS version by
// tools/gen_presets.py (see native/preset_map_gen.go). Do not edit by hand.

// ---------------------------------------------------------------------------
// tee-ing net.Conn: records handshake bytes for JA4/JA4S self-verification
// ---------------------------------------------------------------------------

type teeConn struct {
	net.Conn
	mu     sync.Mutex
	out    []byte
	in     []byte
	cap    int
	record bool
}

func (t *teeConn) Write(b []byte) (int, error) {
	t.mu.Lock()
	if t.record && len(t.out) < t.cap {
		t.out = append(t.out, b...)
	}
	t.mu.Unlock()
	return t.Conn.Write(b)
}

func (t *teeConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.mu.Lock()
		if t.record && len(t.in) < t.cap {
			t.in = append(t.in, b[:n]...)
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *teeConn) captured() (out, in []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.out...), append([]byte(nil), t.in...)
}

// firstHandshake walks TLS records in stream and returns the first handshake
// message of the requested type (including its 4-byte handshake header).
func firstHandshake(stream []byte, wantType byte) []byte {
	i := 0
	for i+5 <= len(stream) {
		ct := stream[i]
		length := int(stream[i+3])<<8 | int(stream[i+4])
		if i+5+length > len(stream) {
			return nil
		}
		if ct == 0x16 { // handshake record
			hs := stream[i+5 : i+5+length]
			j := 0
			for j+4 <= len(hs) {
				mt := hs[j]
				ml := int(hs[j+1])<<16 | int(hs[j+2])<<8 | int(hs[j+3])
				if j+4+ml > len(hs) {
					break // fragmented into next record; not handled here
				}
				if mt == wantType {
					return append([]byte(nil), hs[j:j+4+ml]...)
				}
				j += 4 + ml
			}
		}
		i += 5 + length
	}
	return nil
}

// ---------------------------------------------------------------------------
// session registry
// ---------------------------------------------------------------------------

type session struct {
	spec     *utls.ClientHelloSpec
	config   *utls.Config
	tee      *teeConn
	uconn    *utls.UConn
	raw      net.Conn
	preset   string
	chloJSON string
	noSNI    bool
	alpn     []string
	alpnSet  bool
	alpnDel  bool
	lastErr  string
	timeout  time.Duration
}

var (
	regMu    sync.Mutex
	registry       = map[int64]*session{}
	nextID   int64 = 1
)

// Shared client session caches used for TLS resumption, keyed by capacity. They
// are process-wide so separate freetls sessions (each a fresh engine session)
// can resume a previously established session with the same server. Sessions
// that request the same capacity share a cache.
var (
	sessCacheMu    sync.Mutex
	sessCacheByCap = map[int]utls.ClientSessionCache{}
)

func sessionCache(capacity int) utls.ClientSessionCache {
	if capacity <= 0 {
		capacity = 64
	}
	sessCacheMu.Lock()
	defer sessCacheMu.Unlock()
	if c, ok := sessCacheByCap[capacity]; ok {
		return c
	}
	c := utls.NewLRUClientSessionCache(capacity)
	sessCacheByCap[capacity] = c
	return c
}

func putSession(s *session) int64 {
	regMu.Lock()
	defer regMu.Unlock()
	id := nextID
	nextID++
	registry[id] = s
	return id
}

func getSession(id int64) *session {
	regMu.Lock()
	defer regMu.Unlock()
	return registry[id]
}

func delSession(id int64) *session {
	regMu.Lock()
	defer regMu.Unlock()
	s := registry[id]
	delete(registry, id)
	return s
}

// ---------------------------------------------------------------------------
// spec -> uTLS
// ---------------------------------------------------------------------------

func toCurveIDs(v []uint16) []utls.CurveID {
	out := make([]utls.CurveID, len(v))
	for i, x := range v {
		out[i] = utls.CurveID(x)
	}
	return out
}

func toSigSchemes(v []uint16) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, len(v))
	for i, x := range v {
		out[i] = utls.SignatureScheme(x)
	}
	return out
}

func toKeyShares(v []uint16) []utls.KeyShare {
	out := make([]utls.KeyShare, len(v))
	for i, x := range v {
		out[i] = utls.KeyShare{Group: utls.CurveID(x), Data: nil}
	}
	return out
}

func buildExtension(e extJSON) (utls.TLSExtension, error) {
	switch e.Type {
	case "sni":
		return &utls.SNIExtension{ServerName: e.ServerName}, nil
	case "alpn":
		return &utls.ALPNExtension{AlpnProtocols: e.Strings}, nil
	case "supported_versions":
		return &utls.SupportedVersionsExtension{Versions: e.Values}, nil
	case "supported_curves":
		return &utls.SupportedCurvesExtension{Curves: toCurveIDs(e.Values)}, nil
	case "ec_point_formats":
		return &utls.SupportedPointsExtension{SupportedPoints: e.Points}, nil
	case "signature_algorithms":
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: toSigSchemes(e.Values)}, nil
	case "key_share":
		return &utls.KeyShareExtension{KeyShares: toKeyShares(e.Values)}, nil
	case "psk_key_exchange_modes":
		return &utls.PSKKeyExchangeModesExtension{Modes: e.Modes}, nil
	case "extended_master_secret":
		return &utls.ExtendedMasterSecretExtension{}, nil
	case "renegotiation_info":
		return &utls.RenegotiationInfoExtension{}, nil
	case "session_ticket":
		return &utls.SessionTicketExtension{}, nil
	case "status_request":
		return &utls.StatusRequestExtension{}, nil
	case "sct":
		return &utls.SCTExtension{}, nil
	case "compress_certificate":
		algs := make([]utls.CertCompressionAlgo, len(e.Values))
		for i, x := range e.Values {
			algs[i] = utls.CertCompressionAlgo(x)
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algs}, nil
	case "padding":
		if e.PaddingLen > 0 {
			n := e.PaddingLen
			return &utls.UtlsPaddingExtension{
				GetPaddingLen: func(int) (int, bool) { return n, true },
			}, nil
		}
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil
	case "record_size_limit":
		var limit uint16
		if len(e.Values) > 0 {
			limit = e.Values[0]
		}
		return &utls.FakeRecordSizeLimitExtension{Limit: limit}, nil
	case "pre_shared_key":
		return &utls.UtlsPreSharedKeyExtension{}, nil
	case "application_settings":
		return &utls.ApplicationSettingsExtension{SupportedProtocols: e.Strings}, nil
	case "generic":
		if e.ID == nil {
			return nil, errors.New("generic extension requires id")
		}
		var data []byte
		if e.Data != "" {
			b, err := hex.DecodeString(e.Data)
			if err != nil {
				return nil, fmt.Errorf("generic ext data not hex: %w", err)
			}
			data = b
		}
		return &utls.GenericExtension{Id: *e.ID, Data: data}, nil
	case "grease":
		return &utls.UtlsGREASEExtension{}, nil
	default:
		return nil, fmt.Errorf("unknown extension type %q", e.Type)
	}
}

func parseSpec(js string) (*specJSON, *utls.ClientHelloSpec, *utls.Config, error) {
	var s specJSON
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		return nil, nil, nil, fmt.Errorf("bad spec json: %w", err)
	}

	exts := make([]utls.TLSExtension, 0, len(s.Extensions))
	for i, e := range s.Extensions {
		ext, err := buildExtension(e)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("extension[%d]: %w", i, err)
		}
		exts = append(exts, ext)
	}

	chs := &utls.ClientHelloSpec{
		CipherSuites:       s.Ciphers,
		CompressionMethods: s.Compression,
		Extensions:         exts,
		TLSVersMin:         s.VersMin,
		TLSVersMax:         s.VersMax,
	}

	checkHostname := true
	if s.CheckHostname != nil {
		checkHostname = *s.CheckHostname
	}
	systemRoots := true
	if s.SystemRoots != nil {
		systemRoots = *s.SystemRoots
	}

	cfg := &utls.Config{ServerName: s.ServerName}
	// With HelloCustom uTLS refuses to handshake if resumption is enabled but
	// no ticket/PSK extension is present. This lets a spec opt out cleanly.
	cfg.PreferSkipResumptionOnNilExtension = true
	if s.SessionCache > 0 {
		cfg.ClientSessionCache = sessionCache(s.SessionCache)
		// Conceal an empty pre_shared_key on the first (cold-cache) connection.
		cfg.OmitEmptyPsk = true
	}

	// Assemble a CA pool from the requested sources.
	var pool *x509.CertPool
	if systemRoots {
		if sys, err := x509.SystemCertPool(); err == nil {
			pool = sys
		} else {
			pool = x509.NewCertPool()
		}
	}
	addPEM := func(pem []byte, src string) error {
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("failed to parse %s", src)
		}
		return nil
	}
	if s.RootCA != "" {
		pem, err := os.ReadFile(s.RootCA)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read root_ca: %w", err)
		}
		if err := addPEM(pem, "root_ca"); err != nil {
			return nil, nil, nil, err
		}
	}
	if s.CAData != "" {
		if err := addPEM([]byte(s.CAData), "cadata"); err != nil {
			return nil, nil, nil, err
		}
	}
	if s.CADir != "" {
		entries, err := os.ReadDir(s.CADir)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read ca_dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if pem, err := os.ReadFile(filepath.Join(s.CADir, e.Name())); err == nil {
				if pool == nil {
					pool = x509.NewCertPool()
				}
				pool.AppendCertsFromPEM(pem)
			}
		}
	}

	switch {
	case !s.Verify:
		cfg.InsecureSkipVerify = true
	case !checkHostname:
		// Verify the chain but not the hostname; also enforce pins.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = makeChainVerifier(pool, s.PinnedSHA256)
	case len(s.PinnedSHA256) > 0:
		cfg.RootCAs = pool
		cfg.VerifyPeerCertificate = makePinVerifier(s.PinnedSHA256)
	default:
		cfg.RootCAs = pool
	}

	if cert, err := loadClientCert(s); err != nil {
		return nil, nil, nil, err
	} else if cert != nil {
		cfg.Certificates = []utls.Certificate{*cert}
	}
	return &s, chs, cfg, nil
}

// loadClientCert builds a client certificate for mTLS from files or inline PEM.
func loadClientCert(s specJSON) (*utls.Certificate, error) {
	var certPEM, keyPEM []byte
	switch {
	case s.ClientCertPEM != "" || s.ClientKeyPEM != "":
		certPEM, keyPEM = []byte(s.ClientCertPEM), []byte(s.ClientKeyPEM)
	case s.ClientCert != "" || s.ClientKey != "":
		var err error
		if certPEM, err = os.ReadFile(s.ClientCert); err != nil {
			return nil, fmt.Errorf("read client_cert: %w", err)
		}
		if keyPEM, err = os.ReadFile(s.ClientKey); err != nil {
			return nil, fmt.Errorf("read client_key: %w", err)
		}
	default:
		return nil, nil
	}
	c, err := utls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	return &c, nil
}

func checkPins(cert *x509.Certificate, pins []string) error {
	if len(pins) == 0 {
		return nil
	}
	leaf := sha256.Sum256(cert.Raw)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	leafEnc := base64.StdEncoding.EncodeToString(leaf[:])
	spkiEnc := base64.StdEncoding.EncodeToString(spki[:])
	for _, p := range pins {
		if p == leafEnc || p == spkiEnc {
			return nil
		}
	}
	return errors.New("certificate pin mismatch")
}

// makeChainVerifier verifies the peer chain (against roots) but not the
// hostname, and enforces pins.
func makeChainVerifier(roots *x509.CertPool, pins []string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		if _, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return err
		}
		return checkPins(certs[0], pins)
	}
}

// makePinVerifier enforces pins while the normal Go verification runs.
func makePinVerifier(pins []string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		return checkPins(c, pins)
	}
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

func cErr(s *session, err error) {
	if s != nil {
		s.lastErr = err.Error()
	}
}

//export freetls_version
func freetls_version() *C.char {
	return C.CString("freetls/0.0.1")
}

// ABI version of the C surface. Bump when an export's signature/semantics
// changes incompatibly; the Python binding refuses to load on a major mismatch.
const abiVersion = 2

//export freetls_abi_version
func freetls_abi_version() C.int {
	return abiVersion
}

//export freetls_free
func freetls_free(p *C.char) {
	C.free(unsafe.Pointer(p))
}

//export freetls_ping
func freetls_ping() C.int {
	return 0x4654
}

// dummyConn is a no-op net.Conn used to build a ClientHello without any I/O.
type dummyConn struct{}

func (dummyConn) Read(b []byte) (int, error)       { return 0, errors.New("no io") }
func (dummyConn) Write(b []byte) (int, error)      { return 0, errors.New("no io") }
func (dummyConn) Close() error                     { return nil }
func (dummyConn) LocalAddr() net.Addr              { return nil }
func (dummyConn) RemoteAddr() net.Addr             { return nil }
func (dummyConn) SetDeadline(time.Time) error      { return nil }
func (dummyConn) SetReadDeadline(time.Time) error  { return nil }
func (dummyConn) SetWriteDeadline(time.Time) error { return nil }

// freetls_preset_raw builds a preset's ClientHello offline and returns the raw
// handshake message as hex (empty string on error). No network is used.
//
//export freetls_preset_raw
func freetls_preset_raw(name *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("panic: %v", r)
			out = C.CString("")
		}
	}()
	id, ok := presetByName[C.GoString(name)]
	if !ok {
		return C.CString("")
	}
	uconn := utls.UClient(dummyConn{}, &utls.Config{ServerName: "example.com"}, id)
	if err := uconn.BuildHandshakeState(); err != nil {
		return C.CString("")
	}
	if err := uconn.MarshalClientHello(); err != nil {
		return C.CString("")
	}
	return hexOf(uconn.HandshakeState.Hello.Raw)
}

// parseChloJSON parses a uTLS ClientHelloSpec JSON document.
func parseChloJSON(js string) (*utls.ClientHelloSpec, error) {
	var chs utls.ClientHelloSpec
	if err := json.Unmarshal([]byte(js), &chs); err != nil {
		return nil, err
	}
	return &chs, nil
}

// safeParseChloJSON parses JSON but converts the uTLS parser's panics (it can
// nil-deref on a document missing required fields) into an error.
func safeParseChloJSON(js string) (chs *utls.ClientHelloSpec, err error) {
	defer func() {
		if r := recover(); r != nil {
			chs, err = nil, fmt.Errorf("invalid ClientHelloSpec JSON: %v", r)
		}
	}()
	return parseChloJSON(js)
}

// freetls_chlo_raw builds a ClientHello offline from a uTLS ClientHelloSpec
// JSON document and returns the raw handshake message as hex (empty on error).
// No network is used.
//
//export freetls_chlo_raw
func freetls_chlo_raw(chloJSON *C.char) (out *C.char) {
	auxErr = ""
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("invalid ClientHelloSpec JSON: %v", r)
			out = C.CString("")
		}
	}()
	chs, err := safeParseChloJSON(C.GoString(chloJSON))
	if err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	uconn := utls.UClient(dummyConn{}, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(chs); err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	if err := uconn.MarshalClientHello(); err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	return hexOf(uconn.HandshakeState.Hello.Raw)
}

// auxErr holds the reason the last offline build (chlo_json) failed.
var auxErr string

// freetls_aux_error returns the last offline-build error (empty if none).
//
//export freetls_aux_error
func freetls_aux_error() *C.char {
	return C.CString(auxErr)
}

// freetls_preset_list returns a JSON array of known preset names.
//
//export freetls_preset_list
func freetls_preset_list() (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			out = C.CString("[]")
		}
	}()
	names := make([]string, 0, len(presetByName))
	for k := range presetByName {
		names = append(names, k)
	}
	sort.Strings(names)
	b, _ := json.Marshal(names)
	return C.CString(string(b))
}

// freetls_supported_ciphers returns a JSON array of the cipher-suite IDs this
// engine can complete (Go-native union any libcrypto-added suites).
//
//export freetls_supported_ciphers
func freetls_supported_ciphers() (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			out = C.CString("[]")
		}
	}()
	b, err := json.Marshal(utls.FreetlsSupportedCipherSuiteIDs())
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(b))
}

// safeExtensionIDs is the whitelist of extension types safe mode accepts: the
// extension kinds the engine implements and whose semantics it can honour.
var safeExtensionIDs = []uint16{
	0x0000, // server_name
	0x0005, // status_request (OCSP)
	0x000a, // supported_groups
	0x000b, // ec_point_formats
	0x000d, // signature_algorithms
	0x0010, // alpn
	0x0012, // signed_certificate_timestamp (SCT)
	0x0015, // padding
	0x0017, // extended_master_secret
	0x001b, // compress_certificate
	0x001c, // record_size_limit
	0x0023, // session_ticket
	0x0029, // pre_shared_key
	0x002b, // supported_versions
	0x002d, // psk_key_exchange_modes
	0x0033, // key_share
	0x4469, // application_settings (ALPS)
	0x44cd, // application_settings (ALPS, alternate codepoint)
	0xff01, // renegotiation_info
}

// freetls_supported_extensions returns the safe-mode extension whitelist as a
// JSON array of extension type IDs.
//
//export freetls_supported_extensions
func freetls_supported_extensions() (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			out = C.CString("[]")
		}
	}()
	b, err := json.Marshal(safeExtensionIDs)
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(b))
}

// freetls_spec_raw builds the ClientHello for an engine spec offline (no
// network) and returns the raw handshake message as hex (empty on error). It is
// used by the safe-mode validator to inspect the effective hello.
//
//export freetls_spec_raw
func freetls_spec_raw(specJSON *C.char) (out *C.char) {
	auxErr = ""
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("invalid spec: %v", r)
			out = C.CString("")
		}
	}()
	_, chs, _, err := parseSpec(C.GoString(specJSON))
	if err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	uconn := utls.UClient(dummyConn{}, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(chs); err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	if err := uconn.MarshalClientHello(); err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	return hexOf(uconn.HandshakeState.Hello.Raw)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func applyNoSNI(uconn *utls.UConn) {
	kept := uconn.Extensions[:0]
	for _, e := range uconn.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			continue
		}
		kept = append(kept, e)
	}
	uconn.Extensions = kept
	if uconn.HandshakeState.Hello != nil {
		uconn.HandshakeState.Hello.ServerName = ""
	}
}

// alpnJSON: "" leaves ALPN untouched, "-" removes ALPN, otherwise a JSON array.
func applyALPN(uconn *utls.UConn, alpnJSON string) {
	if alpnJSON == "" {
		return
	}
	kept := uconn.Extensions[:0]
	for _, e := range uconn.Extensions {
		if _, ok := e.(*utls.ALPNExtension); ok {
			continue
		}
		kept = append(kept, e)
	}
	uconn.Extensions = kept
	var protos []string
	if alpnJSON != "-" {
		_ = json.Unmarshal([]byte(alpnJSON), &protos)
	}
	if len(protos) > 0 {
		uconn.Extensions = append(uconn.Extensions, &utls.ALPNExtension{AlpnProtocols: protos})
	}
	if uconn.HandshakeState.Hello != nil {
		uconn.HandshakeState.Hello.AlpnProtocols = protos
	}
}

// freetls_preset_raw_opts builds a preset ClientHello offline with SNI/ALPN
// overrides (used to enumerate real-world variants). No network is used.
//
//export freetls_preset_raw_opts
func freetls_preset_raw_opts(name *C.char, noSNI C.int, alpnJSON *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("panic: %v", r)
			out = C.CString("")
		}
	}()
	id, ok := presetByName[C.GoString(name)]
	if !ok {
		return C.CString("")
	}
	uconn := utls.UClient(dummyConn{}, &utls.Config{ServerName: "example.com"}, id)
	if err := uconn.BuildHandshakeState(); err != nil {
		return C.CString("")
	}
	if C.GoString(alpnJSON) != "" {
		applyALPN(uconn, C.GoString(alpnJSON))
	}
	if noSNI != 0 {
		applyNoSNI(uconn)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		return C.CString("")
	}
	return hexOf(uconn.HandshakeState.Hello.Raw)
}

//export freetls_session_new
func freetls_session_new(specJSON *C.char) (id C.longlong) {
	auxErr = ""
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("panic: %v", r)
			id = 0
		}
	}()
	s, chs, cfg, err := parseSpec(C.GoString(specJSON))
	if err != nil {
		auxErr = err.Error()
		return 0
	}
	sess := &session{spec: chs, config: cfg, preset: s.Preset, chloJSON: s.ChloJSON,
		noSNI: s.PresetNoSNI, alpn: s.PresetALPN,
		alpnSet: s.PresetALPN != nil, alpnDel: s.PresetALPNRemove}
	if s.TimeoutMS > 0 {
		sess.timeout = time.Duration(s.TimeoutMS) * time.Millisecond
	}
	id = C.longlong(putSession(sess))
	return id
}

// freetls_session_count returns the number of live sessions in the registry.
// Used by tests to assert there are no leaks.
//
//export freetls_session_count
func freetls_session_count() C.longlong {
	regMu.Lock()
	defer regMu.Unlock()
	return C.longlong(len(registry))
}

//export freetls_session_free
func freetls_session_free(h C.longlong) {
	defer func() { _ = recover() }()
	s := delSession(int64(h))
	if s == nil {
		return
	}
	if s.uconn != nil {
		_ = s.uconn.Close()
	}
	if s.raw != nil {
		_ = s.raw.Close()
	}
}

// freetls_handshake performs the TLS handshake over an already-connected fd.
// Returns 0 on success, negative on failure.
//
//export freetls_handshake
func freetls_handshake(h C.longlong, fd C.int, sni *C.char) (rc C.int) {
	defer func() {
		if r := recover(); r != nil {
			if s := getSession(int64(h)); s != nil {
				cErr(s, fmt.Errorf("panic: %v", r))
			}
			rc = -99
		}
	}()
	s := getSession(int64(h))
	if s == nil {
		return -1
	}
	if sni != nil && C.GoString(sni) != "" {
		s.config.ServerName = C.GoString(sni)
	}
	f := os.NewFile(uintptr(fd), "freetls-fd")
	if f == nil {
		cErr(s, errors.New("bad fd"))
		return -2
	}
	raw, err := net.FileConn(f)
	_ = f.Close() // FileConn dups the fd; close our wrapper/dup
	if err != nil {
		cErr(s, fmt.Errorf("FileConn: %w", err))
		return -3
	}
	s.raw = raw

	tee := &teeConn{Conn: raw, cap: 1 << 16, record: true}
	s.tee = tee

	uconn := utls.UClient(tee, s.config, utls.HelloCustom)
	if s.chloJSON != "" {
		chs, err := safeParseChloJSON(s.chloJSON)
		if err != nil {
			cErr(s, fmt.Errorf("chlo_json: %w", err))
			return -9
		}
		if err := uconn.ApplyPreset(chs); err != nil {
			cErr(s, fmt.Errorf("ApplyPreset(chlo_json): %w", err))
			return -4
		}
	} else if s.preset != "" {
		id, ok := presetByName[s.preset]
		if !ok {
			cErr(s, fmt.Errorf("unknown preset %q", s.preset))
			return -6
		}
		uconn = utls.UClient(tee, s.config, id)
		if s.alpnSet || s.alpnDel || s.noSNI {
			if err := uconn.BuildHandshakeState(); err != nil {
				cErr(s, fmt.Errorf("build state: %w", err))
				return -7
			}
			if s.alpnSet {
				applyALPN(uconn, mustJSON(s.alpn))
			} else if s.alpnDel {
				applyALPN(uconn, "-")
			}
			if s.noSNI {
				applyNoSNI(uconn)
			}
			if err := uconn.MarshalClientHello(); err != nil {
				cErr(s, fmt.Errorf("marshal: %w", err))
				return -8
			}
		}
	} else if err := uconn.ApplyPreset(s.spec); err != nil {
		cErr(s, fmt.Errorf("ApplyPreset: %w", err))
		return -4
	}
	if s.timeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(s.timeout))
	}
	if err := uconn.Handshake(); err != nil {
		cErr(s, fmt.Errorf("handshake: %w", err))
		return -5
	}
	if s.timeout > 0 {
		_ = raw.SetDeadline(time.Time{})
	}
	tee.mu.Lock()
	tee.record = false
	tee.mu.Unlock()
	s.uconn = uconn
	return 0
}

//export freetls_read
func freetls_read(h C.longlong, buf unsafe.Pointer, length C.longlong) (rc C.longlong) {
	defer func() {
		if r := recover(); r != nil {
			if s := getSession(int64(h)); s != nil {
				cErr(s, fmt.Errorf("panic: %v", r))
			}
			rc = -99
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.uconn == nil {
		return -1
	}
	if s.timeout > 0 && s.raw != nil {
		_ = s.raw.SetReadDeadline(time.Now().Add(s.timeout))
	}
	n, err := s.uconn.Read(unsafe.Slice((*byte)(buf), int(length)))
	if s.timeout > 0 && s.raw != nil {
		_ = s.raw.SetReadDeadline(time.Time{})
	}
	if n > 0 {
		return C.longlong(n)
	}
	if err != nil {
		cErr(s, err)
		return -2
	}
	return 0
}

//export freetls_write
func freetls_write(h C.longlong, buf unsafe.Pointer, length C.longlong) (rc C.longlong) {
	defer func() {
		if r := recover(); r != nil {
			if s := getSession(int64(h)); s != nil {
				cErr(s, fmt.Errorf("panic: %v", r))
			}
			rc = -99
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.uconn == nil {
		return -1
	}
	n, err := s.uconn.Write(unsafe.Slice((*byte)(buf), int(length)))
	if n > 0 {
		return C.longlong(n)
	}
	if err != nil {
		cErr(s, err)
		return -2
	}
	return 0
}

//export freetls_close
func freetls_close(h C.longlong) {
	defer func() { _ = recover() }()
	s := getSession(int64(h))
	if s == nil {
		return
	}
	if s.uconn != nil {
		_ = s.uconn.Close()
	}
}

// freetls_set_timeout updates the per-session I/O timeout (milliseconds).
//
//export freetls_set_timeout
func freetls_set_timeout(h C.longlong, ms C.int) {
	defer func() { _ = recover() }()
	s := getSession(int64(h))
	if s == nil {
		return
	}
	if ms <= 0 {
		s.timeout = 0
	} else {
		s.timeout = time.Duration(ms) * time.Millisecond
	}
}

func hexOf(b []byte) *C.char {
	if b == nil {
		return C.CString("")
	}
	return C.CString(hex.EncodeToString(b))
}

//export freetls_get_client_hello
func freetls_get_client_hello(h C.longlong) (rc *C.char) {
	defer func() {
		if r := recover(); r != nil {
			rc = C.CString("")
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.tee == nil {
		return C.CString("")
	}
	out, _ := s.tee.captured()
	return hexOf(firstHandshake(out, 1))
}

//export freetls_get_server_hello
func freetls_get_server_hello(h C.longlong) (rc *C.char) {
	defer func() {
		if r := recover(); r != nil {
			rc = C.CString("")
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.tee == nil {
		return C.CString("")
	}
	_, in := s.tee.captured()
	return hexOf(firstHandshake(in, 2))
}

type stateJSON struct {
	Version      string   `json:"version"`
	CipherSuite  uint16   `json:"cipher_suite"`
	ALPN         string   `json:"alpn"`
	ServerName   string   `json:"server_name"`
	PeerCertB64  string   `json:"peer_cert_b64,omitempty"`
	PeerCertsB64 []string `json:"peer_certs_b64,omitempty"`
	DidResume    bool     `json:"did_resume"`
	OCSPB64      string   `json:"ocsp_response_b64,omitempty"`
	SCTB64       []string `json:"sct_b64,omitempty"`
	ALPSB64      string   `json:"peer_alps_b64,omitempty"`
	Error        string   `json:"error"`
}

//export freetls_get_state
func freetls_get_state(h C.longlong) (rc *C.char) {
	defer func() {
		if r := recover(); r != nil {
			rc = C.CString("{}")
		}
	}()
	s := getSession(int64(h))
	if s == nil {
		return C.CString("{}")
	}
	st := stateJSON{Error: s.lastErr}
	if s.uconn != nil {
		cs := s.uconn.ConnectionState()
		st.Version = tlsVersionName(cs.Version)
		st.CipherSuite = uint16(cs.CipherSuite)
		st.ALPN = cs.NegotiatedProtocol
		st.ServerName = cs.ServerName
		for _, c := range cs.PeerCertificates {
			enc := base64.StdEncoding.EncodeToString(c.Raw)
			st.PeerCertsB64 = append(st.PeerCertsB64, enc)
		}
		if len(st.PeerCertsB64) > 0 {
			st.PeerCertB64 = st.PeerCertsB64[0]
		}
		st.DidResume = cs.DidResume
		if len(cs.OCSPResponse) > 0 {
			st.OCSPB64 = base64.StdEncoding.EncodeToString(cs.OCSPResponse)
		}
		for _, sct := range cs.SignedCertificateTimestamps {
			st.SCTB64 = append(st.SCTB64, base64.StdEncoding.EncodeToString(sct))
		}
		if len(cs.PeerApplicationSettings) > 0 {
			st.ALPSB64 = base64.StdEncoding.EncodeToString(cs.PeerApplicationSettings)
		}
	}
	b, _ := json.Marshal(st)
	return C.CString(string(b))
}

//export freetls_last_error
func freetls_last_error(h C.longlong) (rc *C.char) {
	defer func() {
		if r := recover(); r != nil {
			rc = C.CString("panic")
		}
	}()
	s := getSession(int64(h))
	if s == nil {
		return C.CString("no such session")
	}
	return C.CString(s.lastErr)
}

func tlsVersionName(v uint16) string {
	switch v {
	case utls.VersionTLS13:
		return "TLS1.3"
	case utls.VersionTLS12:
		return "TLS1.2"
	case utls.VersionTLS11:
		return "TLS1.1"
	case utls.VersionTLS10:
		return "TLS1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

func main() {}
