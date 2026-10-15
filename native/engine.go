package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
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
}

type specJSON struct {
	// Preset selects a built-in uTLS ClientHelloID (e.g. "HelloChrome_133").
	// When set, it is used instead of the explicit Extensions list.
	Preset string `json:"preset,omitempty"`
	// Overrides applied to a preset before the handshake.
	PresetNoSNI      bool     `json:"preset_no_sni,omitempty"`
	PresetALPN       []string `json:"preset_alpn,omitempty"`
	PresetALPNRemove bool     `json:"preset_alpn_remove,omitempty"`

	Ciphers     []uint16  `json:"ciphers"`
	Compression []uint8   `json:"compression,omitempty"`
	Extensions  []extJSON `json:"extensions,omitempty"`

	VersMin uint16 `json:"vers_min,omitempty"`
	VersMax uint16 `json:"vers_max,omitempty"`

	Verify     bool   `json:"verify"`
	RootCA     string `json:"root_ca,omitempty"`
	ServerName string `json:"server_name,omitempty"`

	TimeoutMS int `json:"timeout_ms,omitempty"`
}

// presetByName maps uTLS preset names to their ClientHelloIDs. This is the
// authoritative catalogue of real client fingerprints shipped by uTLS.
var presetByName = map[string]utls.ClientHelloID{
	"HelloFirefox_55":                 utls.HelloFirefox_55,
	"HelloFirefox_56":                 utls.HelloFirefox_56,
	"HelloFirefox_63":                 utls.HelloFirefox_63,
	"HelloFirefox_65":                 utls.HelloFirefox_65,
	"HelloFirefox_99":                 utls.HelloFirefox_99,
	"HelloFirefox_102":                utls.HelloFirefox_102,
	"HelloFirefox_105":                utls.HelloFirefox_105,
	"HelloFirefox_120":                utls.HelloFirefox_120,
	"HelloChrome_58":                  utls.HelloChrome_58,
	"HelloChrome_62":                  utls.HelloChrome_62,
	"HelloChrome_70":                  utls.HelloChrome_70,
	"HelloChrome_72":                  utls.HelloChrome_72,
	"HelloChrome_83":                  utls.HelloChrome_83,
	"HelloChrome_87":                  utls.HelloChrome_87,
	"HelloChrome_96":                  utls.HelloChrome_96,
	"HelloChrome_100":                 utls.HelloChrome_100,
	"HelloChrome_102":                 utls.HelloChrome_102,
	"HelloChrome_106_Shuffle":         utls.HelloChrome_106_Shuffle,
	"HelloChrome_100_PSK":             utls.HelloChrome_100_PSK,
	"HelloChrome_112_PSK_Shuf":        utls.HelloChrome_112_PSK_Shuf,
	"HelloChrome_114_Padding_PSK_Shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"HelloChrome_115_PQ":              utls.HelloChrome_115_PQ,
	"HelloChrome_115_PQ_PSK":          utls.HelloChrome_115_PQ_PSK,
	"HelloChrome_120":                 utls.HelloChrome_120,
	"HelloChrome_120_PQ":              utls.HelloChrome_120_PQ,
	"HelloChrome_131":                 utls.HelloChrome_131,
	"HelloChrome_133":                 utls.HelloChrome_133,
	"HelloIOS_11_1":                   utls.HelloIOS_11_1,
	"HelloIOS_12_1":                   utls.HelloIOS_12_1,
	"HelloIOS_13":                     utls.HelloIOS_13,
	"HelloIOS_14":                     utls.HelloIOS_14,
	"HelloAndroid_11_OkHttp":          utls.HelloAndroid_11_OkHttp,
	"HelloEdge_85":                    utls.HelloEdge_85,
	"HelloEdge_106":                   utls.HelloEdge_106,
	"HelloSafari_16_0":                utls.HelloSafari_16_0,
	"Hello360_7_5":                    utls.Hello360_7_5,
	"Hello360_11_0":                   utls.Hello360_11_0,
	"HelloQQ_11_1":                    utls.HelloQQ_11_1,
	"HelloGolang":                     utls.HelloGolang,
	"HelloRandomized":                 utls.HelloRandomized,
	"HelloRandomizedALPN":             utls.HelloRandomizedALPN,
	"HelloRandomizedNoALPN":           utls.HelloRandomizedNoALPN,
}

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
	spec    *utls.ClientHelloSpec
	config  *utls.Config
	tee     *teeConn
	uconn   *utls.UConn
	raw     net.Conn
	preset  string
	noSNI   bool
	alpn    []string
	alpnSet bool
	alpnDel bool
	lastErr string
	timeout time.Duration
}

var (
	regMu    sync.Mutex
	registry = map[int64]*session{}
	nextID   int64 = 1
)

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
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil
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

	cfg := &utls.Config{
		ServerName:         s.ServerName,
		InsecureSkipVerify: !s.Verify,
	}
	if s.Verify && s.RootCA != "" {
		pem, err := os.ReadFile(s.RootCA)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read root_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, nil, nil, errors.New("failed to parse root_ca PEM")
		}
		cfg.RootCAs = pool
	}
	return &s, chs, cfg, nil
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

func (dummyConn) Read(b []byte) (int, error)            { return 0, errors.New("no io") }
func (dummyConn) Write(b []byte) (int, error)           { return 0, errors.New("no io") }
func (dummyConn) Close() error                          { return nil }
func (dummyConn) LocalAddr() net.Addr                   { return nil }
func (dummyConn) RemoteAddr() net.Addr                  { return nil }
func (dummyConn) SetDeadline(time.Time) error           { return nil }
func (dummyConn) SetReadDeadline(time.Time) error       { return nil }
func (dummyConn) SetWriteDeadline(time.Time) error      { return nil }

// freetls_preset_raw builds a preset's ClientHello offline and returns the raw
// handshake message as hex (empty string on error). No network is used.
//
//export freetls_preset_raw
func freetls_preset_raw(name *C.char) *C.char {
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

// freetls_preset_list returns a JSON array of known preset names.
//
//export freetls_preset_list
func freetls_preset_list() *C.char {
	names := make([]string, 0, len(presetByName))
	for k := range presetByName {
		names = append(names, k)
	}
	sort.Strings(names)
	b, _ := json.Marshal(names)
	return C.CString(string(b))
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
func freetls_preset_raw_opts(name *C.char, noSNI C.int, alpnJSON *C.char) *C.char {
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
func freetls_session_new(specJSON *C.char) C.longlong {
	s, chs, cfg, err := parseSpec(C.GoString(specJSON))
	if err != nil {
		return 0
	}
	sess := &session{spec: chs, config: cfg, preset: s.Preset,
		noSNI: s.PresetNoSNI, alpn: s.PresetALPN,
		alpnSet: s.PresetALPN != nil, alpnDel: s.PresetALPNRemove}
	if s.TimeoutMS > 0 {
		sess.timeout = time.Duration(s.TimeoutMS) * time.Millisecond
	}
	id := putSession(sess)
	return C.longlong(id)
}

//export freetls_session_free
func freetls_session_free(h C.longlong) {
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
func freetls_handshake(h C.longlong, fd C.int, sni *C.char) C.int {
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
	if s.preset != "" {
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
func freetls_read(h C.longlong, buf unsafe.Pointer, length C.longlong) C.longlong {
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
func freetls_write(h C.longlong, buf unsafe.Pointer, length C.longlong) C.longlong {
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
	s := getSession(int64(h))
	if s == nil {
		return
	}
	if s.uconn != nil {
		_ = s.uconn.Close()
	}
}

func hexOf(b []byte) *C.char {
	if b == nil {
		return C.CString("")
	}
	return C.CString(hex.EncodeToString(b))
}

//export freetls_get_client_hello
func freetls_get_client_hello(h C.longlong) *C.char {
	s := getSession(int64(h))
	if s == nil || s.tee == nil {
		return C.CString("")
	}
	out, _ := s.tee.captured()
	return hexOf(firstHandshake(out, 1))
}

//export freetls_get_server_hello
func freetls_get_server_hello(h C.longlong) *C.char {
	s := getSession(int64(h))
	if s == nil || s.tee == nil {
		return C.CString("")
	}
	_, in := s.tee.captured()
	return hexOf(firstHandshake(in, 2))
}

type stateJSON struct {
	Version     string `json:"version"`
	CipherSuite uint16 `json:"cipher_suite"`
	ALPN        string `json:"alpn"`
	ServerName  string `json:"server_name"`
	PeerCertB64 string `json:"peer_cert_b64,omitempty"`
	Error       string `json:"error"`
}

//export freetls_get_state
func freetls_get_state(h C.longlong) *C.char {
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
		if len(cs.PeerCertificates) > 0 {
			st.PeerCertB64 = base64.StdEncoding.EncodeToString(cs.PeerCertificates[0].Raw)
		}
	}
	b, _ := json.Marshal(st)
	return C.CString(string(b))
}

//export freetls_last_error
func freetls_last_error(h C.longlong) *C.char {
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
