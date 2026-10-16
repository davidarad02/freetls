package main

// QUIC / HTTP-3 engine side (see docs/route-c-plan.md).
//
// The TLS handshake for QUIC is driven by the uQUIC fork (a hard fork of
// quic-go built against our uTLS fork), which emits the Initial flight described
// by a QUICSpec. Python owns the UDP socket and passes a dup'd fd, exactly as
// the TCP path does; here it is wrapped with net.FilePacketConn.

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

// reservedQuicTPIDs are the transport-parameter ids the QUIC stack switches on.
// A `fake` parameter with one of these ids would be misinterpreted (uQUIC's
// PopulateFromUQUIC type-asserts on them, which panics for a fake), so it is
// rejected in favour of the typed kind.
var reservedQuicTPIDs = map[uint64]bool{
	0x01: true, // max_idle_timeout
	0x04: true, // initial_max_data
	0x05: true, // initial_max_stream_data_bidi_local
	0x06: true, // initial_max_stream_data_bidi_remote
	0x07: true, // initial_max_stream_data_uni
	0x08: true, // initial_max_streams_bidi
	0x09: true, // initial_max_streams_uni
	0x0b: true, // max_ack_delay
	0x0c: true, // disable_active_migration
	0x0e: true, // active_connection_id_limit
	0x0f: true, // initial_source_connection_id
	0x20: true, // max_datagram_frame_size
}

// tpJSON is one QUIC transport parameter, carried in the ClientHello's ext 57.
type tpJSON struct {
	Kind     string   `json:"kind"`
	ID       *uint64  `json:"id,omitempty"`
	Value    *uint64  `json:"value,omitempty"`
	Data     string   `json:"data,omitempty"` // hex
	Length   uint16   `json:"length,omitempty"`
	Versions []uint32 `json:"versions,omitempty"`
	Legacy   bool     `json:"legacy,omitempty"`
}

// quicInitialJSON is the QUIC Initial packet shape around the ClientHello.
type quicInitialJSON struct {
	Version                      uint32   `json:"version"`
	DCIDLen                      int      `json:"dcid_len"`
	SCIDLen                      int      `json:"scid_len"`
	Token                        string   `json:"token,omitempty"` // hex
	UDPDatagramMinSize           int      `json:"udp_datagram_min_size"`
	PacketNumber                 uint64   `json:"packet_number"`
	PacketNumberLen              int      `json:"packet_number_len"`
	RandomizeTransportParameters bool     `json:"randomize_transport_parameters,omitempty"`
	SuppressTransportParameters  []uint64 `json:"suppress_transport_parameters,omitempty"`
}

// quicState holds the live QUIC resources for a session.
type quicState struct {
	pc        net.PacketConn
	tr        *quic.UTransport
	conn      *quic.Conn
	spec      *quic.QUICSpec
	remote    net.Addr
	datagrams bool
	// cc is the HTTP/3 client connection, built lazily on the first request. It
	// owns every stream (requests and datagrams) over this session's single QUIC
	// connection, so there is exactly one quic.Transport/PacketConn.
	cc     *http3.ClientConn
	ccOnce sync.Once
	ccMu   sync.Mutex
	// dg holds the request streams opened for RFC 9297 datagram flows, keyed by
	// their stream ID.
	dgMu sync.Mutex
	dg   map[quic.StreamID]*http3.RequestStream
}

// clientConn returns the session's HTTP/3 ClientConn under its lock, so a
// concurrent close() cannot race the pointer read/write.
func (qs *quicState) clientConn() *http3.ClientConn {
	qs.ccMu.Lock()
	defer qs.ccMu.Unlock()
	return qs.cc
}

// quicPtr returns the session's QUIC state under the session lock, so a
// concurrent close() from another thread cannot race the pointer read.
func (s *session) quicPtr() *quicState {
	s.quicMu.RLock()
	defer s.quicMu.RUnlock()
	return s.quic
}

func hexOrEmpty(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	return b, nil
}

func derefU64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// buildTransportParameters maps the Python transport-parameter list onto uTLS's
// typed TransportParameters, preserving wire order (itself a fingerprint).
func buildTransportParameters(in []tpJSON) (utls.TransportParameters, error) {
	out := make(utls.TransportParameters, 0, len(in))
	for i, p := range in {
		tp, err := buildTransportParameter(p)
		if err != nil {
			return nil, fmt.Errorf("transport_parameters[%d]: %w", i, err)
		}
		out = append(out, tp)
	}
	return out, nil
}

func buildTransportParameter(p tpJSON) (utls.TransportParameter, error) {
	switch p.Kind {
	case "max_idle_timeout":
		return utls.MaxIdleTimeout(derefU64(p.Value)), nil
	case "max_udp_payload_size":
		return utls.MaxUDPPayloadSize(derefU64(p.Value)), nil
	case "initial_max_data":
		return utls.InitialMaxData(derefU64(p.Value)), nil
	case "initial_max_stream_data_bidi_local":
		return utls.InitialMaxStreamDataBidiLocal(derefU64(p.Value)), nil
	case "initial_max_stream_data_bidi_remote":
		return utls.InitialMaxStreamDataBidiRemote(derefU64(p.Value)), nil
	case "initial_max_stream_data_uni":
		return utls.InitialMaxStreamDataUni(derefU64(p.Value)), nil
	case "initial_max_streams_bidi":
		return utls.InitialMaxStreamsBidi(derefU64(p.Value)), nil
	case "initial_max_streams_uni":
		return utls.InitialMaxStreamsUni(derefU64(p.Value)), nil
	case "max_ack_delay":
		return utls.MaxAckDelay(derefU64(p.Value)), nil
	case "active_connection_id_limit":
		return utls.ActiveConnectionIDLimit(derefU64(p.Value)), nil
	case "max_datagram_frame_size":
		return utls.MaxDatagramFrameSize(derefU64(p.Value)), nil
	case "disable_active_migration":
		return &utls.DisableActiveMigration{}, nil
	case "grease_quic_bit":
		return &utls.GREASEQUICBit{}, nil
	case "initial_source_connection_id":
		b, err := hexOrEmpty(p.Data)
		if err != nil {
			return nil, err
		}
		return utls.InitialSourceConnectionID(b), nil
	case "version_information":
		avail := make([]uint32, len(p.Versions))
		copy(avail, p.Versions)
		return &utls.VersionInformation{
			ChoosenVersion:    uint32(derefU64(p.Value)),
			AvailableVersions: avail,
			LegacyID:          p.Legacy,
		}, nil
	case "grease":
		return &utls.GREASETransportParameter{Length: p.Length}, nil
	case "padding":
		b, err := hexOrEmpty(p.Data)
		if err != nil {
			return nil, err
		}
		return utls.PaddingTransportParameter(b), nil
	case "fake":
		if p.ID == nil || *p.ID == 0 {
			return nil, errors.New("fake transport parameter requires a non-zero id")
		}
		if reservedQuicTPIDs[*p.ID] {
			return nil, fmt.Errorf(
				"transport parameter id 0x%x is handled by the QUIC stack; use the typed kind instead of fake",
				*p.ID,
			)
		}
		b, err := hexOrEmpty(p.Data)
		if err != nil {
			return nil, err
		}
		return &utls.FakeQUICTransportParameter{Id: *p.ID, Val: b}, nil
	default:
		return nil, fmt.Errorf("unknown transport parameter kind %q", p.Kind)
	}
}

// applyQuicInitial overlays the caller's Initial-packet shape onto a spec. A
// nil override leaves the spec's own shape alone, which is what a uQUIC preset
// needs: its Initial flight is part of the fingerprint.
func applyQuicInitial(spec *quic.QUICSpec, qi *quicInitialJSON) error {
	if qi == nil {
		return nil
	}
	spec.UDPDatagramMinSize = qi.UDPDatagramMinSize
	spec.RandomizeTransportParameters = qi.RandomizeTransportParameters
	spec.SuppressTransportParameters = qi.SuppressTransportParameters
	spec.InitialPacketSpec = quic.InitialPacketSpec{
		SrcConnIDLength:  qi.SCIDLen,
		DestConnIDLength: qi.DCIDLen,
		InitPacketNumber: qi.PacketNumber,
	}
	if qi.PacketNumberLen > 0 {
		spec.InitialPacketSpec.InitPacketNumberLengths = []quic.PacketNumberLen{
			quic.PacketNumberLen(qi.PacketNumberLen),
		}
	}
	if qi.Token != "" {
		b, err := hex.DecodeString(qi.Token)
		if err != nil {
			return fmt.Errorf("token not hex: %w", err)
		}
		spec.InitialPacketSpec.ClientTokenPrefix = b
		spec.InitialPacketSpec.ClientTokenLength = len(b)
	}
	return nil
}

// marshalClientHello builds the exact ClientHello bytes a ClientHelloSpec
// produces, offline. uQUIC feeds the same spec to uTLS's UQUICClient, so these
// are the bytes that go into the Initial packet's CRYPTO frame — which is what
// the reported JA4q is computed from.
//
// cfg must be the config the handshake will use: uTLS fills an empty SNI
// extension from config.ServerName, so using a different ServerName here would
// report an SNI the wire does not carry (e.g. connecting by IP). The config is
// cloned because UClient does not clone it and ApplyPreset mutates ServerName.
func marshalClientHello(chs *utls.ClientHelloSpec, cfg *utls.Config) ([]byte, error) {
	if cfg == nil {
		cfg = &utls.Config{}
	}
	uconn := utls.UClient(dummyConn{}, cfg.Clone(), utls.HelloCustom)
	if err := uconn.ApplyPreset(chs); err != nil {
		return nil, err
	}
	// QUIC carries no legacy_session_id (RFC 9001 §8.4). ApplyPreset only skips
	// it for a QUIC UConn, and this is a plain UClient, so clear it explicitly to
	// match the emitted bytes.
	uconn.HandshakeState.Hello.SessionId = nil
	if err := uconn.MarshalClientHello(); err != nil {
		return nil, err
	}
	return uconn.HandshakeState.Hello.Raw, nil
}

func stripSNIFromSpec(chs *utls.ClientHelloSpec) {
	out := make([]utls.TLSExtension, 0, len(chs.Extensions))
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			continue
		}
		out = append(out, e)
	}
	chs.Extensions = out
}

func setALPNOnSpec(chs *utls.ClientHelloSpec, protocols []string) {
	out := make([]utls.TLSExtension, 0, len(chs.Extensions)+1)
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.ALPNExtension); ok {
			continue
		}
		out = append(out, e)
	}
	if len(protocols) > 0 {
		out = append(out, &utls.ALPNExtension{AlpnProtocols: protocols})
	}
	chs.Extensions = out
}

// closeQUIC releases a session's QUIC resources. Safe to call on a session that
// never ran a QUIC handshake.
func closeQUIC(s *session) {
	if s == nil {
		return
	}
	s.quicMu.Lock()
	qs := s.quic
	s.quic = nil
	s.quicMu.Unlock()
	if qs == nil {
		return
	}
	if cc := qs.clientConn(); cc != nil {
		_ = cc.CloseWithError(0, "")
	}
	if qs.conn != nil {
		_ = qs.conn.CloseWithError(0, "")
	}
	if qs.pc != nil {
		_ = qs.pc.Close()
	}
}

// quicAuthority returns the peer's host:port for the :authority pseudo-header.
func (s *session) quicAuthority() string {
	if s == nil {
		return ""
	}
	qs := s.quicPtr()
	if qs == nil || qs.remote == nil {
		return ""
	}
	return qs.remote.String()
}

// quicRemoteAddr builds the peer address. Python resolves the host and passes
// the literal IP, so no name resolution happens here.
//
// The UDP socket must NOT be connected: Go's net.UDPConn.WriteTo refuses on a
// pre-connected socket ("use of WriteTo with pre-connected connection"), which
// is how quic-go sends. Python therefore hands over a plain bound socket.
func quicRemoteAddr(host string, port int) (net.Addr, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("quic host must be a literal IP, got %q", host)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid quic port %d", port)
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// ensureInitialSourceCID guarantees the ClientHello carries
// initial_source_connection_id (0x0f).
//
// RFC 9000 §7.3 requires the client's Initial to send it, and a conformant
// server silently drops an Initial that omits it — so the symptom is a
// handshake that never completes rather than an error. uQUIC's own default
// ClientHello includes it, but an explicit ClientHelloSpec must. It is only
// appended when absent, and left alone when the caller explicitly suppresses
// the parameter, so a spec can still reproduce a client that omits it.
//
// Appending it does not change JA4q: JA4 hashes extension *type* IDs, and this
// is a parameter inside extension 57, not a new extension.
func ensureInitialSourceCID(spec *quic.QUICSpec) error {
	if spec.ClientHelloSpec == nil {
		return errors.New("quic spec requires a ClientHello")
	}
	for _, e := range spec.ClientHelloSpec.Extensions {
		qtp, ok := e.(*utls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		for _, p := range qtp.TransportParameters {
			if _, ok := p.(utls.InitialSourceConnectionID); ok {
				return nil
			}
			if fp, ok := p.(*utls.FakeQUICTransportParameter); ok && fp.Id == 0x0f {
				return nil
			}
		}
		for _, id := range spec.SuppressTransportParameters {
			if id == 0x0f {
				return nil
			}
		}
		qtp.TransportParameters = append(qtp.TransportParameters, utls.InitialSourceConnectionID{})
		return nil
	}
	return errors.New("quic ClientHello must contain a quic_transport_parameters extension")
}

// ensureMaxDatagramFrameSize guarantees the ClientHello's QUIC transport
// parameters advertise max_datagram_frame_size (0x20) when HTTP/3 datagrams are
// enabled.
//
// uQUIC takes the transport parameters from the ClientHelloSpec, so setting
// quic.Config.EnableDatagrams is not enough: without this parameter on the wire
// the peer sees a client that does not support QUIC datagrams and closes the
// connection with "missing QUIC Datagram support" (HTTP/3 SETTINGS error).
// Like initial_source_connection_id it lives inside extension 57, so it does not
// change JA4q.
func ensureMaxDatagramFrameSize(spec *quic.QUICSpec) error {
	if spec.ClientHelloSpec == nil {
		return errors.New("quic spec requires a ClientHello")
	}
	for _, e := range spec.ClientHelloSpec.Extensions {
		qtp, ok := e.(*utls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		for _, p := range qtp.TransportParameters {
			if _, ok := p.(utls.MaxDatagramFrameSize); ok {
				return nil
			}
			if fp, ok := p.(*utls.FakeQUICTransportParameter); ok && fp.Id == 0x20 {
				return nil
			}
		}
		for _, id := range spec.SuppressTransportParameters {
			if id == 0x20 {
				return nil
			}
		}
		qtp.TransportParameters = append(qtp.TransportParameters, utls.MaxDatagramFrameSize(65536))
		return nil
	}
	return errors.New("quic ClientHello must contain a quic_transport_parameters extension")
}

// quicSpecFor returns the uQUIC spec for the session: a built-in preset (whose
// Initial flight is part of the fingerprint, so only explicit overrides replace
// it), or one assembled from the session's own ClientHello plus Initial shape.
func quicSpecFor(s *session) (*quic.QUICSpec, error) {
	var spec *quic.QUICSpec
	if s.quicID != "" {
		id, ok := quicIDByName[s.quicID]
		if !ok {
			return nil, fmt.Errorf("unknown QUIC preset %q", s.quicID)
		}
		built, err := quic.QUICID2Spec(id)
		if err != nil {
			return nil, fmt.Errorf("QUIC preset %q: %w", s.quicID, err)
		}
		spec = &built
		if spec.ClientHelloSpec == nil {
			return nil, fmt.Errorf("QUIC preset %q has no ClientHello", s.quicID)
		}
		if s.noSNI {
			stripSNIFromSpec(spec.ClientHelloSpec)
		}
		if s.alpnSet || s.alpnDel {
			setALPNOnSpec(spec.ClientHelloSpec, s.alpn)
		}
	} else {
		if s.spec == nil {
			return nil, errors.New("quic spec requires a ClientHello")
		}
		spec = &quic.QUICSpec{ClientHelloSpec: s.spec}
	}
	if err := applyQuicInitial(spec, s.qinit); err != nil {
		return nil, err
	}
	if err := ensureInitialSourceCID(spec); err != nil {
		return nil, err
	}
	if s.quicDgram {
		if err := ensureMaxDatagramFrameSize(spec); err != nil {
			return nil, err
		}
	}
	return spec, nil
}

// freetls_quic_handshake runs the QUIC handshake over the UDP socket whose fd
// Python passed (a dup of its connected socket).
//
//export freetls_quic_handshake
func freetls_quic_handshake(h C.longlong, fd C.int, sni *C.char, host *C.char, port C.int) (rc C.int) {
	var pc net.PacketConn
	defer func() {
		if r := recover(); r != nil {
			if pc != nil {
				_ = pc.Close()
			}
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
	f := os.NewFile(uintptr(fd), "freetls-udp-fd")
	if f == nil {
		cErr(s, errors.New("bad fd"))
		return -2
	}
	var err error
	pc, err = net.FilePacketConn(f)
	_ = f.Close() // FilePacketConn dups the fd; close our wrapper/dup
	if err != nil {
		cErr(s, fmt.Errorf("FilePacketConn: %w", err))
		return -3
	}
	remote, err := quicRemoteAddr(C.GoString(host), int(port))
	if err != nil {
		_ = pc.Close()
		cErr(s, err)
		return -4
	}
	qspec, err := quicSpecFor(s)
	if err != nil {
		_ = pc.Close()
		cErr(s, err)
		return -5
	}
	if raw, err := marshalClientHello(qspec.ClientHelloSpec, s.config); err == nil {
		s.quicCH = raw
	} else {
		cErr(s, fmt.Errorf("marshal quic ClientHello: %w", err))
		_ = pc.Close()
		return -7
	}

	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultQUICTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	qcfg := &quic.Config{EnableDatagrams: s.quicDgram}
	// QuicInitialSpec.version selects the QUIC version (v1 by default).
	if s.qinit != nil && s.qinit.Version != 0 {
		qcfg.Versions = []quic.Version{quic.Version(s.qinit.Version)}
	}

	tr := &quic.UTransport{Transport: &quic.Transport{Conn: pc}, QUICSpec: qspec}
	conn, err := dialQUIC(ctx, tr, remote, s.config, pc, qcfg)
	if err != nil {
		_ = pc.Close()
		cErr(s, err)
		return -8
	}
	s.quicSH = conn.FreetlsServerHello()
	s.quicMu.Lock()
	s.quic = &quicState{pc: pc, tr: tr, conn: conn, spec: qspec, remote: remote, datagrams: s.quicDgram}
	s.quicMu.Unlock()
	return 0
}

// defaultQUICTimeout bounds a handshake whose spec leaves timeout_ms at 0.
const defaultQUICTimeout = 30 * time.Second

// dialQUIC runs UTransport.Dial under the engine's own deadline.
//
// uQUIC's Dial does not return when the peer never answers if the spec carries
// a custom ClientHelloSpec: its handshake-idle-timeout path never fires, so the
// call blocks indefinitely. (With the default ClientHello it does time out.)
// The engine therefore enforces the deadline itself and closes the socket to
// release the dial. Reported upstream behaviour is otherwise unchanged.
func dialQUIC(
	ctx context.Context, tr *quic.UTransport, remote net.Addr, cfg *utls.Config,
	pc net.PacketConn, qcfg *quic.Config,
) (*quic.Conn, error) {
	type result struct {
		conn *quic.Conn
		err  error
	}
	if qcfg == nil {
		qcfg = &quic.Config{}
	}
	resc := make(chan result, 1)
	go func() {
		// A panic anywhere in the uQUIC dial (e.g. an unchecked type assertion
		// on a malformed transport parameter) would otherwise abort the host
		// process, since this goroutine is outside the export's recover().
		defer func() {
			if r := recover(); r != nil {
				resc <- result{err: fmt.Errorf("quic dial panic: %v", r)}
			}
		}()
		c, err := tr.Dial(ctx, remote, cfg, qcfg)
		resc <- result{c, err}
	}()
	select {
	case r := <-resc:
		if r.err != nil {
			return nil, fmt.Errorf("quic handshake: %w", r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		_ = pc.Close() // unblock the dial goroutine; it discards its result
		return nil, fmt.Errorf("quic handshake: %w", ctx.Err())
	}
}

// freetls_quic_id_list returns the built-in uQUIC preset names as JSON.
//
//export freetls_quic_id_list
func freetls_quic_id_list() (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			out = C.CString("[]")
		}
	}()
	names := make([]string, 0, len(quicIDNames))
	names = append(names, quicIDNames...)
	b, err := json.Marshal(names)
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(b))
}

// freetls_quic_id_raw builds a uQUIC preset's ClientHello offline and returns it
// as hex (empty on error). No network is used.
//
//export freetls_quic_id_raw
func freetls_quic_id_raw(name *C.char, noSNI C.int, alpnJSON *C.char) (out *C.char) {
	auxErr = ""
	defer func() {
		if r := recover(); r != nil {
			auxErr = fmt.Sprintf("panic: %v", r)
			out = C.CString("")
		}
	}()
	id, ok := quicIDByName[C.GoString(name)]
	if !ok {
		auxErr = fmt.Sprintf("unknown QUIC preset %q", C.GoString(name))
		return C.CString("")
	}
	qspec, err := quic.QUICID2Spec(id)
	if err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	chs := qspec.ClientHelloSpec
	if chs == nil {
		auxErr = "preset has no ClientHello"
		return C.CString("")
	}
	if noSNI != 0 {
		stripSNIFromSpec(chs)
	}
	if alpnJSON != nil && C.GoString(alpnJSON) != "" {
		var protocols []string
		if err := json.Unmarshal([]byte(C.GoString(alpnJSON)), &protocols); err != nil {
			auxErr = fmt.Sprintf("alpn json: %v", err)
			return C.CString("")
		}
		setALPNOnSpec(chs, protocols)
	}
	raw, err := marshalClientHello(chs, &utls.Config{ServerName: "example.com"})
	if err != nil {
		auxErr = err.Error()
		return C.CString("")
	}
	return hexOf(raw)
}
