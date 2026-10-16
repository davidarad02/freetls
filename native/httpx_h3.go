package main

// HTTP/3 application layer (see docs/route-c-plan.md).
//
// Requests and RFC 9297 datagrams run over the QUIC connection the handshake
// already established, through a single http3.ClientConn. That is deliberate:
// the ClientConn owns the connection's stream accept loop, so a session must
// have exactly one of them (a second would compete for unidirectional streams).
// It also means one quic.Transport and one PacketConn per session.

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
)

type h3RequestSpec struct {
	Method    string      `json:"method"`
	Scheme    string      `json:"scheme"`
	Authority string      `json:"authority"`
	Path      string      `json:"path"`
	Headers   [][2]string `json:"headers,omitempty"`
	BodyB64   string      `json:"body_b64,omitempty"`
	TimeoutMS int         `json:"timeout_ms,omitempty"`
}

type h3Response struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	BodyB64 string      `json:"body_b64"`
	Error   string      `json:"error,omitempty"`
}

// h3Client returns the session's HTTP/3 client connection, building it on first
// use. It wraps the connection the handshake established, so no new socket is
// created and the QUIC/HTTP-3 fingerprints keep coming from the same connection.
func (s *session) h3Client() (*http3.ClientConn, error) {
	if s == nil || s.quic == nil || s.quic.conn == nil {
		return nil, errors.New("no active QUIC session")
	}
	qs := s.quic
	qs.ccOnce.Do(func() {
		tr := &http3.Transport{EnableDatagrams: qs.datagrams}
		qs.cc = tr.NewClientConn(qs.conn)
	})
	return qs.cc, nil
}

// buildH3Request turns the request spec into an *http.Request whose URL carries
// the scheme/authority/path http3 needs (http3 rejects a nil URL, a non-https
// scheme or an empty host).
func buildH3Request(s *session, req h3RequestSpec, body io.Reader) (*http.Request, error) {
	authority := req.Authority
	if authority == "" {
		authority = s.quicAuthority()
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("bad path %q: %w", path, err)
	}
	ref.Scheme = scheme
	ref.Host = authority

	hreq, err := http.NewRequest(req.Method, ref.String(), body)
	if err != nil {
		return nil, err
	}
	hreq.Host = authority
	for _, h := range req.Headers {
		hreq.Header.Add(h[0], h[1])
	}
	return hreq, nil
}

func (s *session) h3Timeout(ms int) time.Duration {
	if ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return s.timeout
}

func doH3(s *session, req h3RequestSpec) (*h3Response, error) {
	cc, err := s.h3Client()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if req.BodyB64 != "" {
		b, err := base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			return nil, fmt.Errorf("body not base64: %w", err)
		}
		body = bytes.NewReader(b)
	}
	hreq, err := buildH3Request(s, req, body)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if timeout := s.h3Timeout(req.TimeoutMS); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	hreq = hreq.WithContext(ctx)

	resp, err := cc.RoundTrip(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	out := &h3Response{
		Status:  resp.StatusCode,
		Headers: [][2]string{},
		BodyB64: base64.StdEncoding.EncodeToString(data),
	}
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			out.Headers = append(out.Headers, [2]string{strings.ToLower(k), v})
		}
	}
	return out, nil
}

//export freetls_h3_request
func freetls_h3_request(h C.longlong, reqJSON *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(h3Response{Error: fmt.Sprintf("panic: %v", r)})
			out = C.CString(string(b))
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.quic == nil {
		return C.CString(`{"error":"no active QUIC session"}`)
	}
	var req h3RequestSpec
	if err := json.Unmarshal([]byte(C.GoString(reqJSON)), &req); err != nil {
		b, _ := json.Marshal(h3Response{Error: err.Error()})
		return C.CString(string(b))
	}
	resp, err := doH3(s, req)
	if err != nil {
		b, _ := json.Marshal(h3Response{Error: err.Error()})
		return C.CString(string(b))
	}
	b, _ := json.Marshal(resp)
	return C.CString(string(b))
}

// ---------------------------------------------------------------------------
// RFC 9297 HTTP/3 datagrams
// ---------------------------------------------------------------------------

// freetls_h3_datagram_open opens a request stream (sending the request headers)
// and returns its flow ID, which the caller uses for send/recv. Datagrams are
// associated with a request stream (RFC 9297), so a flow must be opened first.
//
//export freetls_h3_datagram_open
func freetls_h3_datagram_open(h C.longlong, reqJSON *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(map[string]any{"error": fmt.Sprintf("panic: %v", r)})
			out = C.CString(string(b))
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.quic == nil {
		return C.CString(`{"error":"no active QUIC session"}`)
	}
	if !s.quic.datagrams {
		return C.CString(`{"error":"datagrams are not enabled for this session"}`)
	}
	var req h3RequestSpec
	if err := json.Unmarshal([]byte(C.GoString(reqJSON)), &req); err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	cc, err := s.h3Client()
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	hreq, err := buildH3Request(s, req, nil)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	ctx := context.Background()
	if timeout := s.h3Timeout(req.TimeoutMS); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	if err := str.SendRequestHeader(hreq); err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	flow := uint64(str.StreamID())
	s.quic.dgMu.Lock()
	if s.quic.dg == nil {
		s.quic.dg = map[quic.StreamID]*http3.RequestStream{}
	}
	s.quic.dg[str.StreamID()] = str
	s.quic.dgMu.Unlock()
	b, _ := json.Marshal(map[string]any{"flow": flow})
	return C.CString(string(b))
}

func h3DatagramStream(s *session, flow uint64) (*http3.RequestStream, error) {
	if s == nil || s.quic == nil {
		return nil, errors.New("no active QUIC session")
	}
	s.quic.dgMu.Lock()
	defer s.quic.dgMu.Unlock()
	str, ok := s.quic.dg[quic.StreamID(flow)]
	if !ok {
		return nil, fmt.Errorf("unknown datagram flow %d", flow)
	}
	return str, nil
}

//export freetls_h3_datagram_send
func freetls_h3_datagram_send(h C.longlong, flow C.longlong, dataB64 *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(map[string]any{"error": fmt.Sprintf("panic: %v", r)})
			out = C.CString(string(b))
		}
	}()
	s := getSession(int64(h))
	str, err := h3DatagramStream(s, uint64(flow))
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	data, err := base64.StdEncoding.DecodeString(C.GoString(dataB64))
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": fmt.Sprintf("data not base64: %v", err)})
		return C.CString(string(b))
	}
	if err := str.SendDatagram(data); err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	return C.CString("{}")
}

//export freetls_h3_datagram_recv
func freetls_h3_datagram_recv(h C.longlong, flow C.longlong, timeoutMS C.int) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(map[string]any{"error": fmt.Sprintf("panic: %v", r)})
			out = C.CString(string(b))
		}
	}()
	s := getSession(int64(h))
	str, err := h3DatagramStream(s, uint64(flow))
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	ctx := context.Background()
	if timeout := s.h3Timeout(int(timeoutMS)); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	data, err := str.ReceiveDatagram(ctx)
	if err != nil {
		b, _ := json.Marshal(map[string]any{"error": err.Error()})
		return C.CString(string(b))
	}
	b, _ := json.Marshal(map[string]any{"data_b64": base64.StdEncoding.EncodeToString(data)})
	return C.CString(string(b))
}
