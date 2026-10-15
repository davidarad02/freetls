package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// ---------------------------------------------------------------------------
// HTTP/2 request model (fully controllable fingerprint)
// ---------------------------------------------------------------------------

type h2Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

type h2RequestSpec struct {
	Method       string      `json:"method"`
	Scheme       string      `json:"scheme"`
	Authority    string      `json:"authority"`
	Path         string      `json:"path"`
	Headers      [][2]string `json:"headers,omitempty"`
	BodyB64      string      `json:"body_b64,omitempty"`
	Settings     []h2Setting `json:"settings,omitempty"`
	WindowUpdate uint32      `json:"window_update,omitempty"`
	PseudoOrder  []string    `json:"pseudo_header_order,omitempty"`
	TimeoutMS    int         `json:"timeout_ms,omitempty"`
}

type h2Response struct {
	Status          int         `json:"status"`
	Headers         [][2]string `json:"headers"`
	BodyB64         string      `json:"body_b64"`
	Error           string      `json:"error,omitempty"`
	SentSettings    []h2Setting `json:"sent_settings"`
	SentWindow      uint32      `json:"sent_window_update"`
	SentPseudoOrder []string    `json:"sent_pseudo_header_order"`
}

// Chrome-like defaults, used when the caller does not supply SETTINGS.
func defaultH2Settings() []h2Setting {
	return []h2Setting{
		{uint16(http2.SettingHeaderTableSize), 65536},
		{uint16(http2.SettingEnablePush), 0},
		{uint16(http2.SettingInitialWindowSize), 6291456},
		{uint16(http2.SettingMaxHeaderListSize), 262144},
	}
}

var validPseudo = map[string]string{
	"method":    ":method",
	"scheme":    ":scheme",
	"authority": ":authority",
	"path":      ":path",
}

// newH2Decoder builds an HPACK decoder whose dynamic table is sized to match
// the HEADER_TABLE_SIZE we advertise in SETTINGS. Without this a peer may send
// a dynamic table size update up to the advertised value and the decoder would
// reject it as "too large".
func newH2Decoder(maxTableSize uint32, emit func(hpack.HeaderField)) *hpack.Decoder {
	d := hpack.NewDecoder(maxTableSize, emit)
	d.SetMaxDynamicTableSize(maxTableSize)
	d.SetAllowedMaxDynamicTableSize(maxTableSize)
	return d
}

func doH2(conn net.Conn, req h2RequestSpec) (*h2Response, error) {
	resp := &h2Response{Headers: [][2]string{}}
	var bodyBuf []byte

	// Resolve effective settings / window / pseudo order.
	settings := req.Settings
	if len(settings) == 0 {
		settings = defaultH2Settings()
	}
	order := req.PseudoOrder
	if len(order) == 0 {
		order = []string{"method", "scheme", "authority", "path"}
	}
	for _, p := range order {
		if _, ok := validPseudo[p]; !ok {
			return nil, fmt.Errorf("unknown pseudo-header %q", p)
		}
	}
	resp.SentSettings = settings
	resp.SentWindow = req.WindowUpdate
	resp.SentPseudoOrder = order

	// The HPACK decoder must allow a dynamic table at least as large as the
	// HEADER_TABLE_SIZE we advertise, or a compliant peer's size update (which
	// may grow up to the advertised value) is rejected as "too large".
	headerTableSize := uint32(4096)
	for _, s := range settings {
		if s.ID == uint16(http2.SettingHeaderTableSize) {
			headerTableSize = s.Value
		}
	}

	if req.TimeoutMS > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(req.TimeoutMS) * time.Millisecond))
		defer conn.SetDeadline(time.Time{})
	}

	fr := http2.NewFramer(conn, conn)

	// 1. Client preface.
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}
	// 2. SETTINGS (in the order requested).
	sets := make([]http2.Setting, 0, len(settings))
	for _, s := range settings {
		sets = append(sets, http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value})
	}
	if err := fr.WriteSettings(sets...); err != nil {
		return nil, err
	}
	// 3. Connection WINDOW_UPDATE.
	if req.WindowUpdate > 0 {
		if err := fr.WriteWindowUpdate(0, req.WindowUpdate); err != nil {
			return nil, err
		}
	}

	// 4. HEADERS (HPACK), pseudo-headers in the requested order.
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	pseudo := map[string]string{
		"method":    req.Method,
		"scheme":    req.Scheme,
		"authority": req.Authority,
		"path":      req.Path,
	}
	for _, p := range order {
		if err := enc.WriteField(hpack.HeaderField{Name: validPseudo[p], Value: pseudo[p]}); err != nil {
			return nil, err
		}
	}
	for _, h := range req.Headers {
		if err := enc.WriteField(hpack.HeaderField{
			Name: strings.ToLower(h[0]), Value: h[1],
		}); err != nil {
			return nil, err
		}
	}
	body, err := base64.StdEncoding.DecodeString(req.BodyB64)
	if err != nil {
		return nil, err
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     len(body) == 0,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}
	if len(body) > 0 {
		if err := fr.WriteData(1, true, body); err != nil {
			return nil, err
		}
	}

	// 5. Read frames until the stream ends.
	dec := newH2Decoder(headerTableSize, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			fmt.Sscanf(f.Value, "%d", &resp.Status)
		} else {
			resp.Headers = append(resp.Headers, [2]string{f.Name, f.Value})
		}
	})
	done := false
	for !done {
		f, err := fr.ReadFrame()
		if err != nil {
			if resp.Status != 0 {
				break
			}
			return nil, err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
				return nil, err
			}
			if f.StreamEnded() {
				done = true
			}
		case *http2.ContinuationFrame:
			if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
				return nil, err
			}
		case *http2.DataFrame:
			if n := len(f.Data()); n > 0 {
				bodyBuf = append(bodyBuf, f.Data()...)
				_ = fr.WriteWindowUpdate(0, uint32(n))
				_ = fr.WriteWindowUpdate(1, uint32(n))
			}
			if f.StreamEnded() {
				done = true
			}
		case *http2.GoAwayFrame:
			done = true
		}
	}
	resp.BodyB64 = base64.StdEncoding.EncodeToString(bodyBuf)
	return resp, nil
}

//export freetls_h2_request
func freetls_h2_request(h C.longlong, reqJSON *C.char) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			b, _ := json.Marshal(h2Response{Error: fmt.Sprintf("panic: %v", r)})
			out = C.CString(string(b))
		}
	}()
	s := getSession(int64(h))
	if s == nil || s.uconn == nil {
		return C.CString(`{"error":"no active session"}`)
	}
	var req h2RequestSpec
	if err := json.Unmarshal([]byte(C.GoString(reqJSON)), &req); err != nil {
		b, _ := json.Marshal(h2Response{Error: err.Error()})
		return C.CString(string(b))
	}
	resp, err := doH2(s.uconn, req)
	if err != nil {
		b, _ := json.Marshal(h2Response{Error: err.Error()})
		return C.CString(string(b))
	}
	b, _ := json.Marshal(resp)
	return C.CString(string(b))
}
