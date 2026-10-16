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

const h2DefaultWindow = 65535

// h2Client is the persistent state of one HTTP/2 connection: the framer, the
// shared HPACK contexts (so a connection can serve many requests), the
// stream-ID counter and the send flow-control windows.
type h2Client struct {
	conn          net.Conn
	fr            *http2.Framer
	dec           *hpack.Decoder
	enc           *hpack.Encoder
	encBuf        bytes.Buffer
	nextStream    uint32
	maxFrameSize  uint32
	connWindow    int64
	streamWindow  map[uint32]int64
	peerInitWin   int64
	peerSettings  bool
	sentSettings  []h2Setting
	sentWindow    uint32

	// per-request state
	resp      *h2Response
	bodyBuf   []byte
	streamDone bool
}

func newH2Client(conn net.Conn) *h2Client {
	return &h2Client{
		conn:         conn,
		maxFrameSize: 16384, // RFC 7540 §6.5.2: peers may not advertise less.
		connWindow:   h2DefaultWindow,
		streamWindow: map[uint32]int64{},
		peerInitWin:  h2DefaultWindow,
		nextStream:   1,
	}
}

// start sends the connection preface, SETTINGS and the connection
// WINDOW_UPDATE. It runs once per connection.
func (c *h2Client) start(settings []h2Setting, windowUpdate uint32) error {
	c.fr = http2.NewFramer(c.conn, c.conn)
	if _, err := c.conn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}
	sets := make([]http2.Setting, 0, len(settings))
	headerTableSize := uint32(4096)
	for _, s := range settings {
		sets = append(sets, http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value})
		if s.ID == uint16(http2.SettingHeaderTableSize) {
			headerTableSize = s.Value
		}
	}
	if err := c.fr.WriteSettings(sets...); err != nil {
		return err
	}
	if windowUpdate > 0 {
		if err := c.fr.WriteWindowUpdate(0, windowUpdate); err != nil {
			return err
		}
	}
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.dec = newH2Decoder(headerTableSize, func(f hpack.HeaderField) {
		if c.resp == nil {
			return
		}
		if f.Name == ":status" {
			fmt.Sscanf(f.Value, "%d", &c.resp.Status)
		} else {
			c.resp.Headers = append(c.resp.Headers, [2]string{f.Name, f.Value})
		}
	})
	c.sentSettings = settings
	c.sentWindow = windowUpdate
	return nil
}

// handle processes one inbound frame, updating flow-control windows and the
// response being read. It returns an error only when the peer aborts the
// request (RST_STREAM / GOAWAY) before a response status was seen.
func (c *h2Client) handle(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			return nil
		}
		_ = f.ForeachSetting(func(s http2.Setting) error {
			switch s.ID {
			case http2.SettingMaxFrameSize:
				c.maxFrameSize = s.Val
			case http2.SettingInitialWindowSize:
				delta := int64(s.Val) - c.peerInitWin
				c.peerInitWin = int64(s.Val)
				for id := range c.streamWindow {
					c.streamWindow[id] += delta
				}
			}
			return nil
		})
		c.peerSettings = true
		return c.fr.WriteSettingsAck()
	case *http2.PingFrame:
		if !f.IsAck() {
			return c.fr.WritePing(true, f.Data)
		}
	case *http2.WindowUpdateFrame:
		if f.StreamID == 0 {
			c.connWindow += int64(f.Increment)
		} else {
			c.streamWindow[f.StreamID] += int64(f.Increment)
		}
	case *http2.HeadersFrame:
		if c.resp == nil {
			return nil
		}
		if _, err := c.dec.Write(f.HeaderBlockFragment()); err != nil {
			return err
		}
		if f.StreamEnded() {
			c.streamDone = true
		}
	case *http2.ContinuationFrame:
		if _, err := c.dec.Write(f.HeaderBlockFragment()); err != nil {
			return err
		}
	case *http2.DataFrame:
		if c.resp == nil {
			return nil
		}
		if n := len(f.Data()); n > 0 {
			c.bodyBuf = append(c.bodyBuf, f.Data()...)
			_ = c.fr.WriteWindowUpdate(0, uint32(n))
			_ = c.fr.WriteWindowUpdate(f.StreamID, uint32(n))
		}
		if f.StreamEnded() {
			c.streamDone = true
		}
	case *http2.RSTStreamFrame:
		if c.resp != nil && c.resp.Status == 0 {
			return fmt.Errorf("HTTP/2 stream reset by peer (code 0x%x)", f.ErrCode)
		}
		c.streamDone = true
	case *http2.GoAwayFrame:
		if c.resp != nil && c.resp.Status == 0 {
			return fmt.Errorf("HTTP/2 connection closed by peer (GOAWAY code 0x%x)", f.ErrCode)
		}
		c.streamDone = true
	}
	return nil
}

// readFrame reads and handles one frame.
func (c *h2Client) readFrame() error {
	f, err := c.fr.ReadFrame()
	if err != nil {
		return err
	}
	return c.handle(f)
}

func doH2(conn net.Conn, holder **h2Client, req h2RequestSpec) (*h2Response, error) {
	resp := &h2Response{Headers: [][2]string{}}

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

	if conn == nil {
		return nil, fmt.Errorf("no active session")
	}
	if req.TimeoutMS > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(req.TimeoutMS) * time.Millisecond))
		defer conn.SetDeadline(time.Time{})
	}

	if *holder == nil {
		c := newH2Client(conn)
		if err := c.start(settings, req.WindowUpdate); err != nil {
			return nil, err
		}
		*holder = c
	}
	c := *holder
	c.sentSettings = settings
	if req.WindowUpdate > 0 {
		c.sentWindow = req.WindowUpdate
	}
	resp.SentSettings = c.sentSettings
	resp.SentWindow = c.sentWindow
	resp.SentPseudoOrder = order

	streamID := c.nextStream
	c.nextStream += 2
	c.streamWindow[streamID] = c.peerInitWin
	c.resp = resp
	c.bodyBuf = nil
	c.streamDone = false

	// HEADERS (HPACK), pseudo-headers in the requested order.
	c.encBuf.Reset()
	pseudo := map[string]string{
		"method":    req.Method,
		"scheme":    req.Scheme,
		"authority": req.Authority,
		"path":      req.Path,
	}
	for _, p := range order {
		if err := c.enc.WriteField(hpack.HeaderField{Name: validPseudo[p], Value: pseudo[p]}); err != nil {
			return nil, err
		}
	}
	for _, h := range req.Headers {
		if err := c.enc.WriteField(hpack.HeaderField{Name: strings.ToLower(h[0]), Value: h[1]}); err != nil {
			return nil, err
		}
	}
	body, err := base64.StdEncoding.DecodeString(req.BodyB64)
	if err != nil {
		return nil, err
	}
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: c.encBuf.Bytes(),
		EndStream:     len(body) == 0,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}

	// Send the body within the peer's flow-control window, splitting at its
	// maximum frame size and reading WINDOW_UPDATE / SETTINGS as needed.
	remaining := body
	for len(remaining) > 0 && !c.streamDone {
		for c.connWindow <= 0 || c.streamWindow[streamID] <= 0 {
			if err := c.readFrame(); err != nil {
				return nil, err
			}
			if c.streamDone {
				break
			}
		}
		if c.streamDone {
			break
		}
		n := int64(len(remaining))
		if n > int64(c.maxFrameSize) {
			n = int64(c.maxFrameSize)
		}
		if n > c.connWindow {
			n = c.connWindow
		}
		if w := c.streamWindow[streamID]; n > w {
			n = w
		}
		end := int64(len(remaining)) == n
		if err := c.fr.WriteData(streamID, end, remaining[:n]); err != nil {
			return nil, err
		}
		c.connWindow -= n
		c.streamWindow[streamID] -= n
		remaining = remaining[n:]
	}

	// Read frames until the stream ends.
	for !c.streamDone {
		if err := c.readFrame(); err != nil {
			return nil, err
		}
	}
	resp.BodyB64 = base64.StdEncoding.EncodeToString(c.bodyBuf)
	c.resp = nil
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
	resp, err := doH2(s.uconn, &s.h2, req)
	if err != nil {
		b, _ := json.Marshal(h2Response{Error: err.Error()})
		return C.CString(string(b))
	}
	b, _ := json.Marshal(resp)
	return C.CString(string(b))
}
