package main

import (
	"encoding/base64"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestH2WireFingerprint drives doH2 against a raw Framer peer and asserts that
// the SETTINGS values/order, WINDOW_UPDATE increment, and pseudo-header order
// are exactly what the caller requested.
func TestH2WireFingerprint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srvCh <- c
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-srvCh
	defer cli.Close()
	defer srv.Close()

	type captured struct {
		settings []http2.Setting
		window   uint32
		pseudo   []string
	}
	got := make(chan captured, 1)
	errCh := make(chan error, 1)

	go func() {
		// 1. Read the client connection preface.
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(srv, preface); err != nil {
			errCh <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		fr := http2.NewFramer(srv, srv)

		var cap captured
		// 2. SETTINGS.
		f, err := fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		sf, ok := f.(*http2.SettingsFrame)
		if !ok {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		sf.ForeachSetting(func(s http2.Setting) error {
			cap.settings = append(cap.settings, s)
			return nil
		})

		// 3. WINDOW_UPDATE.
		f, err = fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		if wu, ok := f.(*http2.WindowUpdateFrame); ok {
			cap.window = wu.Increment
		}

		// 4. HEADERS (decode HPACK, record field order).
		f, err = fr.ReadFrame()
		if err != nil {
			errCh <- err
			return
		}
		hf, ok := f.(*http2.HeadersFrame)
		if !ok {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
			cap.pseudo = append(cap.pseudo, hf.Name)
		})
		if _, err := dec.Write(hf.HeaderBlockFragment()); err != nil {
			errCh <- err
			return
		}
		got <- cap

		// 5. Reply so the client completes (read all client frames first to
		// avoid deadlocking on the synchronous pipe).
		var buf []byte
		enc := hpack.NewEncoder(&byteWriter{&buf})
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = fr.WriteSettingsAck()
		_ = fr.WriteSettings()
		_ = fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: 1, BlockFragment: buf, EndStream: true, EndHeaders: true,
		})

		// Drain remaining client frames (e.g. its SETTINGS ack).
		for i := 0; i < 4; i++ {
			_ = srv.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := fr.ReadFrame(); err != nil {
				break
			}
		}
	}()

	req := h2RequestSpec{
		Method:       "GET",
		Scheme:       "https",
		Authority:    "example.com",
		Path:         "/",
		Settings:     []h2Setting{{4, 65535}, {1, 4096}, {6, 131072}},
		WindowUpdate: 12345678,
		PseudoOrder:  []string{"method", "authority", "scheme", "path"},
		TimeoutMS:    5000,
	}
	resp, err := doH2(cli, req)
	if err != nil {
		t.Fatalf("doH2: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status = %d, want 200", resp.Status)
	}

	select {
	case cap := <-got:
		wantSettings := []http2.Setting{{ID: 4, Val: 65535}, {ID: 1, Val: 4096}, {ID: 6, Val: 131072}}
		if !reflect.DeepEqual(cap.settings, wantSettings) {
			t.Errorf("settings order/value = %+v, want %+v", cap.settings, wantSettings)
		}
		if cap.window != 12345678 {
			t.Errorf("window update = %d, want 12345678", cap.window)
		}
		wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
		if !reflect.DeepEqual(cap.pseudo, wantPseudo) {
			t.Errorf("pseudo-header order = %v, want %v", cap.pseudo, wantPseudo)
		}
	case err := <-errCh:
		t.Fatalf("server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for captured frames")
	}
	_ = base64.StdEncoding
}

type byteWriter struct{ b *[]byte }

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}
