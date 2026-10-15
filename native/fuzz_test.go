package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// go test -run Fuzz -fuzz FuzzParseSpec ./... seeds these; the corpus grows in
// testdata if `-fuzz` is used. They assert malformed input never panics.

func FuzzParseSpec(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"ciphers":[4865,4866],"extensions":[],"vers_min":771,"vers_max":772}`,
		`{"extensions":[{"type":"generic","id":42,"data":"00ff"}]}`,
		`{"extensions":[{"type":"unknown"}]}`,
		`{"preset":"HelloChrome_133"}`,
		`not json`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, js string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSpec panicked on %q: %v", js, r)
			}
		}()
		_, _, _, _ = parseSpec(js)
	})
}

func FuzzChloJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"extensions":[{"name":"supported_versions","versions":["TLS 1.3"]}]}`,
		`{"cipher_suites":["NOPE"],"extensions":[]}`,
		`[1,2,3]`,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, js string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("safeParseChloJSON panicked on %q: %v", js, r)
			}
		}()
		_, _ = safeParseChloJSON(js)
	})
}

func BenchmarkParseSpec(b *testing.B) {
	raw := map[string]any{
		"ciphers": []int{4865, 4866, 4867, 49196},
		"extensions": []map[string]any{
			{"type": "supported_versions", "values": []int{772, 771}},
			{"type": "supported_curves", "values": []int{29, 23}},
			{"type": "signature_algorithms", "values": []int{1027, 2052}},
			{"type": "key_share", "values": []int{29}},
			{"type": "alpn", "strings": []string{"h2", "http/1.1"}},
		},
		"vers_min": 771,
		"vers_max": 772,
	}
	js, _ := json.Marshal(raw)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := parseSpec(string(js)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSafeParseChloJSON(b *testing.B) {
	doc := []byte(`{
		"cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
		"extensions": [
			{"name": "supported_versions", "versions": ["TLS 1.3", "TLS 1.2"]},
			{"name": "supported_groups", "named_group_list": ["x25519", "secp256r1"]},
			{"name": "key_share", "client_shares": [{"group": "x25519"}]}
		],
		"min_vers": 771, "max_vers": 772
	}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := safeParseChloJSON(string(doc)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFirstHandshakeMalformed(t *testing.T) {
	cases := [][]byte{nil, {0x16}, {0x16, 0x03, 0x03, 0x00, 0x04, 0x01}, bytes.Repeat([]byte{0x16}, 3)}
	for _, c := range cases {
		if got := firstHandshake(c, 1); got != nil && len(got) < 4 {
			t.Fatalf("surprisingly short handshake: %x", got)
		}
	}
}
