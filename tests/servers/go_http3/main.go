// A minimal local HTTP/3 test server used by the freetls test-suite.
//
// It is built on upstream quic-go (not the uQUIC fork freetls ships), so the
// client is validated against an independent QUIC/TLS implementation. ALPN is
// "h3"; the certificate and key are passed on the command line.
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := os.Args[1]
	cert := os.Args[2]
	key := os.Args[3]

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello-h3 %s", r.Proto)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.Header {
			w.Header().Set("X-Echo-"+k, v[0])
		}
		fmt.Fprint(w, "ok")
	})

	srv := &http3.Server{
		Addr: addr,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		},
		Handler: mux,
	}
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		panic(err)
	}
}
