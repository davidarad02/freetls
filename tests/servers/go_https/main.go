// A minimal local HTTPS test server used by the freetls test-suite.
//
// It serves HTTP/1.1 and HTTP/2 (ALPN "h2") so freetls can be tested against a
// second, independent TLS stack (Go crypto/tls) besides OpenSSL.
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

func main() {
	addr := os.Args[1]
	cert := os.Args[2]
	key := os.Args[3]

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello-go %s", r.Proto)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.Header {
			w.Header().Set("X-Echo-"+k, v[0])
		}
		fmt.Fprint(w, "ok")
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		},
	}
	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		panic(err)
	}
}
