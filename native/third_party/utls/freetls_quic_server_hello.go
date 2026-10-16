package tls

import "sync"

// QUIC has no TLS record stream to tee, so the ServerHello cannot be recovered
// from the wire the way the TCP path does it. It does arrive in plaintext,
// though: the server sends it at the Initial encryption level, and
// UQUICConn.HandleData sees those bytes. This file records them per connection
// so the engine can report JA4Sq for a QUIC session.
//
// The store is keyed by connection pointer rather than a struct field because
// UQUICConn lives in an upstream file, and the fork's rule is new files only
// (plus the documented patch set). Reads are take-once, so entries do not
// accumulate.

var (
	freetlsSHMu     sync.Mutex
	freetlsSHByConn = map[*UQUICConn][]byte{}
)

// freetlsRecordQUICHandshake records handshake bytes received at a QUIC
// encryption level. Only the Initial level is kept: it carries the ServerHello,
// and it arrives before any other level.
func freetlsRecordQUICHandshake(q *UQUICConn, level QUICEncryptionLevel, data []byte) {
	if q == nil || level != QUICEncryptionLevelInitial || len(data) == 0 {
		return
	}
	cp := append([]byte(nil), data...)
	freetlsSHMu.Lock()
	if _, seen := freetlsSHByConn[q]; !seen {
		freetlsSHByConn[q] = cp
	}
	freetlsSHMu.Unlock()
}

// FreetlsServerHello returns the handshake message the peer sent at the QUIC
// Initial encryption level — the ServerHello — or nil if none was seen.
//
// The value is consumed: a second call returns nil.
func (q *UQUICConn) FreetlsServerHello() []byte {
	freetlsSHMu.Lock()
	defer freetlsSHMu.Unlock()
	b := freetlsSHByConn[q]
	delete(freetlsSHByConn, q)
	return b
}
