package tls

// QUIC has no TLS record stream to tee, so the ServerHello cannot be recovered
// from the wire the way the TCP path does it. It does arrive in plaintext,
// though: the server sends it at the Initial encryption level, and
// UQUICConn.HandleData sees those bytes. This file records them on the
// connection itself so the engine can report JA4Sq.
//
// The bytes live in a field added to UQUICConn by the documented patch set
// (patches/freetls.patch), so they are released with the connection — a failed
// handshake cannot leak them, and a reused pointer cannot see stale data.

// freetlsRecordQUICHandshake records handshake bytes received at a QUIC
// encryption level. Only the Initial level is kept: it carries the ServerHello,
// and it arrives before any other level.
func freetlsRecordQUICHandshake(q *UQUICConn, level QUICEncryptionLevel, data []byte) {
	if q == nil || level != QUICEncryptionLevelInitial || len(data) == 0 || q.freetlsSH != nil {
		return
	}
	q.freetlsSH = append([]byte(nil), data...)
}

// FreetlsServerHello returns the handshake message the peer sent at the QUIC
// Initial encryption level — the ServerHello — or nil if none was seen.
//
// The value is consumed: a second call returns nil.
func (q *UQUICConn) FreetlsServerHello() []byte {
	b := q.freetlsSH
	q.freetlsSH = nil
	return b
}
