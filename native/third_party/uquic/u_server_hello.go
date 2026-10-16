package quic

// FreetlsServerHello returns the raw ServerHello handshake message received on
// this connection, or nil if the handshake has not progressed far enough.
//
// QUIC carries the ServerHello in the server's Initial packet rather than a TLS
// record stream, so the engine cannot tee it; this reaches the capture the uTLS
// fork records while handling Initial-level handshake data.
func (c *Conn) FreetlsServerHello() []byte {
	if c == nil {
		return nil
	}
	if p, ok := c.cryptoStreamHandler.(interface{ FreetlsServerHello() []byte }); ok {
		return p.FreetlsServerHello()
	}
	return nil
}
