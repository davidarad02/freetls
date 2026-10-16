package handshake

// FreetlsServerHello returns the raw ServerHello the TLS stack received, or nil.
// It exposes the uTLS fork's per-connection capture so the engine can report
// JA4Sq for QUIC, where there is no TLS record stream to tee.
func (c *uCryptoSetup) FreetlsServerHello() []byte {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.FreetlsServerHello()
}
