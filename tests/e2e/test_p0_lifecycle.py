"""P0 lifecycle: no session leaks, deferred handshake, recv_into, cipher shape."""

from __future__ import annotations

import socket

from freetls import TLSContext, TLSSession, engine, modes
from freetls.errors import HandshakeError


def _connect(port, **kw):
    s = TLSSession(modes.baseline_spec(server_name="localhost", **kw))
    s.connect("127.0.0.1", port, server_hostname="localhost")
    return s


def test_no_session_leak_on_close(tls_server_13):
    base = engine.active_sessions()
    for _ in range(5):
        s = _connect(tls_server_13.port)
        s.close()
    assert engine.active_sessions() <= base


def test_failed_handshake_does_not_leak(tls_server_13):
    base = engine.active_sessions()
    s = TLSSession(modes.specific(ciphers=[], server_name="localhost"))
    try:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
    except HandshakeError:
        pass
    finally:
        s.close()
    assert engine.active_sessions() <= base


def test_deferred_handshake(tls_server_13):
    raw = socket.create_connection(("127.0.0.1", tls_server_13.port), timeout=5)
    ctx = TLSContext.baseline(server_name="localhost")
    sess = ctx.wrap_socket(raw, "localhost", do_handshake_on_connect=False)
    assert sess.ja4 is None  # not handshaked yet
    sess.do_handshake()
    assert sess.ja4.startswith("t13d")
    sess.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    assert b"HTTP/1.0 200" in sess.recv(256)
    sess.close()


def test_recv_into_and_socket_parity(tls_server_13):
    with _connect(tls_server_13.port) as s:
        assert s.getpeername()[0] == "127.0.0.1"
        assert s.getsockname()[0] == "127.0.0.1"
        assert s.fileno() >= 0
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        buf = bytearray(96)
        n = s.recv_into(buf)
        assert n > 0 and b"HTTP" in bytes(buf[:n])


def test_cipher_is_ssl_shaped(tls_server_13):
    with _connect(tls_server_13.port) as s:
        name, protocol, bits = s.cipher()
        assert name.startswith("TLS_")
        assert protocol == "TLSv1.3"
        assert bits in (128, 256)


def test_getpeercert_binary_form(tls_server_13):
    with _connect(tls_server_13.port) as s:
        der = s.getpeercert(binary_form=True)
        assert isinstance(der, (bytes, bytearray)) and len(der) > 0
