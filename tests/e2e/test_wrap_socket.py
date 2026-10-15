"""End-to-end tests for TLSContext.wrap_socket (ssl.SSLContext-style)."""

from __future__ import annotations

import socket

import freetls
from freetls import TLSContext


def _connect_raw(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    return s


def test_wrap_socket_baseline(tls_server_13):
    ctx = TLSContext.baseline(server_name="localhost")
    raw = _connect_raw(tls_server_13.port)
    sess = ctx.wrap_socket(raw, server_hostname="localhost")
    assert sess.version() == "TLS1.3"
    assert sess.ja4.startswith("t13d")
    assert sess.cipher()[0]
    sess.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    assert b"HTTP/1.0 200" in sess.recv(256)
    sess.close()


def test_wrap_socket_specific_mode(tls_server_13):
    ctx = TLSContext.specific(ciphers=[0x1301, 0x1302, 0x1303], server_name="localhost")
    raw = _connect_raw(tls_server_13.port)
    sess = ctx.wrap_socket(raw, server_hostname="localhost")
    assert sess.fingerprints["ciphers"] == [0x1301, 0x1302, 0x1303]
    assert sess.ja4.split("_")[0][4:6] == "03"
    sess.close()


def test_wrap_socket_without_sni_marks_i(tls_server_13):
    ctx = TLSContext.baseline(server_name=None)
    raw = _connect_raw(tls_server_13.port)
    sess = ctx.wrap_socket(raw, server_hostname="")
    assert sess.fingerprints["sni"] == "i"
    assert sess.ja4[3] == "i"
    sess.close()


def test_wrap_socket_with_default_sni(tls_server_13):
    ctx = TLSContext.baseline(server_name="localhost")
    raw = _connect_raw(tls_server_13.port)
    # server_hostname omitted -> falls back to spec.server_name
    sess = ctx.wrap_socket(raw)
    assert sess.ja4[3] == "d"
    assert sess.server_hostname() == "localhost"
    sess.close()


def test_wrap_socket_ja4_matches_engine(tls_server_13):
    ctx = TLSContext.true_random(server_name="localhost", seed=9, n_ciphers=80, n_extensions=40)
    raw = _connect_raw(tls_server_13.port)
    sess = ctx.wrap_socket(raw, server_hostname="localhost")
    assert sess.ja4 == freetls.ja4_from_bytes(sess.client_hello)["ja4"]
    sess.close()


def test_ctx_is_reusable_for_multiple_sockets(tls_server_13):
    ctx = TLSContext.baseline(server_name="localhost")
    ja4s = []
    for _ in range(3):
        raw = _connect_raw(tls_server_13.port)
        sess = ctx.wrap_socket(raw, server_hostname="localhost")
        ja4s.append(sess.ja4)
        sess.close()
    assert len(set(ja4s)) == 1  # fixed spec -> stable JA4
