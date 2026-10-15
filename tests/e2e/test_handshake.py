"""End-to-end handshake and fingerprint tests against local TLS servers."""

from __future__ import annotations

import re

import freetls

JA4_RE = re.compile(r"^t13d\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")


def _get(session: freetls.TLSSession) -> bytes:
    session.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    return session.recv(256)


def test_baseline_handshake_and_http(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"
        assert JA4_RE.match(s.ja4), s.ja4
        assert s.ja3 and len(s.ja3) == 32
        assert s.ja4s and s.ja4s.startswith("t13")
        data = _get(s)
        assert b"HTTP/1.0 200" in data


def test_reported_ja4_matches_emitted_bytes(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        recomputed = freetls.ja4_from_bytes(s.client_hello)["ja4"]
        assert s.ja4 == recomputed


def test_tls12_handshake(tls_server_12):
    spec = freetls.modes.baseline_spec(
        server_name="localhost", vers_min=freetls.TLS12, vers_max=freetls.TLS12
    )
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_12.port, server_hostname="localhost")
        assert s.state.version == "TLS1.2"
        assert s.ja4.startswith("t12")


def test_each_connection_has_fresh_key_share(tls_server_13):
    spec = freetls.modes.baseline_spec(server_name="localhost")
    a = freetls.TLSSession(spec)
    a.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
    ja4_a, ch_a = a.ja4, a.client_hello
    a.close()
    b = freetls.TLSSession(spec)
    b.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
    ja4_b, ch_b = b.ja4, b.client_hello
    b.close()
    # JA4 is stable across connections for a fixed spec ...
    assert ja4_a == ja4_b
    # ... but the random field / key_share bytes differ on the wire.
    assert ch_a != ch_b
