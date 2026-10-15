"""TLS version matrix: 1.0, 1.1, 1.2, 1.3 handshakes."""

from __future__ import annotations

import pytest

import freetls
from freetls import modes


def _spec(minv, maxv):
    return modes.baseline_spec(server_name="localhost", vers_min=minv, vers_max=maxv)


def test_tls13(tls_server_13):
    with freetls.TLSSession(_spec(freetls.TLS13, freetls.TLS13)) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"
        assert s.ja4.startswith("t13")


def test_tls12(tls_server_12):
    with freetls.TLSSession(_spec(freetls.TLS12, freetls.TLS12)) as s:
        s.connect("127.0.0.1", tls_server_12.port, server_hostname="localhost")
        assert s.state.version == "TLS1.2"
        assert s.ja4.startswith("t12")


def test_tls11(tls_server_11):
    with freetls.TLSSession(_spec(freetls.TLS11, freetls.TLS11)) as s:
        try:
            s.connect("127.0.0.1", tls_server_11.port, server_hostname="localhost")
        except freetls.HandshakeError:
            pytest.skip("local OpenSSL refuses TLS 1.1")
        assert s.state.version == "TLS1.1"
        assert s.ja4.startswith("t11")


def test_tls10(tls_server_10):
    with freetls.TLSSession(_spec(freetls.TLS10, freetls.TLS10)) as s:
        try:
            s.connect("127.0.0.1", tls_server_10.port, server_hostname="localhost")
        except freetls.HandshakeError:
            pytest.skip("local OpenSSL refuses TLS 1.0")
        assert s.state.version == "TLS1.0"
        assert s.ja4.startswith("t10")


def test_mixed_version_offer_negotiates_highest(tls_server_13):
    spec = modes.baseline_spec(
        server_name="localhost", vers_min=freetls.TLS10, vers_max=freetls.TLS13
    )
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"
