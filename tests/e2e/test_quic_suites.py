"""QUIC cipher-suite matrix.

Negotiates every QUIC-capable TLS 1.3 suite against the independent HTTP/3 test
server (built on upstream quic-go) with an application-data round trip. TLS 1.3
CCM cannot be negotiated against that server — Go's ``crypto/tls`` and OpenSSL
3.5.5 do not implement it — so those rows are skipped with that reason; the wide
engine covers CCM at the AEAD level (``make test-uquic``).
"""

from __future__ import annotations

import pytest
from _quic_spec import quic_spec

from freetls import QUICSession

QUIC_SUITES = [
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
]

CCM_SUITES = [
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0x1305, "TLS_AES_128_CCM_8_SHA256"),
]


@pytest.mark.parametrize("suite,name", QUIC_SUITES, ids=[n for _, n in QUIC_SUITES])
def test_quic_suite_negotiates_with_app_data(h3_server, suite, name):
    session = QUICSession(quic_spec(ciphers=[suite]))
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
        cipher = session.cipher()
        assert cipher is not None and cipher[0] == name
        resp = session.request("/")
        assert resp.get("error") in (None, ""), resp.get("error")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()


@pytest.mark.parametrize("suite,name", CCM_SUITES, ids=[n for _, n in CCM_SUITES])
def test_quic_ccm_suite_not_negotiable_locally(h3_server, suite, name):
    pytest.skip(
        f"{name} cannot be negotiated end-to-end against the independent server: "
        "Go crypto/tls (and OpenSSL 3.5.5) do not implement TLS 1.3 CCM; the wide "
        "engine covers it at the AEAD level (make test-uquic)"
    )


def test_quic_baseline_mode_handshakes(h3_server):
    from freetls import modes

    session = QUICSession(modes.quic_baseline_spec(server_name="localhost"))
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
        assert session.ja4q is not None and session.ja4q.startswith("q")
        resp = session.request("/")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()
