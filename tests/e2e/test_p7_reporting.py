"""P7 e2e: JA4+ reporting on live sessions and requests."""

from __future__ import annotations

import freetls
from freetls import modes
from freetls.session import TLSSession


def test_session_reports_ja4x(tls_server_13):
    s = TLSSession(modes.baseline_spec(server_name="localhost"))
    s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
    s.do_handshake()
    try:
        value = s.ja4x
    finally:
        s.close()
    assert value is not None
    parts = value.split("_")
    assert len(parts) == 3
    assert all(len(p) == 12 for p in parts)


def test_h2_request_reports_ja4h(go_server):
    spec = modes.baseline_spec(server_name="localhost", alpn=["h2"])
    with TLSSession(spec) as s:
        s.connect("127.0.0.1", go_server.port, server_hostname="localhost")
        assert s.selected_alpn_protocol() == "h2"
        resp = s.h2_request("/", headers=[["user-agent", "freetls"], ["accept", "*/*"]])
    assert resp["ja4h"].startswith("ge20")
    assert (
        resp["ja4h"]
        == freetls.ja4h_from_request(
            "GET",
            [("user-agent", "freetls"), ("accept", "*/*")],
            version="HTTP/2",
        )["ja4h"]
    )
