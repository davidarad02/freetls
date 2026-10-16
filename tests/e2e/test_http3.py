"""HTTP/3 application layer: requests over a QUIC connection.

The server is built on upstream quic-go (not the uQUIC fork freetls ships), so
the client is exercised against an independent HTTP/3 implementation.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from _quic_spec import quic_spec as _quic_spec

from freetls import QUICSession, engine


def _connect(h3_server) -> QUICSession:
    session = QUICSession(_quic_spec())
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    return session


def test_http3_get_roundtrip(h3_server):
    session = _connect(h3_server)
    try:
        resp = session.request("/")
        assert resp.get("error") in (None, ""), resp.get("error")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
        assert resp["body"] == b"hello-h3 HTTP/3.0"
    finally:
        session.close()


def test_http3_reports_ja4h_version_30(h3_server):
    session = _connect(h3_server)
    try:
        resp = session.request("/", headers=[("Accept-Language", "en-US")])
        assert resp["ja4h"].startswith("ge30")
    finally:
        session.close()


def test_http3_post_with_body(h3_server):
    session = _connect(h3_server)
    try:
        resp = session.request("/", method="POST", body=b"payload")
        assert resp.get("error") in (None, ""), resp.get("error")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()


def test_http3_headers_are_echoed(h3_server):
    session = _connect(h3_server)
    try:
        resp = session.request("/headers", headers=[("X-Test", "abc")])
        assert resp["status"] == 200
        headers = {k.lower(): v for k, v in resp["headers"]}
        assert headers.get("x-echo-x-test") == "abc"
    finally:
        session.close()


def test_http3_concurrent_requests_share_one_connection(h3_server):
    session = _connect(h3_server)
    before = engine.active_sessions()
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: session.request("/"), range(16)))
        assert all(r["status"] == 200 for r in results)
        assert all(b"hello-h3" in r["body"] for r in results)
        # One QUIC connection multiplexed all 16 requests: no new sessions.
        assert engine.active_sessions() == before
    finally:
        session.close()
    assert engine.active_sessions() == before - 1


def test_http3_request_before_handshake_raises():
    session = QUICSession(_quic_spec())
    with pytest.raises(Exception):
        session.request("/")


def test_http3_request_after_close_raises(h3_server):
    session = _connect(h3_server)
    session.close()
    with pytest.raises(Exception):
        session.request("/")


def test_http3_datagram_echo(h3_server):
    """RFC 9297 datagrams: send on a flow, receive the server's echo."""
    session = QUICSession(_quic_spec(datagrams=True))
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    try:
        flow = session.open_datagram_flow("/echo-datagram")
        # The server may not have associated the flow yet, so retry until the
        # echo comes back (datagrams for unknown flows are dropped per RFC 9297).
        deadline = time.monotonic() + 10
        got = None
        while time.monotonic() < deadline:
            session.send_datagram(flow, b"ping-dgram")
            try:
                got = session.recv_datagram(flow, timeout=1.0)
                break
            except Exception:
                continue
        assert got == b"ping-dgram"
    finally:
        session.close()


def test_http3_datagram_requires_opt_in(h3_server):
    session = _connect(h3_server)
    try:
        with pytest.raises(Exception):
            session.open_datagram_flow("/echo-datagram")
    finally:
        session.close()


def test_quic_early_data_is_ignored(h3_server):
    """quic_early_data is reserved for the deferred 0-RTT work: the engine must
    not attempt 0-RTT, so the handshake completes normally and does not resume."""
    spec = _quic_spec()
    spec.quic_early_data = True
    session = QUICSession(spec)
    try:
        session.connect("127.0.0.1", h3_server.port, timeout=15)
        assert session.selected_alpn_protocol() == "h3"
        assert session.did_resume is False
        resp = session.request("/")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()


def test_http3_invalid_header_fails_fast(h3_server):
    """A bad header name/value errors immediately, not after the request deadline."""
    session = _connect(h3_server)
    try:
        start = time.monotonic()
        resp = session.request("/", headers=[("X-Bad", "a\r\nInjected: yes")])
        elapsed = time.monotonic() - start
        assert resp.get("error"), resp
        assert elapsed < 5  # not the ~15s deadline hang
    finally:
        session.close()


def test_http3_does_not_inject_headers(h3_server):
    """An H3 request carries exactly the caller's headers (no UA/Accept-Encoding)."""
    session = _connect(h3_server)
    try:
        resp = session.request("/headers")
        echoed = {k.lower() for k, _ in resp["headers"]}
        assert "x-echo-user-agent" not in echoed
        assert "x-echo-accept-encoding" not in echoed
    finally:
        session.close()


def test_http3_datagram_flow_close(h3_server):
    """A datagram flow can be released; sending on it then fails, and close is idempotent."""
    session = QUICSession(_quic_spec(datagrams=True))
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    try:
        flow = session.open_datagram_flow("/echo-datagram")
        session.close_datagram_flow(flow)
        with pytest.raises(Exception):
            session.send_datagram(flow, b"x")
        session.close_datagram_flow(flow)  # idempotent
    finally:
        session.close()


def test_http3_ipv6_request(h3_server_v6):
    """HTTP/3 over an IPv6 peer (the :authority must bracket the literal)."""
    session = QUICSession(_quic_spec())
    session.connect("::1", h3_server_v6.port, server_hostname="::1", timeout=15)
    try:
        assert session.selected_alpn_protocol() == "h3"
        assert session._authority() == f"[::1]:{h3_server_v6.port}"
        resp = session.request("/")
        assert resp.get("error") in (None, ""), resp.get("error")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()


def test_http3_datagram_flows_recycle(h3_server):
    """Closed flows free their streams, so more than the peer's limit can be opened."""
    session = QUICSession(_quic_spec(datagrams=True))
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    try:
        for _ in range(120):  # > the advertised initial_max_streams_bidi (100)
            flow = session.open_datagram_flow("/echo-datagram")
            session.close_datagram_flow(flow)
    finally:
        session.close()


def test_quic_v2_handshake_and_request(h3_server):
    """QuicInitialSpec.version selects QUIC v2 (RFC 9369) end to end."""
    from freetls.model import QUIC_V2

    spec = _quic_spec()
    spec.quic.version = QUIC_V2
    session = QUICSession(spec)
    session.connect("127.0.0.1", h3_server.port, timeout=15)
    try:
        assert session.selected_alpn_protocol() == "h3"
        resp = session.request("/")
        assert resp.get("error") in (None, ""), resp.get("error")
        assert resp["status"] == 200
        assert b"hello-h3" in resp["body"]
    finally:
        session.close()


def test_httpx_http3_error_does_not_leak(h3_server, monkeypatch):
    import httpx

    from freetls.transport import httpx_transport
    from freetls.transport.httpx_transport import FreeTLSTransport

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(httpx_transport._http3, "execute", boom)
    before = engine.active_sessions()
    transport = FreeTLSTransport(spec=_quic_spec(), http3=True)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(RuntimeError):
            client.get(f"https://127.0.0.1:{h3_server.port}/")
    assert engine.active_sessions() == before


def test_httpx_http3_transport(h3_server):
    import httpx

    from freetls.transport.httpx_transport import FreeTLSTransport

    transport = FreeTLSTransport(spec=_quic_spec(), http3=True)
    with httpx.Client(transport=transport) as client:
        resp = client.get(f"https://127.0.0.1:{h3_server.port}/")
    assert resp.status_code == 200
    assert b"hello-h3" in resp.content
    assert transport.last_http_version == "HTTP/3"
    assert resp.extensions["http_version"] == b"HTTP/3"


def test_requests_http3_adapter(h3_server):
    import requests

    from freetls import JA4Adapter

    adapter = JA4Adapter(spec=_quic_spec(), http3=True)
    session = requests.Session()
    session.mount("https://", adapter)
    resp = session.get(f"https://127.0.0.1:{h3_server.port}/")
    assert resp.status_code == 200
    assert b"hello-h3" in resp.content
    assert adapter.last_ja4 is not None and adapter.last_ja4.startswith("q")
    assert adapter.last_ja4s is not None and adapter.last_ja4s.startswith("q")


def test_requests_http3_forwards_headers(h3_server):
    """The transport must forward request headers (regression: Mapping handling)."""
    import requests

    from freetls import JA4Adapter

    adapter = JA4Adapter(spec=_quic_spec(), http3=True)
    session = requests.Session()
    session.mount("https://", adapter)
    try:
        resp = session.get(
            f"https://127.0.0.1:{h3_server.port}/headers",
            headers={"X-Test": "abc", "X-Two": "def"},
        )
        assert resp.status_code == 200
        assert resp.headers.get("x-echo-x-test") == "abc"
        assert resp.headers.get("x-echo-x-two") == "def"
    finally:
        session.close()


def test_quic_wrap_socket_with_host_port(h3_server):
    """wrap_socket works when the (unconnected) UDP peer is supplied."""
    import socket as _socket

    spec = _quic_spec()
    spec.timeout_ms = 15000
    session = QUICSession(spec)
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        session.wrap_socket(sock, "localhost", host="127.0.0.1", port=h3_server.port)
        assert session.selected_alpn_protocol() == "h3"
        resp = session.request("/")
        assert resp["status"] == 200
    finally:
        session.close()


def test_httpx_http3_rejects_proxy(h3_server):
    import httpx

    from freetls.transport.httpx_transport import FreeTLSTransport

    transport = FreeTLSTransport(spec=_quic_spec(), proxy="http://127.0.0.1:9", http3=True)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.UnsupportedProtocol):
            client.get(f"https://127.0.0.1:{h3_server.port}/")


def test_http3_invalid_authority_fails_fast(h3_server):
    """A host that is invalid as :authority errors immediately, not after the deadline."""
    session = _connect(h3_server)
    try:
        start = time.monotonic()
        resp = session.request("/", authority="exa<mple.com")
        assert resp.get("error"), resp
        assert time.monotonic() - start < 5
    finally:
        session.close()


def test_requests_http3_reuses_one_connection(h3_server):
    """requests/urllib3 H3 closes each connection's session (no per-request leak)."""
    import requests

    from freetls import JA4Adapter

    before = engine.active_sessions()
    adapter = JA4Adapter(spec=_quic_spec(), http3=True)
    session = requests.Session()
    session.mount("https://", adapter)
    try:
        for _ in range(3):
            resp = session.get(f"https://127.0.0.1:{h3_server.port}/")
            assert resp.status_code == 200
            assert b"hello-h3" in resp.content
        assert engine.active_sessions() == before
    finally:
        session.close()
    assert engine.active_sessions() == before


def test_requests_http3_follows_redirect(h3_server):
    import requests

    from freetls import JA4Adapter

    adapter = JA4Adapter(spec=_quic_spec(), http3=True)
    session = requests.Session()
    session.mount("https://", adapter)
    try:
        resp = session.get(f"https://127.0.0.1:{h3_server.port}/redirect")
        assert resp.status_code == 200
        assert b"hello-h3" in resp.content
    finally:
        session.close()
