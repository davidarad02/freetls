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


def test_httpx_http3_rejects_proxy(h3_server):
    import httpx

    from freetls.transport.httpx_transport import FreeTLSTransport

    transport = FreeTLSTransport(spec=_quic_spec(), proxy="http://127.0.0.1:9", http3=True)
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.UnsupportedProtocol):
            client.get(f"https://127.0.0.1:{h3_server.port}/")
