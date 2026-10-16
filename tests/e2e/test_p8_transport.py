"""P8 e2e: proxies (HTTP CONNECT / SOCKS5) and a WebSocket client."""

from __future__ import annotations

import pytest

from freetls import modes
from freetls.session import TLSSession


def _spec():
    return modes.baseline_spec(server_name="localhost")


def test_http_connect_proxy(tls_server_13):
    from proxies import HTTPConnectProxy

    with HTTPConnectProxy() as proxy:
        s = TLSSession(_spec())
        s.connect_via_proxy(
            f"http://127.0.0.1:{proxy.port}",
            "127.0.0.1",
            tls_server_13.port,
            server_hostname="localhost",
        )
        try:
            assert s.ja4.startswith("t13")
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            assert b"HTTP" in s.recv(65536)
        finally:
            s.close()


def test_http_connect_proxy_requires_auth(tls_server_13):
    from proxies import HTTPConnectProxy

    from freetls.errors import FreeTLSError

    with HTTPConnectProxy(auth=("user", "pass")) as proxy:
        s = TLSSession(_spec())
        with pytest.raises((OSError, FreeTLSError)):
            s.connect_via_proxy(
                f"http://127.0.0.1:{proxy.port}",
                "127.0.0.1",
                tls_server_13.port,
                server_hostname="localhost",
            )


def test_socks5_proxy(tls_server_13):
    from proxies import Socks5Proxy

    with Socks5Proxy() as proxy:
        s = TLSSession(_spec())
        s.connect_via_proxy(
            f"socks5://127.0.0.1:{proxy.port}",
            "127.0.0.1",
            tls_server_13.port,
            server_hostname="localhost",
        )
        try:
            assert s.ja4.startswith("t13")
        finally:
            s.close()


def test_socks5_proxy_with_auth(tls_server_13):
    from proxies import Socks5Proxy

    with Socks5Proxy(auth=("user", "pass")) as proxy:
        s = TLSSession(_spec())
        s.connect_via_proxy(
            f"socks5://user:pass@127.0.0.1:{proxy.port}",
            "127.0.0.1",
            tls_server_13.port,
            server_hostname="localhost",
        )
        try:
            assert s.ja4.startswith("t13")
        finally:
            s.close()


def test_httpx_transport_via_http_proxy(tls_server_13):
    httpx = pytest.importorskip("httpx")
    from proxies import HTTPConnectProxy

    from freetls.transport.httpx_transport import FreeTLSTransport

    with HTTPConnectProxy() as proxy:
        t = FreeTLSTransport(spec=_spec(), proxy=f"http://127.0.0.1:{proxy.port}")
        with httpx.Client(transport=t) as c:
            r = c.get(f"https://127.0.0.1:{tls_server_13.port}/")
    assert r.status_code == 200
    assert t.last_session.ja4.startswith("t13")


def test_websocket_permessage_deflate(certs):
    from proxies import WSEchoServer

    from freetls.transport import websocket

    cert, key = certs
    with WSEchoServer(cert, key) as server:
        s = TLSSession(modes.baseline_spec(server_name="localhost", alpn=["http/1.1"]))
        s.connect("127.0.0.1", server.port, server_hostname="localhost")
        ws = websocket.connect(s, "localhost", "/")
        try:
            assert ws._deflate is not None  # RFC 7692 negotiated
            payload = "abc" * 5000
            ws.send(payload)
            assert ws.recv() == payload
            ws.send_binary(b"\x00" * 4000)
            assert ws.recv() == b"\x00" * 4000
        finally:
            s.close()


def test_websocket_echo(certs):
    from proxies import WSEchoServer

    from freetls.transport import websocket

    cert, key = certs
    with WSEchoServer(cert, key) as server:
        s = TLSSession(modes.baseline_spec(server_name="localhost", alpn=["http/1.1"]))
        s.connect("127.0.0.1", server.port, server_hostname="localhost")
        ws = websocket.connect(s, "localhost", "/")
        try:
            ws.send("hello")
            assert ws.recv() == "hello"
            ws.send_binary(b"\x00\x01\x02")
            assert ws.recv() == b"\x00\x01\x02"
            ws.close()
        finally:
            s.close()
