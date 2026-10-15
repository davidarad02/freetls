"""P3: HTTP/2 auto-selected via ALPN across the transports."""

from __future__ import annotations

import asyncio
import warnings

import pytest

from freetls import modes


def _spec(alpn):
    return modes.baseline_spec(server_name="localhost", alpn=alpn, verify=False)


def test_requests_auto_h2(go_server):
    requests = pytest.importorskip("requests")
    from freetls.transport import JA4Adapter

    adapter = JA4Adapter(spec=_spec(["h2", "http/1.1"]))
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = s.get(f"https://127.0.0.1:{go_server.port}/", verify=False)
    assert r.status_code == 200
    assert "hello-go" in r.text
    assert adapter.last_session.selected_alpn_protocol() == "h2"
    assert "HTTP/2" in r.text


def test_httpx_sync_auto_h2(go_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=_spec(["h2", "http/1.1"]))
    with httpx.Client(transport=t) as c:
        r = c.get(f"https://127.0.0.1:{go_server.port}/")
    assert r.status_code == 200
    assert t.last_http_version == "HTTP/2"
    assert "HTTP/2.0" in r.text


def test_httpx_async_auto_h2(go_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import AsyncFreeTLSTransport

    async def run():
        t = AsyncFreeTLSTransport(spec=_spec(["h2", "http/1.1"]))
        async with httpx.AsyncClient(transport=t) as c:
            r = await c.get(f"https://127.0.0.1:{go_server.port}/")
        return r, t

    r, t = asyncio.run(run())
    assert r.status_code == 200
    assert t.last_http_version == "HTTP/2"


def test_httpx_http11_when_no_h2(go_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=_spec(["http/1.1"]))
    with httpx.Client(transport=t) as c:
        r = c.get(f"https://127.0.0.1:{go_server.port}/")
    assert r.status_code == 200
    assert t.last_http_version == "HTTP/1.1"


def test_aiohttp_guards_alpn_h2(app_server):
    aiohttp = pytest.importorskip("aiohttp")
    from freetls.transport.aiohttp_connector import FreeTLSConnector

    async def run():
        # aiohttp speaks HTTP/1.1; the connector must strip h2 from ALPN so the
        # server does not negotiate an h2 the client cannot speak.
        spec = _spec(["h2", "http/1.1"])
        spec.timeout_ms = 3000
        conn = FreeTLSConnector(spec=spec)
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(f"https://127.0.0.1:{app_server.port}/") as r:
                text = await r.text()
        return r.status, text, conn

    status, text, conn = asyncio.run(run())
    assert status == 200
    assert conn.last_session.selected_alpn_protocol() in (None, "http/1.1")
