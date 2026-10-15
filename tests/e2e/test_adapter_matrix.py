"""Shared behavior matrix across requests, httpx, and aiohttp transports."""
from __future__ import annotations

import asyncio
import warnings

import pytest

import freetls
from freetls import modes


def _spec():
    return modes.baseline_spec(server_name="localhost", alpn=["http/1.1"])


# --------------------------------------------------------------------------- #
# requests
# --------------------------------------------------------------------------- #
def test_requests_matrix(app_server):
    requests = pytest.importorskip("requests")
    from freetls.transport import JA4Adapter

    adapter = JA4Adapter(spec=_spec())
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        base = f"https://127.0.0.1:{app_server.port}"
        assert s.get(f"{base}/", verify=False).text == "hello-root"
        assert s.post(f"{base}/echo", data=b"ping", verify=False).content == b"ping"
        assert s.get(f"{base}/redirect", verify=False).text == "hello-root"
        assert s.get(f"{base}/gzip", verify=False).text.startswith("gzipped-body")
        assert s.get(f"{base}/chunked", verify=False).text.startswith("chunked-body")
        hdr = s.get(f"{base}/headers", headers={"X-Custom": "abc"}, verify=False).json()
        assert hdr["headers"].get("X-Custom") == "abc"
        r = s.get(f"{base}/cookie", verify=False)
        assert "fl=1" in r.headers.get("Set-Cookie", "")
    assert adapter.last_ja4.startswith("t13d")


def test_requests_connection_reuse(app_server):
    requests = pytest.importorskip("requests")
    from freetls.transport import JA4Adapter

    adapter = JA4Adapter(spec=_spec())
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        base = f"https://127.0.0.1:{app_server.port}"
        s.get(f"{base}/", verify=False)
        ja4_a = adapter.last_ja4
        s.get(f"{base}/", verify=False)
        ja4_b = adapter.last_ja4
    assert ja4_a == ja4_b


def test_requests_error_path(app_server):
    requests = pytest.importorskip("requests")
    from freetls.transport import JA4Adapter

    adapter = JA4Adapter(spec=_spec())
    s = requests.Session()
    s.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(requests.exceptions.ConnectionError):
            s.get("https://127.0.0.1:1/", verify=False)


# --------------------------------------------------------------------------- #
# httpx
# --------------------------------------------------------------------------- #
def test_httpx_matrix(app_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=_spec())
    base = f"https://127.0.0.1:{app_server.port}"
    with httpx.Client(transport=t, follow_redirects=True) as c:
        assert c.get(f"{base}/").text == "hello-root"
        assert c.post(f"{base}/echo", content=b"ping").content == b"ping"
        assert c.get(f"{base}/redirect").text == "hello-root"
        assert c.get(f"{base}/gzip").text.startswith("gzipped-body")
        assert c.get(f"{base}/chunked").text.startswith("chunked-body")
    assert t.last_session.ja4.startswith("t13d")


def test_httpx_async_get(app_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import AsyncFreeTLSTransport

    async def run():
        t = AsyncFreeTLSTransport(spec=_spec())
        async with httpx.AsyncClient(transport=t) as c:
            r = await c.get(f"https://127.0.0.1:{app_server.port}/")
        return r, t

    r, t = asyncio.run(run())
    assert r.text == "hello-root"
    assert t.last_session.ja4.startswith("t13d")


# --------------------------------------------------------------------------- #
# aiohttp
# --------------------------------------------------------------------------- #
def test_aiohttp_matrix(app_server):
    aiohttp = pytest.importorskip("aiohttp")
    from freetls.transport.aiohttp_connector import FreeTLSConnector

    async def run():
        spec = _spec()
        spec.timeout_ms = 3000
        conn = FreeTLSConnector(spec=spec)
        base = f"https://127.0.0.1:{app_server.port}"
        to = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(f"{base}/", timeout=to) as r:
                root = await r.text()
            async with s.post(f"{base}/echo", data=b"ping", timeout=to) as r:
                echo = await r.read()
        return root, echo, conn

    root, echo, conn = asyncio.run(run())
    assert root == "hello-root"
    assert echo == b"ping"
    assert conn.last_session.ja4.startswith("t13d")
