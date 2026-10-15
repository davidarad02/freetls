"""End-to-end tests for the httpx and aiohttp transports."""

from __future__ import annotations

import asyncio

import pytest

import freetls


def test_httpx_sync(tls_server_13):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=freetls.modes.baseline_spec(server_name="localhost"))
    with httpx.Client(transport=t) as c:
        r = c.get(f"https://127.0.0.1:{tls_server_13.port}/")
    assert r.status_code == 200
    assert "HTML" in r.text
    assert t.last_session.ja4.startswith("t13d")


def test_httpx_async(tls_server_13):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import AsyncFreeTLSTransport

    async def run():
        t = AsyncFreeTLSTransport(spec=freetls.modes.baseline_spec(server_name="localhost"))
        async with httpx.AsyncClient(transport=t) as c:
            r = await c.get(f"https://127.0.0.1:{tls_server_13.port}/")
        return r, t

    r, t = asyncio.run(run())
    assert r.status_code == 200
    assert t.last_session.ja4.startswith("t13")


def test_aiohttp_connector(tls_server_13):
    aiohttp = pytest.importorskip("aiohttp")
    from freetls.transport.aiohttp_connector import FreeTLSConnector

    async def run():
        spec = freetls.modes.baseline_spec(server_name="localhost")
        spec.timeout_ms = 4000
        conn = FreeTLSConnector(spec=spec)
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(
                f"https://127.0.0.1:{tls_server_13.port}/",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                text = await r.text()
        return r.status, text, conn

    status, text, conn = asyncio.run(run())
    assert status == 200
    assert "HTML" in text
    assert conn.last_session.ja4.startswith("t13d")
