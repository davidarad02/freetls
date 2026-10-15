"""P6 e2e: streaming bodies and content decoding through the transports."""

from __future__ import annotations

import asyncio

import pytest

import freetls


def _synth():
    return freetls.modes.baseline_spec(server_name="localhost")


def test_httpx_streaming_is_incremental(app_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    spec = _synth()
    t = FreeTLSTransport(spec=spec)
    chunks = []
    with httpx.Client(transport=t) as c:
        with c.stream("GET", f"https://127.0.0.1:{app_server.port}/stream") as r:
            assert r.status_code == 200
            for chunk in r.iter_raw():
                chunks.append(chunk)
    body = b"".join(chunks)
    assert body == b"chunk0-chunk1-chunk2-chunk3-chunk4-"
    assert len(chunks) >= 2
    assert t.last_session.ja4.startswith("t13d")


def test_httpx_async_streaming_is_incremental(app_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import AsyncFreeTLSTransport

    async def run():
        t = AsyncFreeTLSTransport(spec=_synth())
        chunks = []
        async with httpx.AsyncClient(transport=t) as c:
            async with c.stream("GET", f"https://127.0.0.1:{app_server.port}/stream") as r:
                async for chunk in r.aiter_raw():
                    chunks.append(chunk)
        return chunks, t

    chunks, t = asyncio.run(run())
    assert b"".join(chunks) == b"chunk0-chunk1-chunk2-chunk3-chunk4-"
    assert len(chunks) >= 2
    assert t.last_session.ja4.startswith("t13d")


def test_aiohttp_streaming_is_incremental(app_server):
    aiohttp = pytest.importorskip("aiohttp")
    from freetls.transport.aiohttp_connector import FreeTLSConnector

    async def run():
        spec = _synth()
        spec.timeout_ms = 4000
        conn = FreeTLSConnector(spec=spec)
        chunks = []
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(
                f"https://127.0.0.1:{app_server.port}/stream",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                async for chunk in r.content.iter_chunked(4):
                    chunks.append(chunk)
        return chunks, conn

    chunks, conn = asyncio.run(run())
    assert b"".join(chunks) == b"chunk0-chunk1-chunk2-chunk3-chunk4-"
    assert len(chunks) >= 2
    assert conn.last_session.ja4.startswith("t13d")


def test_httpx_brotli_and_zstd(app_server):
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("brotli")
    pytest.importorskip("zstandard")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=_synth())
    with httpx.Client(transport=t) as c:
        br = c.get(f"https://127.0.0.1:{app_server.port}/br")
        zs = c.get(f"https://127.0.0.1:{app_server.port}/zstd")
    assert br.content == b"brotli-body-" * 20
    assert zs.content == b"zstd-body-" * 20


def test_sse_helper_over_the_wire(app_server):
    httpx = pytest.importorskip("httpx")
    from freetls.transport.httpx_transport import FreeTLSTransport

    t = FreeTLSTransport(spec=_synth())
    with httpx.Client(transport=t) as c:
        with c.stream("GET", f"https://127.0.0.1:{app_server.port}/sse") as r:
            events = list(freetls.sse.iter_sse(r.iter_bytes()))
    assert [e.event for e in events] == ["ping", "", ""]
    assert events[0].data == '{"n": 1}'
    assert events[1].data == "hello"
    assert events[2].data == "line1\nline2"
