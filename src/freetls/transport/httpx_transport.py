"""httpx integration: transports that use the freetls engine for TLS.

The engines are exposed as httpx ``BaseTransport`` / ``AsyncBaseTransport`` so
the fingerprint API is identical to the requests adapter. Response bodies are
streamed (HTTP/1.1 chunk-by-chunk; HTTP/2 as a single body frame) so that
``client.stream(...)`` works and the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import http.client
from collections.abc import Iterator
from typing import Callable

import httpx

from ..model import FingerprintSpec
from ..quic import QUICSession
from ..session import TLSSession
from . import _http2, _http3

_CHUNK = 65536


class _Reader:
    """Minimal streaming body reader over an engine session."""

    def __init__(
        self, read_fn: Callable[[int], bytes], close_fn: Callable[[], None], first: bytes = b""
    ):
        self._read = read_fn
        self._close = close_fn
        self._first = first
        self._closed = False

    def read(self, n: int = _CHUNK) -> bytes:
        if self._first:
            data, self._first = self._first, b""
            return data
        return self._read(n)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close()


def _open(
    request: httpx.Request,
    spec: FingerprintSpec,
    proxy: str | None = None,
    http3: bool = False,
) -> tuple[TLSSession | QUICSession, int, list, bytes, str, _Reader]:
    url = request.url
    host = url.host
    port = url.port or 443
    if url.scheme != "https":
        raise httpx.UnsupportedProtocol(f"freetls only supports https, got {url.scheme}")
    path = url.raw_path.decode("latin-1") or "/"
    headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in request.headers.raw}
    headers.setdefault("Host", url.netloc.decode("latin-1"))
    body = request.read()

    if http3:
        if proxy:
            raise httpx.UnsupportedProtocol("HTTP/3 over a proxy is not supported")
        session: TLSSession | QUICSession = QUICSession(spec)
        session.connect(host, port, server_hostname=spec.server_name or host)
        resp = _http3.execute(session, request.method, path, headers, body)
        reader = _Reader(lambda n: b"", session.close, resp.get("body", b""))
        return (
            session,
            _http3.status_of(resp),
            _http3.header_tuples(resp),
            b"",
            "HTTP/3",
            reader,
        )

    session = TLSSession(spec)
    if proxy:
        from .proxy import open_tunnel

        sock = open_tunnel(proxy, host, port)
        session.wrap_socket(sock, server_hostname=spec.server_name or host)
    else:
        session.connect(host, port, server_hostname=spec.server_name or host)

    if _http2.negotiated_h2(session):
        resp = _http2.execute(session, request.method, path, headers, body)
        reader = _Reader(lambda n: b"", session.close, resp.get("body", b""))
        return (
            session,
            _http2.status_of(resp),
            _http2.header_tuples(resp),
            b"",
            "HTTP/2",
            reader,
        )

    conn = http.client.HTTPConnection(host, port)
    conn.sock = session  # http.client will skip connect() when sock is set
    conn.request(request.method, path, body=body, headers=headers)
    resp = conn.getresponse()

    def close() -> None:
        try:
            resp.close()
        finally:
            session.close()

    reader = _Reader(getattr(resp, "read1", resp.read), close)
    return session, resp.status, resp.getheaders(), b"", "HTTP/1.1", reader


def _iter_reader(reader: _Reader) -> Iterator[bytes]:
    try:
        while True:
            chunk = reader.read(_CHUNK)
            if not chunk:
                break
            yield chunk
    finally:
        reader.close()


class _SyncBodyStream(httpx.SyncByteStream):
    def __init__(self, reader: _Reader):
        self._reader = reader

    def __iter__(self) -> Iterator[bytes]:
        yield from _iter_reader(self._reader)

    def close(self) -> None:
        self._reader.close()


class _AsyncBodyStream(httpx.AsyncByteStream):
    def __init__(self, loop: asyncio.AbstractEventLoop, reader: _Reader):
        self._loop = loop
        self._reader = reader

    async def __aiter__(self):  # type: ignore[override]
        try:
            while True:
                chunk = await self._loop.run_in_executor(None, self._reader.read, _CHUNK)
                if not chunk:
                    break
                yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        await self._loop.run_in_executor(None, self._reader.close)


def _extensions(version: str) -> dict:
    mapping = {"HTTP/3": b"HTTP/3", "HTTP/2": b"HTTP/2"}
    return {"http_version": mapping.get(version, b"HTTP/1.1")}


def _ja4h(request: httpx.Request, version: str) -> str:
    from ..fingerprint import ja4h_from_request

    pairs = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
    return ja4h_from_request(request.method, pairs, version=version)["ja4h"]


class FreeTLSTransport(httpx.BaseTransport):
    """Synchronous httpx transport driven by the freetls engine.

    HTTP/2 is used automatically when the handshake negotiates ``h2`` (ALPN);
    otherwise HTTP/1.1 is used. Bodies are streamed.
    """

    def __init__(
        self,
        spec: FingerprintSpec | None = None,
        spec_factory: Callable[[], FingerprintSpec] | None = None,
        proxy: str | None = None,
        http3: bool = False,
    ):
        if spec is None and spec_factory is None:
            raise ValueError("FreeTLSTransport requires spec= or spec_factory=")
        self._spec = spec
        self._spec_factory = spec_factory
        self._proxy = proxy
        self._http3 = http3
        self.last_session: TLSSession | QUICSession | None = None
        self.last_http_version: str | None = None
        self.last_ja4h: str | None = None

    def _factory(self) -> FingerprintSpec:
        if self._spec_factory is not None:
            return self._spec_factory()
        assert self._spec is not None
        return self._spec

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        session, status, headers, _unused, version, reader = _open(
            request, self._factory(), self._proxy, self._http3
        )
        self.last_session = session
        self.last_http_version = version
        self.last_ja4h = _ja4h(request, version)
        return httpx.Response(
            status_code=status,
            headers=[(k.lower(), v) for k, v in headers],
            stream=_SyncBodyStream(reader),
            request=request,
            extensions=_extensions(version),
        )

    def close(self) -> None:
        return None


class AsyncFreeTLSTransport(httpx.AsyncBaseTransport):
    """Asynchronous httpx transport.

    The blocking engine call runs in a worker thread, so the asyncio event loop
    is never blocked and HTTP/2 is negotiated automatically via ALPN. Bodies
    are streamed through the worker thread as well.
    """

    def __init__(
        self,
        spec: FingerprintSpec | None = None,
        spec_factory: Callable[[], FingerprintSpec] | None = None,
        proxy: str | None = None,
        http3: bool = False,
    ):
        self._sync = FreeTLSTransport(
            spec=spec, spec_factory=spec_factory, proxy=proxy, http3=http3
        )
        self.last_session: TLSSession | QUICSession | None = None
        self.last_http_version: str | None = None
        self.last_ja4h: str | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        loop = asyncio.get_running_loop()
        session, status, headers, _unused, version, reader = await loop.run_in_executor(
            None, _open, request, self._sync._factory(), self._sync._proxy, self._sync._http3
        )
        self.last_session = session
        self.last_http_version = version
        self.last_ja4h = _ja4h(request, version)
        return httpx.Response(
            status_code=status,
            headers=[(k.lower(), v) for k, v in headers],
            stream=_AsyncBodyStream(loop, reader),
            request=request,
            extensions=_extensions(version),
        )

    async def aclose(self) -> None:
        return None
