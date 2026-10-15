"""httpx integration: transports that use the freetls engine for TLS.

The engines are exposed as httpx ``BaseTransport`` / ``AsyncBaseTransport`` so
the fingerprint API is identical to the requests adapter.
"""
from __future__ import annotations

import asyncio
import gzip
import http.client
from typing import Callable, Optional

import httpx

from ..model import FingerprintSpec
from ..session import TLSSession


def _decode_content(data: bytes, headers: list) -> tuple[bytes, list]:
    """Decode Content-Encoding that httpcore would normally handle for httpx."""
    enc = ""
    for k, v in headers:
        if k.lower() == "content-encoding":
            enc = v.lower()
    if enc == "gzip":
        try:
            data = gzip.decompress(data)
        except OSError:
            return data, headers
        headers = [(k, v) for (k, v) in headers
                   if k.lower() not in ("content-encoding", "content-length")]
        headers.append(("content-length", str(len(data))))
    return data, headers


def _one_request(request: httpx.Request, spec: FingerprintSpec) -> tuple[TLSSession, int, list, bytes]:
    url = request.url
    host = url.host
    port = url.port or (443 if url.scheme == "https" else None)
    if url.scheme != "https":
        raise httpx.UnsupportedProtocol(f"freetls only supports https, got {url.scheme}")
    session = TLSSession(spec)
    session.connect(host, port, server_hostname=spec.server_name or host)
    conn = http.client.HTTPConnection(host, port)
    conn.sock = session  # http.client will skip connect() when sock is set
    path = url.raw_path.decode("latin-1") or "/"
    headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in request.headers.raw}
    headers.setdefault("Host", url.netloc.decode("latin-1"))
    body = request.read()
    try:
        conn.request(request.method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return session, resp.status, resp.getheaders(), data
    finally:
        # http.client's response owns the session file object only during read;
        # the session itself is closed by the caller after the body is built.
        pass


class FreeTLSTransport(httpx.BaseTransport):
    """Synchronous httpx transport driven by the freetls engine."""

    def __init__(self, spec: Optional[FingerprintSpec] = None,
                 spec_factory: Optional[Callable[[], FingerprintSpec]] = None):
        if spec is None and spec_factory is None:
            raise ValueError("FreeTLSTransport requires spec= or spec_factory=")
        self._spec = spec
        self._spec_factory = spec_factory
        self.last_session: Optional[TLSSession] = None

    def _factory(self) -> FingerprintSpec:
        return self._spec_factory() if self._spec_factory else self._spec

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        session, status, headers, data = _one_request(request, self._factory())
        self.last_session = session
        data, headers = _decode_content(data, headers)
        try:
            return httpx.Response(
                status_code=status,
                headers=[(k.lower(), v) for k, v in headers],
                content=data,
                request=request,
            )
        finally:
            session.close()

    def close(self) -> None:
        return None


class AsyncFreeTLSTransport(httpx.AsyncBaseTransport):
    """Asynchronous httpx transport (sync engine run in a worker thread)."""

    def __init__(self, spec: Optional[FingerprintSpec] = None,
                 spec_factory: Optional[Callable[[], FingerprintSpec]] = None):
        self._sync = FreeTLSTransport(spec=spec, spec_factory=spec_factory)
        self.last_session: Optional[TLSSession] = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(None, self._sync.handle_request, request)
        self.last_session = self._sync.last_session
        return resp

    async def aclose(self) -> None:
        return None
