"""urllib3 connection/pool classes that use the freetls engine for TLS.

When the handshake negotiates ``h2`` the connection executes the request with
the engine's HTTP/2 client; otherwise it falls back to urllib3's HTTP/1.1.
"""

from __future__ import annotations

import io
from typing import Callable

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool, PoolManager
from urllib3._collections import HTTPHeaderDict
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import ProtocolError
from urllib3.response import HTTPResponse as U3Response

from ..model import FingerprintSpec
from ..session import TLSSession
from . import _http2
from ._content import decode_content as _decode_content


class Ja4HTTPSConnection(HTTPSConnection):
    """An HTTPS connection whose TLS is performed by the freetls engine.

    ``_spec_factory`` is set on a dynamically-created subclass by the adapter so
    each connection gets a fresh :class:`FingerprintSpec` (important for the
    random modes).
    """

    _spec_factory: Callable[[], FingerprintSpec] = NotImplemented
    _on_session: Callable[[TLSSession], None] | None = None
    ja4_session: TLSSession | None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h2_req = None

    # -- TLS ----------------------------------------------------------------
    def connect(self) -> None:  # noqa: D401
        HTTPConnection.connect(self)
        assert self.sock is not None
        if self.proxy_is_tunneling and self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.server_hostname or self.host

        spec = self._spec_factory()
        session = TLSSession(spec)
        session.wrap_socket(self.sock, server_hostname)
        self.ja4_session = session
        if self._on_session is not None:
            self._on_session(session)
        self.sock = session
        self.is_verified = bool(spec.verify) or self.proxy_is_verified is True

    def _h2_enabled(self) -> bool:
        return self.ja4_session is not None and _http2.negotiated_h2(self.ja4_session)

    # -- HTTP dispatch ------------------------------------------------------
    def request(self, method, url, body=None, headers=None, **kwargs):  # type: ignore[override]
        if self.sock is None:
            self.connect()
        if self._h2_enabled():
            self._h2_req = (method, url, body, headers)
            return
        return super().request(method, url, body=body, headers=headers, **kwargs)

    def getresponse(self):  # type: ignore[override]
        if self._h2_req is not None:
            method, url, body, headers = self._h2_req
            self._h2_req = None
            return self._h2_getresponse(method, url, body, headers)
        return super().getresponse()

    def _h2_getresponse(self, method, url, body, headers) -> U3Response:
        body_bytes: bytes = b"" if body is None else bytes(body)
        try:
            resp = _http2.execute(self.ja4_session, method, url, headers, body_bytes)
        except Exception as exc:  # noqa: BLE001
            raise ProtocolError(str(exc)) from exc
        hdrs = HTTPHeaderDict()
        for k, v in _http2.header_tuples(resp):
            hdrs.add(k, v)
        data, decoded_headers = _decode_content(resp.get("body", b""), list(hdrs.items()))
        out_headers = HTTPHeaderDict()
        for k, v in decoded_headers:
            out_headers.add(k, v)
        return U3Response(
            body=io.BytesIO(data),
            headers=out_headers,
            status=_http2.status_of(resp),
            version=20,
            version_string="HTTP/2",
            reason="",
            preload_content=False,
            request_method=method,
        )


class Ja4HTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = Ja4HTTPSConnection


def make_pool_manager(
    spec_factory: Callable[[], FingerprintSpec],
    on_session: Callable[[TLSSession], None] | None = None,
) -> type[PoolManager]:
    """Return a PoolManager subclass whose HTTPS pools use the freetls engine."""

    class _Conn(Ja4HTTPSConnection):
        _spec_factory = staticmethod(spec_factory)
        _on_session = staticmethod(on_session) if on_session else None

    class _Pool(Ja4HTTPSConnectionPool):
        ConnectionCls = _Conn

    class _Manager(PoolManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pool_classes_by_scheme = {
                "http": HTTPConnectionPool,
                "https": _Pool,
            }

    return _Manager
