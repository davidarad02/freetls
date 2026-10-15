"""urllib3 connection/pool classes that use the freetls engine for TLS."""
from __future__ import annotations

from typing import Callable

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool, PoolManager
from urllib3.connection import HTTPConnection, HTTPSConnection

from ..errors import HandshakeError
from ..model import FingerprintSpec
from ..session import TLSSession


class Ja4HTTPSConnection(HTTPSConnection):
    """An HTTPS connection whose TLS is performed by the freetls engine.

    ``_spec_factory`` is set on a dynamically-created subclass by the adapter so
    each connection gets a fresh :class:`FingerprintSpec` (important for the
    random modes).
    """

    _spec_factory: Callable[[], FingerprintSpec] = NotImplemented
    _on_session: Callable[[TLSSession], None] | None = None
    ja4_session: TLSSession | None = None

    def connect(self) -> None:  # noqa: D401
        # Establish TCP (and any proxy tunnel) with urllib3's HTTP path.
        HTTPConnection.connect(self)
        assert self.sock is not None
        if self.proxy_is_tunneling and self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.server_hostname or self.host

        spec = self._spec_factory()
        session = TLSSession(spec)
        try:
            session.wrap_socket(self.sock, server_hostname)
        except HandshakeError:
            raise
        self.ja4_session = session
        if self._on_session is not None:
            self._on_session(session)
        self.sock = session
        self.is_verified = bool(spec.verify) or self.proxy_is_verified is True


class Ja4HTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = Ja4HTTPSConnection


def make_pool_manager(
    spec_factory: Callable[[], FingerprintSpec],
    on_session: Callable[[TLSSession], None] | None = None,
) -> PoolManager:
    """Return a PoolManager whose HTTPS pools use the freetls engine."""

    class _Conn(Ja4HTTPSConnection):
        _spec_factory = staticmethod(spec_factory)
        _on_session = staticmethod(on_session) if on_session else None

    class _Pool(Ja4HTTPSConnectionPool):
        ConnectionCls = _Conn

    class _Manager(PoolManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # PoolManager.__init__ resets this attribute, so set it afterwards.
            self.pool_classes_by_scheme = {
                "http": HTTPConnectionPool,
                "https": _Pool,
            }

    return _Manager
