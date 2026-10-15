"""aiohttp integration: a TCPConnector that performs TLS with the freetls engine.

aiohttp drives connections through asyncio transports, so this module bridges
the (blocking) freetls engine to an :class:`asyncio.Transport`.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

import aiohttp
from aiohttp.client_proto import ResponseHandler
from aiohttp.connector import TCPConnector
import aiohappyeyeballs

from ..model import FingerprintSpec
from ..session import TLSSession


class _FreetlsTransport(asyncio.Transport):
    """An asyncio.Transport whose reads/writes go through a :class:`TLSSession`."""

    def __init__(self, protocol: asyncio.Protocol, session: TLSSession, loop):
        self._protocol = protocol
        self._session = session
        self._loop = loop
        self._closing = False
        self.last_session = session
        self._reader = loop.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while not self._closing:
                data = await self._loop.run_in_executor(None, self._session.recv, 65536)
                if not data:
                    self._protocol.connection_lost(None)
                    break
                self._protocol.data_received(data)
        except asyncio.CancelledError:  # pragma: no cover
            pass
        except Exception:  # noqa: BLE001
            self._protocol.connection_lost(None)

    def write(self, data) -> None:  # type: ignore[override]
        try:
            self._session.sendall(data)
        except Exception:  # noqa: BLE001
            self._protocol.connection_lost(None)

    def writelines(self, list_of_data) -> None:  # type: ignore[override]
        for d in list_of_data:
            self.write(d)

    def close(self) -> None:  # type: ignore[override]
        if self._closing:
            return
        self._closing = True
        if self._reader is not None and not self._reader.done():
            self._reader.cancel()
        self._session.close()
        self._protocol.connection_lost(None)

    def abort(self) -> None:  # type: ignore[override]
        self.close()

    def is_closing(self) -> bool:  # type: ignore[override]
        return self._closing

    def get_extra_info(self, name, default=None):  # type: ignore[override]
        if name == "sslcontext":
            return None
        if name == "peercert":
            return None
        return self._session._sock.getsockname() if (name == "sockname" and self._session._sock) else default

    def can_write_eof(self) -> bool:  # type: ignore[override]
        return False


class FreeTLSConnector(TCPConnector):
    """aiohttp connector that emits a chosen JA4 fingerprint.

    ``spec`` is a fixed spec or ``spec_factory`` returns a fresh one per
    connection.
    """

    def __init__(self, spec: Optional[FingerprintSpec] = None,
                 spec_factory: Optional[Callable[[], FingerprintSpec]] = None,
                 **kwargs):
        if spec is None and spec_factory is None:
            raise ValueError("FreeTLSConnector requires spec= or spec_factory=")
        self._spec = spec
        self._spec_factory = spec_factory
        self.last_session: Optional[TLSSession] = None
        super().__init__(**kwargs)

    def _build_spec(self) -> FingerprintSpec:
        return self._spec_factory() if self._spec_factory else self._spec

    async def _wrap_create_connection(  # type: ignore[override]
        self,
        *args: Any,
        addr_infos,
        req,
        timeout,
        client_error=aiohttp.ClientConnectorError,
        **kwargs: Any,
    ):
        sock = await aiohappyeyeballs.start_connection(
            addr_infos=addr_infos,
            local_addr_infos=self._local_addr_infos,
            happy_eyeballs_delay=self._happy_eyeballs_delay,
            interleave=self._interleave,
            loop=self._loop,
            socket_factory=self._socket_factory,
        )
        spec = self._build_spec()
        session = TLSSession(spec)
        try:
            await self._loop.run_in_executor(
                None, session.wrap_socket, sock, req.host
            )
        except Exception as exc:  # noqa: BLE001
            sock.close()
            raise client_error(req.connection_key, exc) from exc
        self.last_session = session
        proto = ResponseHandler(loop=self._loop)
        transport = _FreetlsTransport(proto, session, self._loop)
        proto.connection_made(transport)
        return transport, proto
