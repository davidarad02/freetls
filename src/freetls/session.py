"""High-level TLS session: connect, handshake, fingerprint, read/write."""
from __future__ import annotations

import io
import os
import socket
from typing import Optional

from .engine import EngineSession, EngineState
from .errors import HandshakeError
from .fingerprint import ja3_from_bytes, ja4_from_bytes, ja4s_from_bytes
from .model import FingerprintSpec


class _SocketRawIO(io.RawIOBase):
    """Raw IO adapter so ``makefile()`` works over the engine's TLS channel."""

    def __init__(self, session: "TLSSession"):
        self._session = session

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self._session._closed:
            return 0
        data = self._session.recv(len(b))
        if not data:
            return 0
        n = len(data)
        b[:n] = data
        return n


class TLSSession:
    """A connected, fingerprinted TLS session with a socket-like API."""

    def __init__(self, spec: FingerprintSpec):
        self.spec = spec
        self._engine: Optional[EngineSession] = None
        self._sock: Optional[socket.socket] = None
        self._closed = False
        self._client_hello = b""
        self._server_hello = b""
        self._fp: Optional[dict] = None

    # -- connection ----------------------------------------------------------
    def connect(
        self,
        host: str,
        port: int = 443,
        timeout: Optional[float] = None,
        server_hostname: Optional[str] = None,
    ) -> "TLSSession":
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            return self.wrap_socket(sock, server_hostname=server_hostname or host)
        except HandshakeError:
            sock.close()
            raise

    def wrap_socket(self, sock: socket.socket, server_hostname: str) -> "TLSSession":
        """Perform the TLS handshake over an already-connected socket."""
        sni = server_hostname or self.spec.server_name or ""
        self._engine = EngineSession(self.spec.to_engine())
        try:
            fd = os.dup(sock.fileno())
            self._engine.handshake(fd, sni)
        except HandshakeError:
            raise
        self._sock = sock
        self._client_hello = self._engine.client_hello()
        self._server_hello = self._engine.server_hello()
        return self

    # -- socket-like I/O -----------------------------------------------------
    def sendall(self, data) -> None:
        view = memoryview(data)
        total = 0
        while total < len(view):
            n = self._engine.write(view[total:].tobytes())
            if n <= 0:
                raise OSError("engine write returned 0")
            total += n

    def send(self, data) -> int:
        n = self._engine.write(bytes(data))
        return int(n)

    def recv(self, bufsize: int) -> bytes:
        try:
            return self._engine.read(bufsize)
        except Exception:  # noqa: BLE001
            return b""

    def makefile(self, mode: str = "rb", *args, **kwargs):
        raw = _SocketRawIO(self)
        if "b" in mode:
            if "w" in mode:
                raise OSError("write makefile not supported")
            return io.BufferedReader(raw)
        raise OSError("text mode not supported")

    def settimeout(self, value) -> None:
        if self._sock is not None:
            self._sock.settimeout(value)

    def gettimeout(self):
        return self._sock.gettimeout() if self._sock else None

    def fileno(self) -> int:
        return self._sock.fileno() if self._sock else -1

    def shutdown(self, how) -> None:
        try:
            if self._sock is not None:
                self._sock.shutdown(how)
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._engine is not None:
                self._engine.close()
        finally:
            try:
                if self._sock is not None:
                    self._sock.close()
            finally:
                if self._engine is not None:
                    self._engine.free()

    @property
    def closed(self) -> bool:
        return self._closed

    # -- fingerprints --------------------------------------------------------
    @property
    def client_hello(self) -> bytes:
        return self._client_hello

    @property
    def server_hello(self) -> bytes:
        return self._server_hello

    # -- HTTP/2 (Go-side, fingerprinted) ------------------------------------
    def h2_request(
        self,
        path: str = "/",
        method: str = "GET",
        headers=None,
        body: bytes = b"",
        scheme: str = "https",
    ) -> dict:
        """Issue an HTTP/2 request over this connection with full control.

        SETTINGS/WINDOW_UPDATE/pseudo-header order come from the spec's
        ``h2_settings`` / ``h2_window_update`` / ``h2_pseudo_header_order``.
        """
        import base64
        import json as _json

        authority = self.state.server_name or self.spec.server_name or ""
        req = {
            "method": method,
            "scheme": scheme,
            "authority": authority,
            "path": path,
            "headers": [list(h) for h in (headers or [])],
            "body_b64": base64.b64encode(body).decode() if body else "",
            "timeout_ms": self.spec.timeout_ms,
        }
        if self.spec.h2_settings is not None:
            req["settings"] = [{"id": int(i), "value": int(v)} for i, v in self.spec.h2_settings]
        if self.spec.h2_window_update:
            req["window_update"] = int(self.spec.h2_window_update)
        if self.spec.h2_pseudo_header_order is not None:
            req["pseudo_header_order"] = list(self.spec.h2_pseudo_header_order)
        resp = self._engine.h2_request(req)
        if resp.get("body_b64"):
            resp["body"] = base64.b64decode(resp["body_b64"])
        else:
            resp["body"] = b""
        return resp

    @property
    def fingerprints(self) -> dict:
        if self._fp is None:
            fp = {}
            if self._client_hello:
                fp.update(ja4_from_bytes(self._client_hello))
                fp.update(ja3_from_bytes(self._client_hello))
            if self._server_hello:
                fp.update(ja4s_from_bytes(self._server_hello))
            self._fp = fp
        return self._fp

    @property
    def ja4(self) -> Optional[str]:
        return self.fingerprints.get("ja4")

    @property
    def ja4_r(self) -> Optional[str]:
        return self.fingerprints.get("ja4_r")

    @property
    def ja3(self) -> Optional[str]:
        return self.fingerprints.get("ja3")

    @property
    def ja4s(self) -> Optional[str]:
        return self.fingerprints.get("ja4s")

    @property
    def state(self) -> EngineState:
        return self._engine.state() if self._engine else EngineState()

    # ssl.SSLSocket-like accessors ------------------------------------------
    def version(self) -> Optional[str]:
        return self.state.version or None

    def selected_alpn_protocol(self) -> Optional[str]:
        return self.state.alpn or None

    def cipher(self):
        st = self.state
        if not st.cipher_suite:
            return None
        from .fingerprint.tables import cipher_name

        name = cipher_name(st.cipher_suite) or f"0x{st.cipher_suite:04x}"
        return (name, st.version, 128)

    def getpeercert(self, binary_form: bool = False):
        return None

    def server_hostname(self) -> Optional[str]:
        return self.state.server_name or None

    # Context-manager support -------------------------------------------------
    def __enter__(self) -> "TLSSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
