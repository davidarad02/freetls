"""QUIC / HTTP-3 sessions.

:class:`QUICSession` is the UDP counterpart of
:class:`~freetls.session.TLSSession`: Python owns the connected UDP socket, the
engine (built on the uQUIC fork of quic-go, itself built on our uTLS fork)
drives the QUIC handshake, and the fingerprints are reported with the QUIC
(``q``) transport prefix.

See ``docs/route-c-plan.md``.
"""

from __future__ import annotations

import ipaddress
import os
import socket

from .engine import EngineSession, EngineState
from .errors import EngineError, FreeTLSError, HandshakeError, SpecError
from .fingerprint import ja4_from_bytes, ja4s_from_bytes
from .model import FingerprintSpec

# HTTP/3 is negotiated over ALPN; QUIC connections never offer h2/http1.1.
DEFAULT_QUIC_ALPN = ["h3"]


def _bracket_ipv6(host: str) -> str:
    """Bracket an IPv6 literal for a URL authority; leave other hosts unchanged."""
    if host.startswith("["):
        return host
    try:
        ipaddress.IPv6Address(host)
    except ValueError:
        return host
    return f"[{host}]"


class QUICSession:
    """A connected, fingerprinted QUIC session."""

    def __init__(self, spec: FingerprintSpec):
        self.spec = spec
        self._engine: EngineSession | None = None
        self._sock: socket.socket | None = None
        self._remote: tuple[str, int] | None = None
        self._sni = ""
        self._closed = False
        self._handshaked = False
        self._client_hello = b""
        self._server_hello = b""
        self._fp: dict | None = None

    # -- connection ----------------------------------------------------------
    def connect(
        self,
        host: str,
        port: int = 443,
        timeout: float | None = None,
        server_hostname: str | None = None,
    ) -> QUICSession:
        if timeout is not None:
            # The connect timeout also covers the QUIC handshake.
            self.spec.timeout_ms = max(1, int(timeout * 1000))
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        af, socktype, proto, _, addr = infos[0]
        # The socket stays *unconnected*: quic-go sends with WriteTo, which Go
        # refuses on a pre-connected socket. Python resolves the host and passes
        # the literal IP to the engine instead.
        sock = socket.socket(af, socktype, proto)
        self._remote = (str(addr[0]), int(addr[1]))
        try:
            if timeout is not None:
                sock.settimeout(timeout)
        except OSError:
            sock.close()
            raise
        try:
            return self.wrap_socket(sock, server_hostname=server_hostname or host)
        except (HandshakeError, SpecError, EngineError):
            self._cleanup()
            sock.close()
            raise

    def wrap_socket(
        self,
        sock: socket.socket,
        server_hostname: str,
        do_handshake_on_connect: bool = True,
        host: str | None = None,
        port: int | None = None,
    ) -> QUICSession:
        """Wrap a UDP socket and (by default) perform the QUIC handshake.

        The socket is deliberately *not* connected (quic-go sends with
        ``WriteTo``), so the peer address cannot be inferred in general: pass
        ``host``/``port``, or rely on ``connect()`` (which sets it) or on an
        already-connected socket.
        """
        self._sock = sock
        self._sni = server_hostname or self.spec.server_name or ""
        if host is not None and port is not None:
            self._remote = (host, int(port))
        elif self._remote is None:
            try:
                peer = sock.getpeername()
            except OSError:
                peer = None
            if peer:
                self._remote = (str(peer[0]), int(peer[1]))
        if do_handshake_on_connect:
            self.do_handshake()
        return self

    def do_handshake(self) -> None:
        """Perform (or complete) the QUIC handshake."""
        if self._handshaked:
            return
        if self._sock is None:
            raise FreeTLSError("cannot handshake: no socket; call connect()/wrap_socket() first")
        if self._remote is None:
            raise FreeTLSError("cannot handshake: no peer address; call connect() first")
        from .safety import validate

        validate(self.spec)
        self._engine = EngineSession(self.spec.to_engine())
        try:
            fd = os.dup(self._sock.fileno())
            self._engine.quic_handshake(fd, self._sni, self._remote[0], self._remote[1])
        except HandshakeError:
            self._engine.free()
            self._engine = None
            raise
        self._handshaked = True
        self._client_hello = self._engine.client_hello()
        self._server_hello = self._engine.server_hello()
        self._fp = None

    def _cleanup(self) -> None:
        if self._engine is not None:
            self._engine.close()
            self._engine.free()
            self._engine = None
        self._handshaked = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cleanup()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> QUICSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            if not getattr(self, "_closed", True):
                self.close()
        except Exception:  # noqa: BLE001 - never raise from a finalizer
            pass

    # -- fingerprints --------------------------------------------------------
    @property
    def client_hello(self) -> bytes:
        """The ClientHello the QUIC stack put in the Initial packet's CRYPTO frame."""
        return self._client_hello

    @property
    def fingerprints(self) -> dict:
        if self._fp is None:
            fp: dict = {}
            if self._client_hello:
                fp.update(ja4_from_bytes(self._client_hello, transport="q"))
            self._fp = fp
        return self._fp

    @property
    def ja4q(self) -> str | None:
        return self.fingerprints.get("ja4")

    @property
    def ja4q_r(self) -> str | None:
        return self.fingerprints.get("ja4_r")

    @property
    def ja4sq(self) -> str | None:
        """JA4S for the QUIC handshake.

        QUIC carries the ServerHello in the server's Initial packet, so a
        passive capture cannot recover it (the later Handshake packet is
        encrypted under handshake keys). The engine captures it from the TLS
        stack instead, which is what this reports.
        """
        sh = self.server_hello()
        if not sh:
            return None
        return ja4s_from_bytes(sh, transport="q").get("ja4s")

    def server_hello(self) -> bytes:
        """The ServerHello captured at handshake time (empty if none).

        Cached at handshake time, like :class:`~freetls.TLSSession`, so it
        survives :meth:`close` (the JA4Sq stays readable after the session ends).
        """
        return self._server_hello

    # -- requests ------------------------------------------------------------
    def _require_engine(self) -> EngineSession:
        if self._engine is None:
            raise FreeTLSError("session is not handshaked")
        return self._engine

    def _authority(self, authority: str | None = None) -> str:
        """The ``:authority`` for a request: host plus a non-default port.

        Uses the SNI host when set, otherwise the peer's literal IP; IPv6
        literals are bracketed (an unbracketed ``::1`` would produce an invalid
        URL) and the port is appended only when it is not 443.
        """
        if authority:
            return authority
        host = self._sni or (self._remote[0] if self._remote else "")
        if not host:
            return ""
        host = _bracket_ipv6(host)
        if self._remote is not None and self._remote[1] not in (0, 443):
            return f"{host}:{self._remote[1]}"
        return host

    def request(
        self,
        path: str = "/",
        method: str = "GET",
        headers=None,
        body: bytes = b"",
        scheme: str = "https",
        authority: str | None = None,
    ) -> dict:
        """Issue an HTTP/3 request over this connection.

        The body is buffered (mirrors :meth:`~freetls.TLSSession.h2_request`).
        The Go ``http3.Transport`` multiplexes on the wire, so concurrent calls
        from multiple threads share the one QUIC connection.
        """
        import base64

        engine = self._require_engine()
        req = {
            "method": method,
            "scheme": scheme,
            "authority": self._authority(authority),
            "path": path,
            "headers": [list(h) for h in (headers or [])],
            "body_b64": base64.b64encode(body).decode() if body else "",
            "timeout_ms": self.spec.timeout_ms,
        }
        resp = engine.h3_request(req)
        if resp.get("body_b64"):
            resp["body"] = base64.b64decode(resp["body_b64"])
        else:
            resp["body"] = b""
        from .fingerprint import ja4h_from_request

        resp.update(ja4h_from_request(method, headers or [], version="HTTP/3"))
        return resp

    # -- RFC 9297 datagrams --------------------------------------------------
    def open_datagram_flow(
        self,
        path: str = "/",
        method: str = "GET",
        headers=None,
        scheme: str = "https",
        authority: str | None = None,
    ) -> int:
        """Open an HTTP/3 datagram flow and return its flow ID.

        Datagrams are associated with a request stream (RFC 9297), so a flow is
        opened by sending a request first. ``FingerprintSpec.quic_datagrams``
        must be set or the engine refuses.
        """
        engine = self._require_engine()
        if not self.spec.quic_datagrams:
            raise FreeTLSError("datagrams are not enabled for this session")
        req = {
            "method": method,
            "scheme": scheme,
            "authority": self._authority(authority),
            "path": path,
            "headers": [list(h) for h in (headers or [])],
            "timeout_ms": self.spec.timeout_ms,
        }
        resp = engine.h3_datagram_open(req)
        if resp.get("error"):
            raise FreeTLSError(f"open datagram flow failed: {resp['error']}")
        return int(resp["flow"])

    def send_datagram(self, flow: int, data: bytes) -> None:
        """Send one HTTP/3 datagram on ``flow``."""
        engine = self._require_engine()
        resp = engine.h3_datagram_send(flow, data)
        if resp.get("error"):
            raise FreeTLSError(f"send datagram failed: {resp['error']}")

    def recv_datagram(self, flow: int, timeout: float | None = None) -> bytes:
        """Receive one HTTP/3 datagram on ``flow``."""
        import base64

        engine = self._require_engine()
        ms = 0 if timeout is None else max(1, int(timeout * 1000))
        resp = engine.h3_datagram_recv(flow, ms)
        if resp.get("error"):
            raise FreeTLSError(f"recv datagram failed: {resp['error']}")
        return base64.b64decode(resp["data_b64"]) if resp.get("data_b64") else b""

    def close_datagram_flow(self, flow: int) -> None:
        """Release a datagram flow, freeing its request stream on the peer."""
        engine = self._require_engine()
        resp = engine.h3_datagram_close(flow)
        if resp.get("error"):
            raise FreeTLSError(f"close datagram flow failed: {resp['error']}")

    # -- ssl.SSLSocket-like accessors ---------------------------------------
    @property
    def state(self) -> EngineState:
        return self._engine.state() if self._engine else EngineState()

    def version(self) -> str | None:
        return self.state.version or None

    def selected_alpn_protocol(self) -> str | None:
        return self.state.alpn or None

    def cipher(self):
        st = self.state
        if not st.cipher_suite:
            return None
        from .fingerprint.tables import cipher_name

        name = cipher_name(st.cipher_suite) or f"0x{st.cipher_suite:04x}"
        return (name, st.version, 0)

    def peer_chain(self) -> list:
        """The peer certificate chain as a list of DER bytes (leaf first)."""
        return self.state.peer_certs_der

    @property
    def did_resume(self) -> bool:
        return self.state.did_resume
