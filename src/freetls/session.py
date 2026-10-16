"""High-level TLS session: connect, handshake, fingerprint, read/write."""

from __future__ import annotations

import io
import os
import socket

from .engine import EngineSession, EngineState
from .errors import FreeTLSError, HandshakeError, SpecError
from .fingerprint import ja3_from_bytes, ja3n_from_bytes, ja4_from_bytes, ja4s_from_bytes
from .model import FingerprintSpec

_VERSION_STR = {"TLS1.3": "TLSv1.3", "TLS1.2": "TLSv1.2", "TLS1.1": "TLSv1.1", "TLS1.0": "TLSv1"}


def _cipher_bits(name: str) -> int:
    n = name.upper()
    if "CHACHA20" in n or "AES_256" in n or "AES256" in n or "ARIA_256" in n:
        return 256
    if "AES_128" in n or "AES128" in n or "ARIA_128" in n or "CAMELLIA_128" in n:
        return 128
    if "3DES" in n:
        return 112
    return 128


class _SocketRawIO(io.RawIOBase):
    """Raw IO adapter so ``makefile()`` works over the engine's TLS channel."""

    def __init__(self, session: TLSSession):
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
        self._engine: EngineSession | None = None
        self._sock: socket.socket | None = None
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
    ) -> TLSSession:
        if timeout is not None:
            # The connect timeout also covers the TLS handshake.
            self.spec.timeout_ms = max(1, int(timeout * 1000))
        from .net import happy_eyeballs

        sock = happy_eyeballs(host, port, timeout)
        try:
            return self.wrap_socket(sock, server_hostname=server_hostname or host)
        except (HandshakeError, SpecError):
            self._cleanup()
            sock.close()
            raise

    def connect_via_proxy(
        self,
        proxy: str,
        host: str,
        port: int = 443,
        timeout: float | None = None,
        server_hostname: str | None = None,
    ) -> TLSSession:
        """Connect to ``host``/``port`` through ``proxy`` (HTTP CONNECT or SOCKS)."""
        from .transport.proxy import open_tunnel

        if timeout is not None:
            self.spec.timeout_ms = max(1, int(timeout * 1000))
        sock = open_tunnel(proxy, host, port, timeout=timeout)
        try:
            return self.wrap_socket(sock, server_hostname=server_hostname or host)
        except (HandshakeError, SpecError):
            self._cleanup()
            sock.close()
            raise

    def wrap_socket(
        self,
        sock: socket.socket,
        server_hostname: str,
        do_handshake_on_connect: bool = True,
    ) -> TLSSession:
        """Wrap an already-connected socket, performing the TLS handshake.

        With ``do_handshake_on_connect=False`` the handshake is deferred until
        :meth:`do_handshake` is called (mirrors ``ssl.SSLContext``).
        """
        self._sock = sock
        self._sni = server_hostname or self.spec.server_name or ""
        if do_handshake_on_connect:
            self.do_handshake()
        return self

    def do_handshake(self) -> None:
        """Perform (or complete) the TLS handshake."""
        if self._handshaked:
            return
        if self._sock is None:
            raise FreeTLSError("cannot handshake: no socket; call connect()/wrap_socket() first")
        from .safety import validate

        validate(self.spec)
        self._engine = EngineSession(self.spec.to_engine())
        try:
            fd = os.dup(self._sock.fileno())
            self._engine.handshake(fd, self._sni)
        except HandshakeError:
            self._engine.free()
            self._engine = None
            raise
        self._handshaked = True
        self._client_hello = self._engine.client_hello()
        self._server_hello = self._engine.server_hello()
        self._fp = None

    def _require_engine(self) -> EngineSession:
        if self._engine is None or not self._handshaked:
            raise FreeTLSError("TLS session is not connected (call connect() first)")
        return self._engine

    # -- socket-like I/O -----------------------------------------------------
    def sendall(self, data) -> None:
        engine = self._require_engine()
        view = memoryview(data)
        total = 0
        while total < len(view):
            n = engine.write(view[total:].tobytes())
            if n <= 0:
                raise FreeTLSError("engine write returned 0")
            total += n

    def send(self, data) -> int:
        engine = self._require_engine()
        return int(engine.write(bytes(data)))

    def recv(self, bufsize: int) -> bytes:
        engine = self._require_engine()
        return engine.read(bufsize)  # raises EngineError on failure; b"" on EOF

    def recv_into(self, buffer, nbytes: int = 0) -> int:
        size = nbytes or len(buffer)
        data = self.recv(size)
        n = len(data)
        buffer[:n] = data
        return n

    def makefile(self, mode: str = "rb", *args, **kwargs):
        raw = _SocketRawIO(self)
        if "b" in mode:
            if "w" in mode:
                raise FreeTLSError("write makefile not supported")
            return io.BufferedReader(raw)
        raise FreeTLSError("text mode not supported")

    def settimeout(self, value) -> None:
        """Set the read/write timeout (seconds; None = block forever).

        Applies to both the underlying TCP socket and the TLS engine reads.
        """
        ms = 0 if value is None else max(1, int(value * 1000))
        self.spec.timeout_ms = ms
        if self._sock is not None:
            self._sock.settimeout(value)
        if self._engine is not None:
            self._engine.set_timeout(ms)

    def gettimeout(self):
        return self._sock.gettimeout() if self._sock else None

    def setblocking(self, flag: bool) -> None:
        """freetls sessions are blocking-only; ``flag=False`` is unsupported."""
        if not flag:
            raise NotImplementedError("freetls sessions are blocking-only")

    def pending(self) -> int:
        """Bytes currently buffered by the engine (not observable via uTLS)."""
        return 0

    def sendfile(self, file, offset: int = 0, count: int | None = None) -> int:
        """Send ``file`` from ``offset`` over the TLS channel; return bytes sent."""
        file.seek(offset)
        data = file.read(count) if count is not None else file.read()
        self.sendall(data)
        return len(data)

    def fileno(self) -> int:
        return self._sock.fileno() if self._sock else -1

    def getpeername(self):
        return self._sock.getpeername() if self._sock else None

    def getsockname(self):
        return self._sock.getsockname() if self._sock else None

    def shutdown(self, how) -> None:
        try:
            if self._sock is not None:
                self._sock.shutdown(how)
        except OSError:
            pass

    def _cleanup(self) -> None:
        try:
            if self._engine is not None:
                self._engine.free()
        finally:
            self._engine = None
            try:
                if self._sock is not None:
                    self._sock.close()
            finally:
                self._sock = None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cleanup()

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
        authority: str | None = None,
    ) -> dict:
        """Issue an HTTP/2 request over this connection with full control.

        SETTINGS/WINDOW_UPDATE/pseudo-header order come from the spec's
        ``h2_settings`` / ``h2_window_update`` / ``h2_pseudo_header_order``.
        """
        import base64

        engine = self._require_engine()
        auth = authority or self.state.server_name or self.spec.server_name or ""
        req = {
            "method": method,
            "scheme": scheme,
            "authority": auth,
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
        resp = engine.h2_request(req)
        if resp.get("body_b64"):
            resp["body"] = base64.b64decode(resp["body_b64"])
        else:
            resp["body"] = b""
        from .fingerprint import akamai_h2_fingerprint, ja4h_from_request

        resp["akamai_h2"] = akamai_h2_fingerprint(
            resp.get("sent_settings", []),
            resp.get("sent_window_update", 0),
            resp.get("sent_pseudo_header_order"),
        )
        resp.update(ja4h_from_request(method, headers or [], version="HTTP/2"))
        return resp

    @property
    def fingerprints(self) -> dict:
        if self._fp is None:
            fp = {}
            if self._client_hello:
                fp.update(ja4_from_bytes(self._client_hello))
                fp.update(ja3_from_bytes(self._client_hello))
                fp.update(ja3n_from_bytes(self._client_hello))
            if self._server_hello:
                fp.update(ja4s_from_bytes(self._server_hello))
            self._fp = fp
        return self._fp

    @property
    def ja4(self) -> str | None:
        return self.fingerprints.get("ja4")

    @property
    def ja4_r(self) -> str | None:
        return self.fingerprints.get("ja4_r")

    @property
    def ja3(self) -> str | None:
        return self.fingerprints.get("ja3")

    @property
    def ja3n(self) -> str | None:
        return self.fingerprints.get("ja3n")

    @property
    def ja4s(self) -> str | None:
        return self.fingerprints.get("ja4s")

    @property
    def state(self) -> EngineState:
        return self._engine.state() if self._engine else EngineState()

    # ssl.SSLSocket-like accessors ------------------------------------------
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
        protocol = _VERSION_STR.get(st.version, st.version)
        return (name, protocol, _cipher_bits(name))

    def peer_chain(self) -> list:
        """The peer certificate chain as a list of DER bytes (leaf first)."""
        return self.state.peer_certs_der

    @property
    def did_resume(self) -> bool:
        """True if the handshake resumed a cached session (ticket or PSK)."""
        return self.state.did_resume

    @property
    def ocsp_response(self) -> bytes:
        """The stapled OCSP response from the server (empty if none)."""
        return self.state.ocsp_response

    @property
    def signed_certificate_timestamps(self) -> list:
        """SCTs provided by the server (list of DER bytes)."""
        return self.state.signed_certificate_timestamps

    @property
    def peer_application_settings(self) -> bytes:
        """ALPS payload advertised by the peer (empty if none)."""
        return self.state.peer_application_settings

    @property
    def ja4x(self) -> str | None:
        """JA4X of the peer's leaf certificate (None without a cert/``cryptography``)."""
        der = self.state.peer_cert_der
        if not der:
            return None
        try:
            from .fingerprint import ja4x_from_cert
        except ImportError:  # pragma: no cover - cryptography is a core test dep
            return None
        return ja4x_from_cert(der)

    def getpeercert(self, binary_form: bool = False):
        der = self.state.peer_cert_der
        if not der:
            return None
        if binary_form:
            return der
        try:
            from cryptography import x509
        except ImportError as exc:  # pragma: no cover
            raise FreeTLSError(
                "getpeercert() without binary_form needs the 'cryptography' extra; "
                "use getpeercert(binary_form=True) instead"
            ) from exc
        cert = x509.load_der_x509_certificate(der)

        def rdn(name):
            return tuple((attr.oid._name, attr.value) for attr in name)

        out: dict = {
            "subject": (rdn(cert.subject),),
            "issuer": (rdn(cert.issuer),),
            "version": cert.version.value,
            "serialNumber": format(cert.serial_number, "x"),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        }
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["subjectAltName"] = tuple(
                ("DNS", str(v)) for v in san.value.get_values_for_type(x509.DNSName)
            )
        except x509.ExtensionNotFound:
            pass
        return out

    def server_hostname(self) -> str | None:
        return self.state.server_name or None

    # Context-manager support -------------------------------------------------
    def __enter__(self) -> TLSSession:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            if not getattr(self, "_closed", True):
                self.close()
        except Exception:  # noqa: BLE001 - never raise from a finalizer
            pass
