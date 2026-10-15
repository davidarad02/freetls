"""P2: timeouts actually bound engine I/O; socket parity helpers."""

from __future__ import annotations

import io
import socket
import ssl
import threading
import time

import pytest

import freetls
from freetls import modes
from freetls.errors import EngineError, HandshakeError


class _SilentTLSServer:
    """Completes the TLS handshake, then never sends application data."""

    def __init__(self, cert, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self._ctx = ctx
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            self._conn = self._ctx.wrap_socket(conn, server_side=True)
        except Exception:
            return
        self._stop.wait(10)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._sock.close()


class _BlackholeServer:
    """Accepts TCP but never speaks TLS (handshake will stall)."""

    def __init__(self):
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        self._stop.wait(10)
        conn.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._sock.close()


@pytest.fixture(scope="module")
def silent_server(certs):
    cert, key = certs
    with _SilentTLSServer(cert, key) as srv:
        yield srv


def test_read_timeout_on_silent_server(silent_server):
    spec = modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", silent_server.port, server_hostname="localhost")
        s.settimeout(0.4)
        start = time.time()
        with pytest.raises(EngineError):
            s.recv(16)
        assert 0.2 < time.time() - start < 3


def test_handshake_timeout_covers_connect():
    with _BlackholeServer() as bh:
        spec = modes.baseline_spec(server_name="localhost")
        start = time.time()
        with pytest.raises(HandshakeError):
            s = freetls.TLSSession(spec)
            s.connect("127.0.0.1", bh.port, timeout=0.5, server_hostname="localhost")
        assert time.time() - start < 5


def test_socket_parity_helpers(tls_server_13):
    spec = modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.pending() == 0
        s.setblocking(True)  # no-op
        with pytest.raises(NotImplementedError):
            s.setblocking(False)
        assert s.gettimeout() is None
        req = io.BytesIO(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        sent = s.sendfile(req)
        assert sent == req.getbuffer().nbytes
        assert b"HTTP/1.0 200" in s.recv(256)
