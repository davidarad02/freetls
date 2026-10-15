"""Local test helpers for P8: HTTP CONNECT proxy, SOCKS5 proxy, WS echo server.

All servers bind loopback only and never touch the network.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import struct
import threading

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _pump(a: socket.socket, b: socket.socket) -> None:
    def copy(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    t = threading.Thread(target=copy, args=(b, a), daemon=True)
    t.start()
    copy(a, b)
    t.join(timeout=5)


class _Server:
    def __init__(self, handler, **kwargs):
        self._handler = handler
        self._kwargs = kwargs
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handler, args=(conn,), daemon=True).start()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def _read_headers(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class HTTPConnectProxy(_Server):
    def __init__(self, auth: tuple[str, str] | None = None, status: int = 200):
        self.auth = auth
        self.status = status
        super().__init__(self._handle)

    def _handle(self, conn):
        try:
            request = _read_headers(conn)
            lines = request.decode("latin-1").split("\r\n")
            method, target = lines[0].split(" ")[:2]
            if method != "CONNECT":
                conn.sendall(b"HTTP/1.1 405\r\n\r\n")
                return
            if self.auth is not None:
                want = base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
                got = ""
                for line in lines[1:]:
                    if line.lower().startswith("proxy-authorization:"):
                        got = line.split(":", 1)[1].strip().replace("Basic ", "")
                if got != want:
                    conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    return
            if self.status != 200:
                conn.sendall(f"HTTP/1.1 {self.status} Nope\r\n\r\n".encode())
                return
            host, _, port = target.partition(":")
            upstream = socket.create_connection((host, int(port)))
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _pump(conn, upstream)
        except OSError:
            pass
        finally:
            conn.close()


class Socks5Proxy(_Server):
    def __init__(self, auth: tuple[str, str] | None = None):
        self.auth = auth
        super().__init__(self._handle)

    def _handle(self, conn):
        try:
            greeting = conn.recv(2)
            nmethods = greeting[1]
            conn.recv(nmethods)
            if self.auth is not None:
                conn.sendall(b"\x05\x02")
                ver = conn.recv(1)
                assert ver == b"\x01"
                ulen = conn.recv(1)[0]
                user = conn.recv(ulen)
                plen = conn.recv(1)[0]
                pwd = conn.recv(plen)
                if (user.decode(), pwd.decode()) != self.auth:
                    conn.sendall(b"\x01\x01")
                    return
                conn.sendall(b"\x01\x00")
            else:
                conn.sendall(b"\x05\x00")
            head = conn.recv(4)
            atyp = head[3]
            if atyp == 1:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:
                length = conn.recv(1)[0]
                host = conn.recv(length).decode()
            else:
                host = socket.inet_ntoa(conn.recv(4))
            port = struct.unpack(">H", conn.recv(2))[0]
            upstream = socket.create_connection((host, port))
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
            _pump(conn, upstream)
        except OSError:
            pass
        finally:
            conn.close()


class WSEchoServer:
    """A minimal TLS WebSocket echo server (RFC 6455, text/binary echo)."""

    def __init__(self, cert: str, key: str):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn = self._ctx.wrap_socket(conn, server_side=True)
        except OSError:
            return
        try:
            request = _read_headers(conn)
            key = ""
            for line in request.decode("latin-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode()
            )
            while True:
                header = self._recv_exact(conn, 2)
                opcode = header[0] & 0x0F
                length = header[1] & 0x7F
                if length == 126:
                    length = struct.unpack(">H", self._recv_exact(conn, 2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", self._recv_exact(conn, 8))[0]
                mask = self._recv_exact(conn, 4)
                payload = self._recv_exact(conn, length) if length else b""
                if opcode == 0x8:
                    conn.sendall(b"\x88\x00")
                    break
                unmasked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                out = bytes([0x80 | opcode])
                n = len(unmasked)
                if n < 126:
                    out += bytes([n])
                else:
                    out += b"\x7e" + struct.pack(">H", n)
                conn.sendall(out + unmasked)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _recv_exact(self, conn, n) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise OSError("closed")
            data += chunk
        return data

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
