"""Proxy tunneling helpers (HTTP CONNECT, SOCKS5, SOCKS4/4a).

These establish a plain TCP tunnel through a proxy; the freetls engine then
performs the TLS handshake over the returned socket. They use only the standard
library, so the core keeps no runtime dependencies.
"""

from __future__ import annotations

import socket
import struct
from urllib.parse import urlsplit


class ProxyError(OSError):
    """Raised when a proxy tunnel cannot be established."""


def _parse_proxy(proxy: str):
    if "://" not in proxy:
        proxy = "http://" + proxy
    url = urlsplit(proxy)
    scheme = url.scheme.lower()
    if scheme not in ("http", "https", "socks5", "socks5h", "socks4", "socks4a"):
        raise ProxyError(f"unsupported proxy scheme: {scheme!r}")
    host = url.hostname
    if not host:
        raise ProxyError(f"invalid proxy URL: {proxy!r}")
    port = url.port or (1080 if scheme.startswith("socks") else 8080)
    return scheme, host, port, url.username, url.password


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = b""
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def http_connect(
    sock: socket.socket,
    host: str,
    port: int,
    *,
    username: str | None = None,
    password: str | None = None,
    headers: dict | None = None,
) -> socket.socket:
    """Tunnel an already-connected socket through an HTTP CONNECT proxy."""
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if username is not None:
        import base64

        token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    response = _recv_until(sock, b"\r\n\r\n")
    status_line = response.split(b"\r\n", 1)[0]
    if b" 200" not in status_line:
        raise ProxyError(f"CONNECT failed: {status_line.decode('latin-1', 'replace')}")
    return sock


def socks5_connect(
    sock: socket.socket,
    host: str,
    port: int,
    *,
    username: str | None = None,
    password: str | None = None,
) -> socket.socket:
    """Tunnel an already-connected socket through a SOCKS5 proxy."""
    if username is not None:
        sock.sendall(b"\x05\x02\x00\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    choice = sock.recv(2)
    if len(choice) != 2 or choice[0] != 5:
        raise ProxyError("bad SOCKS5 greeting response")
    if choice[1] == 2:
        user = (username or "").encode()
        pwd = (password or "").encode()
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
        auth = sock.recv(2)
        if len(auth) != 2 or auth[1] != 0:
            raise ProxyError("SOCKS5 authentication failed")
    elif choice[1] != 0:
        raise ProxyError("SOCKS5 proxy requires an unsupported auth method")
    name = host.encode()
    request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port)
    sock.sendall(request)
    head = sock.recv(4)
    if len(head) != 4 or head[1] != 0:
        raise ProxyError(f"SOCKS5 connect failed (reply {head[1] if len(head) > 1 else '?'})")
    atyp = head[3]
    if atyp == 1:
        _recv_exact(sock, 4)
    elif atyp == 4:
        _recv_exact(sock, 16)
    elif atyp == 3:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    _recv_exact(sock, 2)
    return sock


def socks4_connect(
    sock: socket.socket, host: str, port: int, *, username: str = "", socks4a: bool = True
) -> socket.socket:
    """Tunnel an already-connected socket through a SOCKS4/4a proxy."""
    user = username.encode()
    try:
        ip = socket.inet_aton(socket.gethostbyname(host))
        tail = b""
    except OSError:
        if not socks4a:
            raise
        ip = b"\x00\x00\x00\x01"
        tail = host.encode() + b"\x00"
    request = b"\x04\x01" + struct.pack(">H", port) + ip + user + b"\x00" + tail
    sock.sendall(request)
    reply = _recv_exact(sock, 8)
    if len(reply) != 8 or reply[1] != 90:
        raise ProxyError(f"SOCKS4 connect failed (code {reply[1] if len(reply) > 1 else '?'})")
    return sock


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def open_tunnel(
    proxy: str,
    host: str,
    port: int,
    *,
    timeout: float | None = None,
    headers: dict | None = None,
) -> socket.socket:
    """Open a TCP connection through ``proxy`` to ``host:port``."""
    scheme, phost, pport, user, password = _parse_proxy(proxy)
    sock = socket.create_connection((phost, pport), timeout=timeout)
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        if scheme in ("http", "https"):
            http_connect(sock, host, port, username=user, password=password, headers=headers)
        elif scheme in ("socks5", "socks5h"):
            socks5_connect(sock, host, port, username=user, password=password)
        else:
            socks4_connect(sock, host, port, username=user or "", socks4a=scheme == "socks4a")
    except Exception:
        sock.close()
        raise
    if timeout is not None:
        sock.settimeout(None)
    return sock
