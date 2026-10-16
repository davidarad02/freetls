"""A minimal RFC 6455 WebSocket client over a freetls :class:`TLSSession`.

Only the client side is implemented (masked frames, text/binary/ping/pong/close
and fragmentation). Use :func:`connect` after a session handshake to perform the
HTTP/1.1 Upgrade, then drive the returned :class:`WebSocket`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import zlib

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


class WebSocketError(Exception):
    """Raised on a failed handshake or a protocol violation."""


def _read_http_response(session) -> tuple[int, dict, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = session.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1]) if len(lines[0].split(" ")) > 1 else 0
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return status, headers, rest


def connect(
    session,
    host: str,
    path: str = "/",
    *,
    headers=None,
    extra_headers=None,
    timeout=None,
    permessage_deflate: bool = True,
):
    """Perform the WebSocket upgrade over ``session`` and return a WebSocket.

    ``permessage-deflate`` (RFC 7692) is offered by default; it is only used if
    the server accepts it.
    """
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if permessage_deflate:
        lines.append("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits")
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    for name, value in (extra_headers or {}).items():
        lines.append(f"{name}: {value}")
    session.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    status, resp_headers, rest = _read_http_response(session)
    if status != 101:
        raise WebSocketError(f"upgrade failed with status {status}")
    expect = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
    if resp_headers.get("sec-websocket-accept") != expect:
        raise WebSocketError("bad Sec-WebSocket-Accept")
    ext = resp_headers.get("sec-websocket-extensions", "")
    deflate = None
    if permessage_deflate and "permessage-deflate" in ext:
        deflate = {
            "client_no_context_takeover": "client_no_context_takeover" in ext,
            "server_no_context_takeover": "server_no_context_takeover" in ext,
        }
    return WebSocket(session, initial=rest, deflate=deflate)


class WebSocket:
    """A client WebSocket wrapping a :class:`~freetls.session.TLSSession`."""

    def __init__(self, session, initial: bytes = b"", deflate=None):
        self._session = session
        self._closed = False
        # Bytes read past the upgrade response (a server may coalesce the 101
        # and the first frames in one TLS record).
        self._buf = bytearray(initial)
        # RFC 7692 permessage-deflate contexts (None when not negotiated).
        self._deflate_opts = deflate
        self._deflate = None
        self._inflate = None
        if deflate is not None:
            self._deflate = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
            self._inflate = zlib.decompressobj(-15)

    def _compress(self, payload: bytes) -> bytes:
        if self._deflate is None:
            return payload
        out = self._deflate.compress(payload) + self._deflate.flush(zlib.Z_SYNC_FLUSH)
        if out.endswith(b"\x00\x00\xff\xff"):
            out = out[:-4]
        if self._deflate_opts.get("client_no_context_takeover"):
            self._deflate = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        return out

    def _decompress(self, payload: bytes) -> bytes:
        if self._inflate is None:
            return payload
        out = self._inflate.decompress(payload + b"\x00\x00\xff\xff")
        if self._deflate_opts.get("server_no_context_takeover"):
            self._inflate = zlib.decompressobj(-15)
        return out

    def close(self, code: int = 1000, reason: str = "") -> None:
        if not self._closed:
            self._send_frame(_OP_CLOSE, struct.pack(">H", code) + reason.encode(), masked=True)
            self._closed = True

    def send(self, data: str | bytes) -> None:
        if isinstance(data, str):
            self._send_frame(_OP_TEXT, data.encode(), masked=True, compress=True)
        else:
            self._send_frame(_OP_BINARY, data, masked=True, compress=True)

    send_text = send

    def send_binary(self, data: bytes) -> None:
        self._send_frame(_OP_BINARY, data, masked=True, compress=True)

    def ping(self, data: bytes = b"") -> None:
        self._send_frame(_OP_PING, data, masked=True)

    def recv(self) -> str | bytes | None:
        """Receive the next application message (``None`` on close)."""
        data = bytearray()
        message_op = None
        compressed = False
        while True:
            fin, opcode, payload, rsv1 = self._read_frame()
            if opcode == _OP_CLOSE:
                self._closed = True
                return None
            if opcode == _OP_PING:
                self._send_frame(_OP_PONG, payload, masked=True)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode in (_OP_TEXT, _OP_BINARY):
                message_op = opcode
                data = bytearray(payload)
                compressed = rsv1
            elif opcode == _OP_CONT:
                data += payload
            if fin:
                if compressed:
                    data = bytearray(self._decompress(bytes(data)))
                if message_op == _OP_TEXT:
                    return data.decode("utf-8")
                return bytes(data)

    def _send_frame(
        self, opcode: int, payload: bytes, *, masked: bool, compress: bool = False
    ) -> None:
        rsv1 = 0
        if compress and self._deflate is not None:
            payload = self._compress(payload)
            rsv1 = 0x40
        header = bytearray()
        header.append(0x80 | rsv1 | opcode)
        mask_bit = 0x80 if masked else 0
        length = len(payload)
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header += struct.pack(">H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack(">Q", length)
        if masked:
            mask = os.urandom(4)
            header += mask
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._session.sendall(bytes(header) + payload)

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._session.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise WebSocketError("connection closed mid-frame")
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _read_frame(self) -> tuple[bool, int, bytes, bool]:
        b0, b1 = self._read_exact(2)
        fin = bool(b0 & 0x80)
        rsv1 = bool(b0 & 0x40)
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read_exact(8))[0]
        masked = bool(b1 & 0x80)
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(length) if length else b""
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return fin, opcode, payload, rsv1
