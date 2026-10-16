"""Minimal, dependency-free TLS ClientHello / ServerHello parser.

Parses raw handshake message bytes (starting at the handshake type byte) into
the fields needed to compute JA4/JA3/JA4S fingerprints.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

GREASE = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}


def is_grease(v: int) -> bool:
    return v in GREASE


class ParseError(ValueError):
    pass


@dataclass
class Extension:
    type: int
    data: bytes


@dataclass
class ClientHello:
    legacy_version: int = 0
    ciphers: list[int] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    alpn_list: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    server_names: list[str] = field(default_factory=list)
    raw: bytes = b""

    @property
    def ext_types(self) -> list[int]:
        return [e.type for e in self.extensions]

    @property
    def has_sni(self) -> bool:
        return any(e.type == 0 for e in self.extensions)


@dataclass
class ServerHello:
    legacy_version: int = 0
    cipher: int = 0
    extensions: list[Extension] = field(default_factory=list)
    alpn_list: list[str] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    raw: bytes = b""

    @property
    def ext_types(self) -> list[int]:
        return [e.type for e in self.extensions]


def _u16(b: bytes, off: int) -> int:
    if off + 2 > len(b):
        raise ParseError("truncated u16")
    return struct.unpack_from(">H", b, off)[0]


def _parse_extensions(buf: bytes) -> list[Extension]:
    exts: list[Extension] = []
    off = 0
    while off + 4 <= len(buf):
        etype = _u16(buf, off)
        elen = _u16(buf, off + 2)
        off += 4
        if off + elen > len(buf):
            raise ParseError("extension overruns buffer")
        exts.append(Extension(etype, buf[off : off + elen]))
        off += elen
    return exts


def _parse_alpn(data: bytes) -> list[str]:
    if len(data) < 2:
        return []
    total = _u16(data, 0)
    out = []
    off = 2
    end = min(2 + total, len(data))
    while off < end:
        n = data[off]
        off += 1
        out.append(data[off : off + n].decode("latin-1"))
        off += n
    return out


def _parse_sni(data: bytes) -> list[str]:
    """server_name extension: ServerNameList of (type, opaque name)."""
    if len(data) < 2:
        return []
    total = _u16(data, 0)
    out = []
    off = 2
    end = min(2 + total, len(data))
    while off + 3 <= end:
        n = _u16(data, off + 1)
        off += 3
        out.append(data[off : off + n].decode("latin-1"))
        off += n
    return out


def _parse_u16_list(data: bytes, len_bytes: int) -> list[int]:
    if len(data) < len_bytes:
        return []
    if len_bytes == 2:
        n = _u16(data, 0)
        off = 2
    else:
        n = data[0]
        off = 1
    out = []
    end = min(off + n, len(data))
    while off + 2 <= end:
        out.append(_u16(data, off))
        off += 2
    return out


def _handshake_body(raw: bytes, want_type: int) -> bytes:
    if not raw:
        raise ParseError("empty handshake")
    if raw[0] != want_type:
        raise ParseError(f"expected handshake type {want_type}, got {raw[0]}")
    if len(raw) < 4:
        raise ParseError("truncated handshake header")
    length = int.from_bytes(raw[1:4], "big")
    body = raw[4 : 4 + length]
    if len(body) < length:
        raise ParseError("truncated handshake body")
    return body


def parse_client_hello(raw: bytes) -> ClientHello:
    body = _handshake_body(raw, 1)
    ch = ClientHello(raw=raw)
    if len(body) < 34:
        raise ParseError("client hello too short")
    ch.legacy_version = _u16(body, 0)
    off = 2 + 32  # legacy_version + random
    if off >= len(body):
        raise ParseError("truncated client hello (session id)")
    sid_len = body[off]
    off += 1 + sid_len
    if off + 2 > len(body):
        raise ParseError("truncated client hello (cipher suites)")
    cs_len = _u16(body, off)
    off += 2
    if off + cs_len > len(body):
        raise ParseError("truncated client hello (cipher suites)")
    cs = body[off : off + cs_len]
    off += cs_len
    ch.ciphers = [_u16(cs, i) for i in range(0, len(cs) - 1, 2)]
    if off >= len(body):
        raise ParseError("truncated client hello (compression)")
    comp_len = body[off]
    off += 1 + comp_len
    if off > len(body):
        raise ParseError("truncated client hello (compression)")
    if off + 2 <= len(body):
        ext_len = _u16(body, off)
        off += 2
        ch.extensions = _parse_extensions(body[off : off + ext_len])
    for e in ch.extensions:
        if e.type == 0:  # server_name
            ch.server_names.extend(_parse_sni(e.data))
        elif e.type == 10:  # supported_groups
            ch.supported_groups = _parse_u16_list(e.data, 2)
        elif e.type == 11:  # ec_point_formats
            if e.data:
                n = e.data[0]
                ch.ec_point_formats = list(e.data[1 : 1 + n])
        elif e.type == 13:  # signature_algorithms
            ch.sig_algs = _parse_u16_list(e.data, 2)
        elif e.type == 16:  # ALPN
            ch.alpn_list = _parse_alpn(e.data)
        elif e.type == 43:  # supported_versions
            ch.supported_versions = _parse_u16_list(e.data, 1)
    return ch


def parse_server_hello(raw: bytes) -> ServerHello:
    body = _handshake_body(raw, 2)
    sh = ServerHello(raw=raw)
    if len(body) < 38:
        raise ParseError("server hello too short")
    sh.legacy_version = _u16(body, 0)
    off = 2 + 32
    sid_len = body[off]
    off += 1 + sid_len
    sh.cipher = _u16(body, off)
    off += 2
    comp = body[off]
    off += 1 + comp
    if off + 2 <= len(body):
        ext_len = _u16(body, off)
        off += 2
        sh.extensions = _parse_extensions(body[off : off + ext_len])
    for e in sh.extensions:
        if e.type == 16:
            sh.alpn_list = _parse_alpn(e.data)
        elif e.type == 43 and len(e.data) >= 2:
            # In ServerHello, supported_versions carries a single 2-byte value.
            sh.supported_versions = [_u16(e.data, 0)]
    return sh
