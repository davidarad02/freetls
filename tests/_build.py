"""Helpers to synthesize raw TLS handshake messages for tests."""
from __future__ import annotations

import struct


def _u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _u24(v: int) -> bytes:
    return v.to_bytes(3, "big")


def ext(etype: int, data: bytes = b"") -> bytes:
    return _u16(etype) + _u16(len(data)) + data


def sni_ext(hostname: str) -> bytes:
    name = hostname.encode()
    entry = b"\x00" + _u16(len(name)) + name
    return ext(0x0000, _u16(len(entry)) + entry)


def alpn_ext(*protocols: str) -> bytes:
    body = b"".join(bytes([len(p)]) + p.encode() for p in protocols)
    return ext(0x0010, _u16(len(body)) + body)


def sigalgs_ext(*algs: int) -> bytes:
    body = b"".join(_u16(a) for a in algs)
    return ext(0x000D, _u16(len(body)) + body)


def supported_versions_ext(*versions: int) -> bytes:
    body = bytes([2 * len(versions)]) + b"".join(_u16(v) for v in versions)
    return ext(0x002B, body)


def supported_groups_ext(*groups: int) -> bytes:
    body = _u16(2 * len(groups)) + b"".join(_u16(g) for g in groups)
    return ext(0x000A, body)


def ec_point_formats_ext(*formats: int) -> bytes:
    return ext(0x000B, bytes([len(formats)]) + bytes(formats))


def build_client_hello(
    ciphers: list[int],
    extensions: list[bytes],
    legacy_version: int = 0x0303,
    random: bytes = b"\x00" * 32,
) -> bytes:
    ciphers_b = b"".join(_u16(c) for c in ciphers)
    exts_b = b"".join(extensions)
    body = bytearray()
    body += _u16(legacy_version)
    body += random
    body += b"\x00"  # session id length
    body += _u16(len(ciphers_b)) + ciphers_b
    body += b"\x01\x00"  # compression methods: null
    body += _u16(len(exts_b)) + exts_b
    return b"\x01" + _u24(len(body)) + bytes(body)


def build_server_hello(
    cipher: int,
    extensions: list[bytes],
    legacy_version: int = 0x0303,
    random: bytes = b"\x00" * 32,
) -> bytes:
    exts_b = b"".join(extensions)
    body = bytearray()
    body += _u16(legacy_version)
    body += random
    body += b"\x00"  # session id length
    body += _u16(cipher)
    body += b"\x00"  # compression method
    body += _u16(len(exts_b)) + exts_b
    return b"\x02" + _u24(len(body)) + bytes(body)
