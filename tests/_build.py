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


# A minimal, valid uTLS ClientHelloSpec JSON document (TLS 1.3).
CHLO_JSON = """{
  "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
  "compression_methods": ["NULL"],
  "extensions": [
    {"name": "server_name"},
    {"name": "extended_master_secret"},
    {"name": "supported_versions", "versions": ["TLS 1.3", "TLS 1.2"]},
    {"name": "supported_groups", "named_group_list": ["x25519", "secp256r1"]},
    {"name": "ec_point_formats", "ec_point_format_list": ["uncompressed"]},
    {"name": "signature_algorithms",
     "supported_signature_algorithms": ["ecdsa_secp256r1_sha256",
                                        "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"]},
    {"name": "key_share", "client_shares": [{"group": "x25519"}]},
    {"name": "psk_key_exchange_modes", "ke_modes": ["psk_dhe_ke"]},
    {"name": "application_layer_protocol_negotiation",
     "protocol_name_list": ["h2", "http/1.1"]}
  ],
  "min_vers": 771,
  "max_vers": 772
}"""
