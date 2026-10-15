"""Convert a raw ClientHello into a uTLS ``ClientHelloSpec`` JSON document.

This is the inverse of the engine's ``chlo_json`` input: it lets a captured
ClientHello (e.g. from a loopback pcap) be replayed through
``FingerprintSpec(chlo_json=...)``. GREASE slots and compression methods are
normalised; unrepresentable extensions raise :class:`SpecError`.
"""

from __future__ import annotations

import json

from ..errors import SpecError
from .parse import is_grease, parse_client_hello

__all__ = ["chlo_json_from_raw"]

_EXT_NAME = {
    0x0000: "server_name",
    0x0005: "status_request",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000D: "signature_algorithms",
    0x0010: "application_layer_protocol_negotiation",
    0x0012: "signed_certificate_timestamp",
    0x0017: "extended_master_secret",
    0x0023: "session_ticket",
    0x002B: "supported_versions",
    0x002D: "psk_key_exchange_modes",
    0x0033: "key_share",
    0x4469: "application_settings",
}

_VERSION_NAME = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

_POINT_NAME = {
    0: "uncompressed",
    1: "ansiX962_compressed_prime",
    2: "ansiX962_compressed_char2",
}

_PSK_MODE_NAME = {0: "psk_ke", 1: "psk_dhe_ke"}


def _version_name(v: int) -> str:
    name = _VERSION_NAME.get(v)
    if name is None:
        raise SpecError(f"cannot represent TLS version 0x{v:04x}")
    return name


def _group_name(v: int) -> str:
    from .tables import group_name

    name = group_name(v)
    if name is None:
        raise SpecError(f"unknown named group: {v}")
    return name.lower()


def _sigalg_name(v: int) -> str:
    from .tables import sigalg_name

    name = sigalg_name(v)
    if name is None:
        raise SpecError(f"unknown signature scheme: {v}")
    return name.lower()


def _key_share_groups(data: bytes) -> list[int]:
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    off = 2
    out: list[int] = []
    while off + 4 <= len(data) and off < 2 + total:
        group = int.from_bytes(data[off : off + 2], "big")
        klen = int.from_bytes(data[off + 2 : off + 4], "big")
        off += 4 + klen
        out.append(group)
    return out


def _psk_modes(data: bytes) -> list[int]:
    return list(data[1 : 1 + data[0]]) if data else []


def _alps_protocols(data: bytes) -> list[str]:
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    off = 2
    out: list[str] = []
    while off < 2 + total and off < len(data):
        ln = data[off]
        off += 1
        out.append(data[off : off + ln].decode("latin-1"))
        off += ln
    return out


def chlo_json_from_raw(raw: bytes) -> str:
    """Return a uTLS ``ClientHelloSpec`` JSON document for ``raw``."""
    from .tables import cipher_name

    ch = parse_client_hello(raw)

    ciphers = []
    for c in ch.ciphers:
        if is_grease(c):
            continue
        name = cipher_name(c)
        if name is None:
            raise SpecError(f"cannot represent cipher suite 0x{c:04x}")
        ciphers.append(name)

    extensions = []
    for e in ch.extensions:
        if is_grease(e.type):
            continue
        name = _EXT_NAME.get(e.type)
        if name is None:
            raise SpecError(f"cannot represent extension 0x{e.type:04x}")
        entry: dict = {"name": name}
        if e.type == 0x002B:
            entry["versions"] = [
                _version_name(v) for v in ch.supported_versions if not is_grease(v)
            ]
        elif e.type == 0x000A:
            entry["named_group_list"] = [_group_name(g) for g in ch.supported_groups]
        elif e.type == 0x000B:
            entry["ec_point_format_list"] = [_POINT_NAME[p] for p in ch.ec_point_formats]
        elif e.type == 0x000D:
            entry["supported_signature_algorithms"] = [_sigalg_name(s) for s in ch.sig_algs]
        elif e.type == 0x0033:
            entry["client_shares"] = [{"group": _group_name(g)} for g in _key_share_groups(e.data)]
        elif e.type == 0x002D:
            entry["ke_modes"] = [_PSK_MODE_NAME[m] for m in _psk_modes(e.data)]
        elif e.type == 0x0010:
            entry["protocol_name_list"] = list(ch.alpn_list)
        elif e.type == 0x4469:
            entry["supported_protocols"] = _alps_protocols(e.data)
        extensions.append(entry)

    versions = [v for v in ch.supported_versions if not is_grease(v)]
    min_vers = min(versions) if versions else ch.legacy_version
    max_vers = max(versions) if versions else ch.legacy_version

    doc = {
        "cipher_suites": ciphers,
        "compression_methods": ["NULL"],
        "extensions": extensions,
        "min_vers": min_vers,
        "max_vers": max_vers,
    }
    return json.dumps(doc)
