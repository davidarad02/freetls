"""JA3 (TLS client) fingerprint.

JA3 = md5("SSLVersion,Cipher,SSLExtension,EllipticCurve,ECPointFormat") with
decimal values joined by '-' within each field and ',' between fields, GREASE
values removed.
"""
from __future__ import annotations

from hashlib import md5

from .parse import ClientHello, is_grease, parse_client_hello


def _dec_join(values) -> str:
    return "-".join(str(v) for v in values if not is_grease(v))


def ja3_string(ch: ClientHello) -> str:
    version = str(ch.legacy_version)
    ciphers = _dec_join(ch.ciphers)
    extensions = _dec_join(ch.ext_types)
    curves = _dec_join(ch.supported_groups)
    points = _dec_join(ch.ec_point_formats)
    return f"{version},{ciphers},{extensions},{curves},{points}"


def to_ja3(ch: ClientHello) -> dict:
    s = ja3_string(ch)
    return {"ja3": md5(s.encode("utf8")).hexdigest(), "ja3_string": s}


def ja3_from_bytes(raw_client_hello: bytes) -> dict:
    return to_ja3(parse_client_hello(raw_client_hello))
