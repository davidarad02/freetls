"""JA4S (TLS server response / session) fingerprint, per the FoxIO reference.

JA4S = t{version}{ext_count}{alpn}_{cipher}_{extensions_hash}

- version: selected version (supported_versions if present, else legacy).
- ext_count: number of ServerHello extensions (GREASE included), capped 99.
- alpn: first/last char of the selected ALPN, or '00' (usually '00' on TLS 1.3
  because ALPN is in the encrypted EncryptedExtensions message).
- cipher: 4-hex of the single selected cipher suite.
- extensions_hash: sha256 of the ServerHello extension IDs in wire order,
  comma-joined hex, first 12 chars; '000000000000' if none.
"""

from __future__ import annotations

from hashlib import sha256

from .ja4 import _VERSION_MAP, first_last_alpn
from .parse import ServerHello, is_grease, parse_server_hello


def _version_string(sh: ServerHello) -> str:
    if sh.supported_versions:
        real = sorted(v for v in sh.supported_versions if not is_grease(v))
        if real:
            return _VERSION_MAP.get(real[-1], "00")
    return _VERSION_MAP.get(sh.legacy_version, "00")


def to_ja4s(sh: ServerHello, *, transport: str = "t") -> dict:
    """Compute JA4S from a parsed ServerHello.

    ``transport`` is the leading character: ``"t"`` for TLS over TCP (default)
    or ``"q"`` for QUIC. As with JA4, only the prefix differs.
    """
    if transport not in ("t", "q"):
        raise ValueError(f"transport must be 't' or 'q', got {transport!r}")
    ptype = transport
    version = _version_string(sh)
    ext_types = sh.ext_types
    ext_count = min(len(ext_types), 99)
    alpn = first_last_alpn(sh.alpn_list)
    cipher = f"{sh.cipher:04x}"
    if ext_types:
        ext_str = ",".join(f"{e:04x}" for e in ext_types)
        ext_hash = sha256(ext_str.encode("utf8")).hexdigest()[:12]
    else:
        ext_str = ""
        ext_hash = "000000000000"
    a = f"{ptype}{version}{ext_count:02d}{alpn}"
    return {
        "ja4s": f"{a}_{cipher}_{ext_hash}",
        "ja4s_r": f"{a}_{cipher}_{ext_str}",
        "ja4s_a": a,
    }


def ja4s_from_bytes(raw_server_hello: bytes, *, transport: str = "t") -> dict:
    return to_ja4s(parse_server_hello(raw_server_hello), transport=transport)
