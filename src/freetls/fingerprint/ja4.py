"""JA4 (TLS client) fingerprint, per the FoxIO specification.

Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
"""

from __future__ import annotations

from hashlib import sha256

from .parse import ClientHello, is_grease, parse_client_hello

_VERSION_MAP = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}


def first_last_alpn(alpn) -> str:
    """First + last char of the first ALPN value, or '00'.

    Mirrors the FoxIO reference: non-ASCII endpoints become '9'.
    """
    if isinstance(alpn, (list, tuple)):
        alpn = alpn[0] if alpn else ""
    if not alpn:
        return "00"
    first = alpn[0] if ord(alpn[0]) < 128 else "9"
    last = alpn[-1] if ord(alpn[-1]) < 128 else "9"
    return f"{first}{last}"


def _version_string(ch: ClientHello) -> str:
    if ch.supported_versions:
        real = sorted(v for v in ch.supported_versions if not is_grease(v))
        if real:
            return _VERSION_MAP.get(real[-1], "00")
    return _VERSION_MAP.get(ch.legacy_version, "00")


def _sha12(text: str) -> str:
    return sha256(text.encode("utf8")).hexdigest()[:12]


def to_ja4(ch: ClientHello, *, transport: str = "t") -> dict:
    """Compute JA4 and its raw variants from a parsed ClientHello.

    ``transport`` is the leading fingerprint character: ``"t"`` for TLS over
    TCP (the default) or ``"q"`` for QUIC. Per the FoxIO spec the rest of the
    algorithm is identical; only the prefix differs.
    """
    if transport not in ("t", "q"):
        raise ValueError(f"transport must be 't' or 'q', got {transport!r}")
    ptype = transport
    version = _version_string(ch)
    sni = "d" if ch.has_sni else "i"
    alpn = first_last_alpn(ch.alpn_list)

    real_ciphers = [c for c in ch.ciphers if not is_grease(c)]
    real_exts = [e for e in ch.ext_types if not is_grease(e)]
    sig_algs = [s for s in ch.sig_algs if not is_grease(s)]

    cipher_count = min(len(real_ciphers), 99)
    ext_count = min(len(real_exts), 99)

    sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(real_ciphers))
    original_ciphers = ",".join(f"{c:04x}" for c in real_ciphers)

    hash_exts = sorted(f"{e:04x}" for e in real_exts if e not in (0x0000, 0x0010))
    sorted_ext_str = ",".join(hash_exts)
    # "original" extensions keep SNI/ALPN and their wire order.
    original_ext_str = ",".join(f"{e:04x}" for e in real_exts)
    sig_str = ",".join(f"{s:04x}" for s in sig_algs)
    if sig_str:
        sorted_ext_str += "_" + sig_str
        original_ext_str += "_" + sig_str

    b = _sha12(sorted_ciphers) if real_ciphers else "000000000000"
    c = _sha12(sorted_ext_str) if sorted_ext_str else "000000000000"
    b_o = _sha12(original_ciphers) if real_ciphers else "000000000000"
    c_o = _sha12(original_ext_str) if original_ext_str else "000000000000"

    a = f"{ptype}{version}{sni}{cipher_count:02d}{ext_count:02d}{alpn}"

    return {
        "ja4": f"{a}_{b}_{c}",
        "ja4_r": f"{a}_{sorted_ciphers}_{sorted_ext_str}",
        "ja4_o": f"{a}_{b_o}_{c_o}",
        "ja4_ro": f"{a}_{original_ciphers}_{original_ext_str}",
        "ja4_a": a,
        "ja4_b": b,
        "ja4_c": c,
        "ciphers": real_ciphers,
        "extensions": real_exts,
        "sig_algs": sig_algs,
        "alpn": alpn,
        "version": version,
        "sni": sni,
    }


def ja4_from_bytes(raw_client_hello: bytes, *, transport: str = "t") -> dict:
    return to_ja4(parse_client_hello(raw_client_hello), transport=transport)


# Extension kind -> wire type id (for computing JA4 from a spec offline).
_KIND_ID = {
    "sni": 0x0000,
    "alpn": 0x0010,
    "supported_versions": 0x002B,
    "supported_curves": 0x000A,
    "ec_point_formats": 0x000B,
    "signature_algorithms": 0x000D,
    "key_share": 0x0033,
    "psk_key_exchange_modes": 0x002D,
    "extended_master_secret": 0x0017,
    "renegotiation_info": 0xFF01,
    "session_ticket": 0x0023,
    "status_request": 0x0005,
    "sct": 0x0012,
    "compress_certificate": 0x001B,
    "record_size_limit": 0x001C,
    "pre_shared_key": 0x0029,
    "padding": 0x0015,
    "application_settings": 0x4469,
    "quic_transport_parameters": 0x0039,
}


def spec_to_client_hello(spec):
    """Build a synthetic ClientHello from a FingerprintSpec (offline JA4)."""
    from .parse import ClientHello
    from .parse import Extension as PExt

    exts = []
    sig_algs = []
    supported_versions = []
    alpn = []
    for e in spec.extensions:
        if e.kind == "generic":
            exts.append(PExt(e.id, b""))
            continue
        if e.kind == "grease":
            continue
        ext_id = _KIND_ID.get(e.kind)
        if ext_id is None:
            continue
        exts.append(PExt(ext_id, b""))
        if e.kind == "signature_algorithms":
            sig_algs = list(e.values)
        elif e.kind == "supported_versions":
            supported_versions = list(e.values)
        elif e.kind == "alpn":
            alpn = list(e.strings)
    if spec.server_name is None:
        exts = [x for x in exts if x.type != 0]
    ch = ClientHello(
        legacy_version=spec.vers_max,
        ciphers=list(spec.ciphers),
        extensions=exts,
        sig_algs=sig_algs,
        alpn_list=alpn,
        supported_versions=supported_versions,
    )
    return ch


def ja4_from_spec(spec, *, transport: str = "t") -> dict:
    return to_ja4(spec_to_client_hello(spec), transport=transport)
