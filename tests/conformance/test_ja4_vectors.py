"""Conformance tests against the FoxIO JA4 specification vectors."""

from __future__ import annotations

import _build as B

from freetls.fingerprint import (
    first_last_alpn,
    ja4_from_bytes,
    ja4s_from_bytes,
    parse_client_hello,
)


def test_first_last_alpn_reference_vectors():
    assert first_last_alpn("h2") == "h2"
    assert first_last_alpn("http/1.1") == "h1"
    assert first_last_alpn("x") == "xx"
    assert first_last_alpn("7") == "77"
    assert first_last_alpn("") == "00"
    assert first_last_alpn(None) == "00"
    assert first_last_alpn([]) == "00"
    assert first_last_alpn(["", "h2"]) == "00"
    assert first_last_alpn(["x", "h2"]) == "xx"
    assert first_last_alpn(["h2", "h3"]) == "h2"


def test_first_last_alpn_non_ascii_reference_vectors():
    assert first_last_alpn("\u00e9") == "99"
    assert first_last_alpn("\u00e9x") == "9x"
    assert first_last_alpn("\u00e9xy") == "9y"
    assert first_last_alpn("x\u00e9") == "x9"
    assert first_last_alpn("xy\u00e9") == "x9"
    assert first_last_alpn("x\u00e9y") == "xy"


def _spec_client_hello() -> bytes:
    # From JA4.md worked example.
    ciphers = [
        0x1301,
        0x1302,
        0x1303,
        0xC02B,
        0xC02F,
        0xC02C,
        0xC030,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ]
    sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    extensions = [
        B.ext(0x001B),
        B.sni_ext("example.com"),
        B.ext(0x0033),
        B.alpn_ext("h2"),
        B.ext(0x4469),
        B.ext(0x0017),
        B.ext(0x002D),
        B.sigalgs_ext(*sigalgs),
        B.ext(0x0005),
        B.ext(0x0023),
        B.ext(0x0012),
        B.supported_versions_ext(0x0304, 0x0303),
        B.ext(0xFF01),
        B.ext(0x000B),
        B.supported_groups_ext(0x001D, 0x0017, 0x0018),
        B.ext(0x0015),
    ]
    return B.build_client_hello(ciphers, extensions)


def test_ja4_spec_worked_example():
    raw = _spec_client_hello()
    ch = parse_client_hello(raw)
    assert len(ch.ciphers) == 15
    assert len(ch.extensions) == 16
    out = ja4_from_bytes(raw)
    assert out["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert out["ja4_r"] == (
        "t13d1516h2_"
        "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
        "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_"
        "0403,0804,0401,0503,0805,0501,0806,0601"
    )


def test_ja4_no_sigalgs_extension_hash_vector():
    # JA4.md: extension list 0005,...,ff01 (with 000d present but empty) hashes
    # to 6d807ffa2a79 with no '_' suffix.
    exts = [
        0x0005,
        0x000A,
        0x000B,
        0x000D,
        0x0012,
        0x0015,
        0x0017,
        0x001B,
        0x0023,
        0x002B,
        0x002D,
        0x0033,
        0x4469,
        0xFF01,
    ]
    extensions = []
    for e in exts:
        if e == 0x002B:
            extensions.append(B.supported_versions_ext(0x0304))
        else:
            extensions.append(B.ext(e))
    raw = B.build_client_hello([0x1301], extensions)
    out = ja4_from_bytes(raw)
    assert out["ja4_c"] == "6d807ffa2a79"


def test_ja4_empty_is_all_zero():
    raw = B.build_client_hello([], [])
    out = ja4_from_bytes(raw)
    assert out["ja4_b"] == "000000000000"
    assert out["ja4_c"] == "000000000000"


def test_ja4s_server_hello_tls13():
    raw = B.build_server_hello(
        0x1301,
        [B.ext(0x002B, b"\x03\x04"), B.ext(0x0033, b"\x00\x1d\x00\x20" + b"\x00" * 32)],
        legacy_version=0x0303,
    )
    out = ja4s_from_bytes(raw)
    assert out["ja4s_a"] == "t130200"
    assert out["ja4s"].split("_")[1] == "1301"
