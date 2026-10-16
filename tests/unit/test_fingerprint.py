"""Unit tests for the fingerprint core (parser, JA4, JA3, JA4S)."""

from __future__ import annotations

import _build as B
import pytest

from freetls.fingerprint import (
    ja3_from_bytes,
    ja4_from_bytes,
    ja4s_from_bytes,
    parse_client_hello,
    parse_server_hello,
)
from freetls.fingerprint.parse import ParseError, is_grease


def test_grease_detection():
    for v in (0x0A0A, 0x1A1A, 0xFAFA):
        assert is_grease(v)
    assert not is_grease(0x1301)
    assert not is_grease(0x0B0B)


def test_parse_client_hello_fields():
    raw = B.build_client_hello(
        [0x1301, 0x1302],
        [
            B.sni_ext("example.com"),
            B.alpn_ext("h2", "http/1.1"),
            B.supported_versions_ext(0x0304, 0x0303),
            B.supported_groups_ext(0x001D, 0x0017),
            B.ec_point_formats_ext(0),
            B.sigalgs_ext(0x0403, 0x0804),
        ],
    )
    ch = parse_client_hello(raw)
    assert ch.ciphers == [0x1301, 0x1302]
    assert ch.has_sni
    assert ch.server_names == ["example.com"]
    assert ch.alpn_list == ["h2", "http/1.1"]
    assert sorted(ch.supported_versions) == [0x0303, 0x0304]
    assert ch.supported_groups == [0x001D, 0x0017]
    assert ch.ec_point_formats == [0]
    assert ch.sig_algs == [0x0403, 0x0804]


def test_grease_is_excluded_from_ja4():
    raw = B.build_client_hello(
        [0x1301, 0x0A0A],
        [B.supported_versions_ext(0x0304), B.alpn_ext("h2")],
    )
    out = ja4_from_bytes(raw)
    assert out["ciphers"] == [0x1301]  # GREASE not counted
    assert out["ja4_a"][4:6] == "01"


def test_ja4_a_version_and_counts():
    raw = B.build_client_hello(
        [0x1301] * 3,
        [B.sni_ext("a.com"), B.alpn_ext("http/1.1"), B.supported_versions_ext(0x0304)],
    )
    out = ja4_from_bytes(raw)
    a = out["ja4_a"]
    assert a[:3] == "t13"
    assert a[3] == "d"
    assert a[4:6] == "03"
    assert a[6:8] == "03"
    assert a[8:10] == "h1"


def test_sni_absent_is_i():
    raw = B.build_client_hello([0x1301], [B.supported_versions_ext(0x0304)])
    out = ja4_from_bytes(raw)
    assert out["sni"] == "i"
    assert out["ja4_a"][3] == "i"


def test_counts_capped_at_99():
    ciphers = list(range(0x0001, 0x0080))  # 127 real ciphers
    raw = B.build_client_hello(ciphers, [B.supported_versions_ext(0x0304)])
    out = ja4_from_bytes(raw)
    assert out["ja4_a"][4:6] == "99"


def test_ja3_reference_form():
    raw = B.build_client_hello(
        [0x1301, 0xC02B],
        [B.supported_groups_ext(0x001D, 0x0017), B.ec_point_formats_ext(0)],
    )
    out = ja3_from_bytes(raw)
    # 771,4865-49195,10-11,29-23,0
    assert out["ja3_string"] == "771,4865-49195,10-11,29-23,0"
    assert len(out["ja3"]) == 32


def test_ja4s_version_and_cipher():
    raw = B.build_server_hello(
        0xC02F,
        [B.ext(0x002B, b"\x03\x04")],
        legacy_version=0x0303,
    )
    out = ja4s_from_bytes(raw)
    assert out["ja4s_a"] == "t130100"
    assert out["ja4s"].split("_")[1] == "c02f"


def test_parse_errors():
    with pytest.raises(ParseError):
        parse_client_hello(b"")
    with pytest.raises(ParseError):
        parse_server_hello(b"\x01\x00\x00\x00")  # client hello, not server


def test_parse_client_hello_truncated_raises_parse_error():
    """A truncated ClientHello raises ParseError, not IndexError."""
    from freetls.fingerprint.parse import ParseError

    raw = bytes([0x01, 0x00, 0x00, 0x22]) + bytes(0x22)  # 34-byte body, no room for fields
    with pytest.raises(ParseError):
        parse_client_hello(raw)
