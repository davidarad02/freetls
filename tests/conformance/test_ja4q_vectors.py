"""JA4q / JA4Sq conformance vectors.

FoxIO publishes no QUIC-specific vectors: the JA4 specification only states that
the leading character becomes ``q`` for QUIC and the algorithm is otherwise
unchanged. The first vector below therefore pins that statement against FoxIO's
own JA4.md worked example (whose JA4 is published), and the remaining vectors
are freetls-authored regression vectors for a realistic QUIC ClientHello.
"""

from __future__ import annotations

import _build as B
import _quic_build as Q

from freetls.fingerprint import ja4_from_bytes, ja4s_from_bytes, parse_quic_client_hello, to_ja4

_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_CIPHERS = [
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


def _foxio_example() -> bytes:
    """The JA4.md worked example ClientHello (published JA4)."""
    extensions = [
        B.ext(0x001B),
        B.sni_ext("example.com"),
        B.ext(0x0033),
        B.alpn_ext("h2"),
        B.ext(0x4469),
        B.ext(0x0017),
        B.ext(0x002D),
        B.sigalgs_ext(*_SIGALGS),
        B.ext(0x0005),
        B.ext(0x0023),
        B.ext(0x0012),
        B.supported_versions_ext(0x0304, 0x0303),
        B.ext(0xFF01),
        B.ext(0x000B),
        B.supported_groups_ext(0x001D, 0x0017, 0x0018),
        B.ext(0x0015),
    ]
    return B.build_client_hello(_CIPHERS, extensions)


def _quic_example() -> bytes:
    """A realistic QUIC ClientHello: h3 ALPN and a transport-parameters extension."""
    transport_parameters = bytes.fromhex("01041d01") + bytes.fromhex("0f080001020304050607")
    extensions = [
        B.ext(0x001B),
        B.sni_ext("example.com"),
        B.ext(0x0033),
        B.alpn_ext("h3"),
        B.ext(0x4469),
        B.ext(0x0017),
        B.ext(0x002D),
        B.sigalgs_ext(*_SIGALGS),
        B.ext(0x0005),
        B.ext(0x0012),
        B.supported_versions_ext(0x0304, 0x0303),
        B.ext(0xFF01),
        B.ext(0x000B),
        B.supported_groups_ext(0x001D, 0x0017, 0x0018),
        B.ext(0x0039, transport_parameters),
        B.ext(0x0015),
    ]
    return B.build_client_hello(_CIPHERS, extensions)


def test_ja4q_is_foxio_vector_with_q_prefix():
    raw = _foxio_example()
    assert ja4_from_bytes(raw)["ja4"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert ja4_from_bytes(raw, transport="q")["ja4"] == "q13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4q_quic_client_hello_vector():
    out = ja4_from_bytes(_quic_example(), transport="q")
    assert out["ja4"] == "q13d1516h3_8daaf6152771_a19841784004"
    assert out["ja4_r"] == (
        "q13d1516h3_"
        "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_"
        "0005,000a,000b,000d,0012,0015,0017,001b,002b,002d,0033,0039,4469,ff01_"
        "0403,0804,0401,0503,0805,0501,0806,0601"
    )
    assert out["alpn"] == "h3"


def test_ja4sq_vector():
    sh = B.build_server_hello(0x1301, [B.ext(0x002B, b"\x03\x04")])
    assert ja4s_from_bytes(sh, transport="q")["ja4s"] == "q130100_1301_b9a491fefe05"


def test_quic_initial_roundtrip_matches_bare_hello():
    raw = _quic_example()
    ch = parse_quic_client_hello([Q.build_quic_initial(raw, packet_number=1)])
    assert to_ja4(ch, transport="q") == ja4_from_bytes(raw, transport="q")
