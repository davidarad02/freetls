"""QUIC Initial parsing, RFC 9001 key derivation and JA4q/JA4Sq."""

from __future__ import annotations

import _build as B
import _quic_build as Q
import pytest

from freetls.errors import SpecError
from freetls.fingerprint import (
    ja4_from_bytes,
    ja4s_from_bytes,
    parse_quic_client_hello,
    parse_transport_parameters,
    read_varint,
    to_ja4,
)
from freetls.fingerprint.chlo import chlo_json_from_raw
from freetls.fingerprint.quic import (
    QUIC_VERSION_1,
    QuicParseError,
    encode_varint,
    initial_keys,
    is_grease_transport_parameter,
    parse_initial,
)

CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]


def _quic_client_hello() -> bytes:
    return B.build_client_hello(
        CIPHERS,
        [
            B.sni_ext("example.com"),
            B.supported_versions_ext(0x0304),
            B.supported_groups_ext(0x001D, 0x0017),
            B.sigalgs_ext(0x0403, 0x0804),
            B.alpn_ext("h3"),
        ],
    )


# --- RFC 9001 Appendix A.1 known-answer vectors ---------------------------


def test_initial_key_schedule_rfc9001_a1():
    key, iv, hp = initial_keys(QUIC_VERSION_1, bytes.fromhex("8394c8f03e515708"))
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_unsupported_version_rejected():
    with pytest.raises(QuicParseError, match="unsupported QUIC version"):
        initial_keys(0xDEADBEEF, b"\x00" * 8)


# --- varint ---------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1],
)
def test_varint_roundtrip(value):
    encoded = encode_varint(value)
    assert read_varint(encoded, 0) == (value, len(encoded))


def test_varint_rejects_negative_and_oversized():
    with pytest.raises(QuicParseError):
        encode_varint(-1)
    with pytest.raises(QuicParseError):
        encode_varint(1 << 62)
    with pytest.raises(QuicParseError, match="truncated"):
        read_varint(b"\x40", 0)


# --- Initial packet parsing ----------------------------------------------


def test_parse_initial_roundtrip():
    hello = _quic_client_hello()
    packet = Q.build_quic_initial(hello, scid=b"\x01\x02\x03\x04", packet_number=1)
    initial = parse_initial(packet)
    assert initial.version == QUIC_VERSION_1
    assert initial.dcid == Q.RFC9001_DCID
    assert initial.scid == b"\x01\x02\x03\x04"
    assert initial.packet_number == 1
    assert initial.token == b""
    assert hello in initial.frames


def test_parse_quic_client_hello_fields():
    hello = _quic_client_hello()
    ch = parse_quic_client_hello([Q.build_quic_initial(hello)])
    assert ch.server_names == ["example.com"]
    assert ch.alpn_list == ["h3"]
    assert ch.supported_versions == [0x0304]
    assert ch.ciphers == CIPHERS
    assert ch.has_sni


def test_crypto_reassembled_across_packets():
    hello = _quic_client_hello()
    half = len(hello) // 2
    packets = [
        Q.build_quic_initial(hello[:half], crypto_offset=0, packet_number=0),
        Q.build_quic_initial(hello[half:], crypto_offset=half, packet_number=1),
    ]
    ch = parse_quic_client_hello(packets)
    assert ch.server_names == ["example.com"]


def test_later_initial_with_server_dcid_still_decrypts():
    """RFC 9001 5.2: the whole client flight is keyed from the first DCID.

    After the server's first packet the client addresses the server's connection
    ID, so a later Initial carries a different DCID — but its keys are still the
    ones derived from the *first* Initial's DCID.
    """
    hello = _quic_client_hello()
    half = len(hello) // 2
    keys = initial_keys(QUIC_VERSION_1, Q.RFC9001_DCID)
    packets = [
        Q.build_quic_initial(hello[:half], crypto_offset=0, packet_number=0),
        Q.build_quic_initial(
            hello[half:],
            crypto_offset=half,
            packet_number=1,
            dcid=b"\x01\x02\x03\x04",
            keys=keys,
        ),
    ]
    ch = parse_quic_client_hello(packets)
    assert ch.server_names == ["example.com"]


def test_initial_carries_token():
    packet = Q.build_quic_initial(_quic_client_hello(), token=b"\xaa" * 8)
    assert parse_initial(packet).token == b"\xaa" * 8


def test_rejects_non_initial_and_short_packets():
    packet = bytearray(Q.build_quic_initial(_quic_client_hello()))
    packet[0] &= ~0x80
    with pytest.raises(QuicParseError, match="long-header"):
        parse_initial(bytes(packet))
    with pytest.raises(QuicParseError, match="too short"):
        parse_initial(b"\x00\x01")


def test_short_packet_rejected_as_handshake():
    packet = bytearray(Q.build_quic_initial(_quic_client_hello()))
    packet[0] = (packet[0] & 0xC0) | 0x30  # long header, type 3 (not Initial)
    with pytest.raises(QuicParseError, match="not an Initial"):
        parse_initial(bytes(packet))


# --- JA4q / JA4Sq ---------------------------------------------------------


def test_ja4q_differs_from_ja4_only_in_prefix():
    ch = parse_quic_client_hello([Q.build_quic_initial(_quic_client_hello())])
    over_tcp = to_ja4(ch, transport="t")
    over_quic = to_ja4(ch, transport="q")
    assert over_quic["ja4"][0] == "q"
    assert over_tcp["ja4"][0] == "t"
    assert over_quic["ja4"][1:] == over_tcp["ja4"][1:]
    assert over_quic["ja4_a"].startswith("q13")


def test_ja4_from_bytes_accepts_transport():
    hello = _quic_client_hello()
    assert ja4_from_bytes(hello, transport="q")["ja4"][0] == "q"
    assert ja4_from_bytes(hello)["ja4"][0] == "t"


def test_ja4s_transport_prefix():
    sh = B.build_server_hello(0x1301, [B.ext(0x002B, b"\x03\x04")])
    assert ja4s_from_bytes(sh, transport="q")["ja4s"][0] == "q"
    assert ja4s_from_bytes(sh)["ja4s"][0] == "t"


def test_invalid_transport_rejected():
    ch = parse_quic_client_hello([Q.build_quic_initial(_quic_client_hello())])
    with pytest.raises(ValueError, match="transport must be"):
        to_ja4(ch, transport="d")


# --- transport parameters -------------------------------------------------


def test_parse_transport_parameters_roundtrip():
    body = (
        encode_varint(0x01)
        + encode_varint(4)
        + encode_varint(30000)
        + encode_varint(0x0F)
        + encode_varint(8)
        + b"\x01" * 8
    )
    params = parse_transport_parameters(body)
    assert params[0] == (0x01, encode_varint(30000))
    assert params[1] == (0x0F, b"\x01" * 8)


def test_parse_transport_parameters_truncated():
    with pytest.raises(QuicParseError, match="overruns"):
        parse_transport_parameters(encode_varint(0x01) + encode_varint(9) + b"\x00")


def test_grease_transport_parameter_detection():
    assert is_grease_transport_parameter(27)
    assert is_grease_transport_parameter(58)
    assert is_grease_transport_parameter(89)
    assert not is_grease_transport_parameter(57)
    assert not is_grease_transport_parameter(0x01)


# --- chlo_json limitation -------------------------------------------------


def test_chlo_json_rejects_quic_transport_parameters():
    hello = B.build_client_hello(
        CIPHERS,
        [B.sni_ext("example.com"), B.ext(0x0039, b"\x01\x02")],
    )
    with pytest.raises(SpecError, match="quic_transport_parameters"):
        chlo_json_from_raw(hello)
