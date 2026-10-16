"""QUIC Initial packet parsing and ClientHello extraction (RFC 9000 / RFC 9001).

A QUIC client's TLS ClientHello is carried inside CRYPTO frames of an *Initial*
packet. Unlike TLS-over-TCP there is no record layer, so the fingerprint cannot
be read straight off the wire: the Initial packet is protected with keys derived
from a version-specific fixed salt and the client's Destination Connection ID
(RFC 9001 §5.2), which a passive observer can reproduce. This module performs
that decryption and reassembles the CRYPTO stream back into the ClientHello
handshake message, which :func:`freetls.fingerprint.parse.parse_client_hello`
then parses as usual.

Only the AES primitives are borrowed from ``cryptography`` (imported lazily, as
in ``ja4x.py``); the HKDF key schedule is stdlib ``hmac``/``hashlib``. The core
package stays free of third-party runtime dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from .parse import ClientHello, parse_client_hello

QUIC_VERSION_1 = 0x00000001
QUIC_VERSION_2 = 0x6B3343CF

# RFC 9001 §5.2 (v1) and RFC 9369 §3.3.2 (v2) fixed initial salts.
_INITIAL_SALTS = {
    QUIC_VERSION_1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_VERSION_2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}

# QUIC v2 renamed the key-derivation labels (RFC 9369 §3.3).
_VERSION_LABELS = {
    QUIC_VERSION_1: (b"quic key", b"quic iv", b"quic hp"),
    QUIC_VERSION_2: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}

# Transport-parameter ID used by QUIC fingerprinters to bucket every GREASE
# value (31*N+27), matching uTLS's GREASETransportParameter.IsGREASEID.
GREASE_TRANSPORT_PARAMETER = 27


class QuicParseError(ValueError):
    pass


def is_grease_transport_parameter(param_id: int) -> bool:
    return param_id >= 27 and (param_id - 27) % 31 == 0


def read_varint(buf: bytes, off: int) -> tuple[int, int]:
    """Decode an RFC 9000 §16 variable-length integer; return (value, new_off)."""
    if off >= len(buf):
        raise QuicParseError("truncated varint")
    length = 1 << (buf[off] >> 6)
    if off + length > len(buf):
        raise QuicParseError("truncated varint")
    value = buf[off] & 0x3F
    for b in buf[off + 1 : off + length]:
        value = (value << 8) | b
    return value, off + length


def encode_varint(value: int) -> bytes:
    """Encode an RFC 9000 §16 variable-length integer (shortest form)."""
    if value < 0:
        raise QuicParseError("varint must be non-negative")
    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return struct.pack(">H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack(">I", value | 0x80000000)
    if value < 1 << 62:
        return struct.pack(">Q", value | 0xC000000000000000)
    raise QuicParseError("varint out of range")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    return _hkdf_expand(secret, info, length)


def initial_keys(version: int, dcid: bytes) -> tuple[bytes, bytes, bytes]:
    """Derive the client's Initial (key, iv, header-protection key)."""
    salt = _INITIAL_SALTS.get(version)
    if salt is None:
        raise QuicParseError(f"unsupported QUIC version 0x{version:08x}")
    key_label, iv_label, hp_label = _VERSION_LABELS[version]
    initial_secret = _hkdf_extract(salt, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    return (
        _hkdf_expand_label(client_secret, key_label, 16),
        _hkdf_expand_label(client_secret, iv_label, 12),
        _hkdf_expand_label(client_secret, hp_label, 16),
    )


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _aes_gcm_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key).decrypt(nonce, ct, aad)


@dataclass
class QuicInitial:
    version: int
    dcid: bytes
    scid: bytes
    token: bytes
    packet_number: int
    frames: bytes
    raw: bytes


def _reconstruct_pn(truncated: int, pn_len: int, largest_pn: int | None) -> int:
    if largest_pn is None:
        return truncated
    expected = largest_pn + 1
    window = 1 << (pn_len * 8)
    half = window // 2
    if expected > half and truncated <= expected - half:
        return truncated + window
    if truncated > expected + half:
        return truncated - window
    return truncated


def parse_initial(
    packet: bytes,
    *,
    largest_pn: int | None = None,
    keys: tuple[bytes, bytes, bytes] | None = None,
) -> QuicInitial:
    """Decrypt one client Initial packet and return its header plus frames.

    ``largest_pn`` is the largest packet number seen so far on the connection;
    pass it when parsing a flight in order so truncated packet numbers are
    reconstructed correctly (RFC 9001 §5.4). A client's first Initial carries
    PN 0 or 1, where the truncated value is already exact.

    ``keys`` overrides the derived (key, iv, hp). Pass it when parsing a flight:
    RFC 9001 §5.2 keys every client Initial from the *first* Initial's
    Destination Connection ID, and later client Initials carry the server's
    connection ID as their DCID — deriving per packet would use wrong keys.
    """
    if len(packet) < 7:
        raise QuicParseError("packet too short")
    first = packet[0]
    if not first & 0x80:
        raise QuicParseError("not a long-header packet")
    if first & 0x30:
        raise QuicParseError("not an Initial packet")
    version = int.from_bytes(packet[1:5], "big")

    off = 5
    dcid_len = packet[off]
    off += 1
    dcid = packet[off : off + dcid_len]
    off += dcid_len
    if off >= len(packet):
        raise QuicParseError("truncated Initial header")
    scid_len = packet[off]
    off += 1
    scid = packet[off : off + scid_len]
    off += scid_len

    token_len, off = read_varint(packet, off)
    token = packet[off : off + token_len]
    off += token_len
    length, off = read_varint(packet, off)
    pn_offset = off
    end = off + length
    if end > len(packet):
        raise QuicParseError("Initial packet length overruns capture")

    if keys is None:
        keys = initial_keys(version, dcid)
    key, iv, hp = keys
    if pn_offset + 4 + 16 > end:
        raise QuicParseError("packet too short for header-protection sample")
    sample = packet[pn_offset + 4 : pn_offset + 4 + 16]
    mask = _aes_ecb_encrypt(hp, sample)

    header = bytearray(packet[:pn_offset])
    header[0] ^= mask[0] & 0x0F
    pn_len = (header[0] & 0x03) + 1
    if pn_offset + pn_len > end:
        raise QuicParseError("truncated packet number")
    pn_bytes = bytearray(packet[pn_offset : pn_offset + pn_len])
    for i in range(pn_len):
        pn_bytes[i] ^= mask[1 + i]
    truncated = int.from_bytes(pn_bytes, "big")
    pn = _reconstruct_pn(truncated, pn_len, largest_pn)

    header += pn_bytes
    aad = bytes(header)
    ciphertext = packet[pn_offset + pn_len : end]
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    frames = _aes_gcm_open(key, nonce, aad, ciphertext)

    return QuicInitial(
        version=version,
        dcid=dcid,
        scid=scid,
        token=token,
        packet_number=pn,
        frames=frames,
        raw=packet,
    )


def iter_frames(frames: bytes) -> Iterable[tuple[int, bytes]]:
    """Walk a decrypted Initial payload, yielding (frame_type, frame_bytes)."""
    off = 0
    while off < len(frames):
        ftype = frames[off]
        if ftype == 0x00:  # PADDING
            off += 1
            continue
        if ftype == 0x01:  # PING
            off += 1
            yield ftype, b""
            continue
        if ftype in (0x02, 0x03):  # ACK / ACK+ECN
            start = off
            off += 1
            _, off = read_varint(frames, off)  # largest acknowledged
            _, off = read_varint(frames, off)  # ack delay
            ranges, off = read_varint(frames, off)
            _, off = read_varint(frames, off)  # first ack range
            for _ in range(ranges):
                _, off = read_varint(frames, off)  # gap
                _, off = read_varint(frames, off)  # ack range length
            if ftype == 0x03:
                for _ in range(3):
                    _, off = read_varint(frames, off)
            yield ftype, frames[start:off]
            continue
        if ftype == 0x06:  # CRYPTO
            start = off
            off += 1
            _, off = read_varint(frames, off)  # offset
            clen, off = read_varint(frames, off)
            off += clen
            if off > len(frames):
                raise QuicParseError("CRYPTO frame overruns payload")
            yield ftype, frames[start:off]
            continue
        raise QuicParseError(f"unsupported frame type 0x{ftype:02x} in Initial")


def _crypto_stream(packets: Iterable[bytes]) -> bytes:
    chunks: dict[int, bytes] = {}
    largest_pn: int | None = None
    keys: tuple[bytes, bytes, bytes] | None = None
    for packet in packets:
        initial = parse_initial(packet, largest_pn=largest_pn, keys=keys)
        if keys is None:
            keys = initial_keys(initial.version, initial.dcid)
        largest_pn = initial.packet_number
        for ftype, frame in iter_frames(initial.frames):
            if ftype != 0x06:
                continue
            off, p = read_varint(frame, 1)
            clen, p = read_varint(frame, p)
            chunks[off] = frame[p : p + clen]
    if not chunks:
        raise QuicParseError("no CRYPTO frames in Initial packets")
    out = bytearray()
    for offset in sorted(chunks):
        if offset != len(out):
            break
        out += chunks[offset]
    return bytes(out)


def parse_quic_client_hello(packets: Iterable[bytes]) -> ClientHello:
    """Reassemble the CRYPTO stream of Initial packets and parse the ClientHello."""
    return parse_client_hello(_crypto_stream(packets))


def parse_transport_parameters(data: bytes) -> list[tuple[int, bytes]]:
    """Decode a quic_transport_parameters (ext 57) body into (id, value) pairs."""
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(data):
        param_id, off = read_varint(data, off)
        plen, off = read_varint(data, off)
        if off + plen > len(data):
            raise QuicParseError("transport parameter overruns extension")
        out.append((param_id, data[off : off + plen]))
        off += plen
    return out
