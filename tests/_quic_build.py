"""Build synthetic QUIC Initial packets for tests (RFC 9000 / RFC 9001).

The inverse of ``freetls.fingerprint.quic``: it frames a ClientHello in a CRYPTO
frame, protects it with the version's Initial keys, and applies header
protection, so tests can round-trip a packet through the parser.
"""

from __future__ import annotations

from freetls.fingerprint.quic import encode_varint, initial_keys

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

# RFC 9001 Appendix A.1's Destination Connection ID.
RFC9001_DCID = bytes.fromhex("8394c8f03e515708")


def crypto_frame(data: bytes, offset: int = 0) -> bytes:
    return b"\x06" + encode_varint(offset) + encode_varint(len(data)) + data


def build_quic_initial(
    crypto_payload: bytes,
    *,
    crypto_offset: int = 0,
    dcid: bytes = RFC9001_DCID,
    scid: bytes = b"",
    version: int = QUIC_V1,
    packet_number: int = 0,
    pn_len: int = 1,
    token: bytes = b"",
    pad_to: int = 1200,
    keys: tuple[bytes, bytes, bytes] | None = None,
) -> bytes:
    """Return a client Initial packet carrying ``crypto_payload`` in a CRYPTO frame.

    ``keys`` overrides the (key, iv, hp) derived from ``dcid`` — pass it to build
    a later Initial of a flight, whose DCID is the server's connection ID while
    its keys still come from the first Initial (RFC 9001 §5.2).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if keys is None:
        keys = initial_keys(version, dcid)
    key, iv, hp = keys
    frame = crypto_frame(crypto_payload, crypto_offset)
    prefix = (
        bytes([0xC0 | (pn_len - 1)])
        + version.to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + encode_varint(len(token))
        + token
    )

    # Padding goes inside the protected payload, so the packet length and the
    # length field's varint size depend on each other; settle them by iteration.
    pad = 0
    for _ in range(4):
        length = pn_len + len(frame) + pad + 16
        total = len(prefix) + len(encode_varint(length)) + length
        settled = max(0, pad + (pad_to - total))
        if settled == pad:
            break
        pad = settled

    payload = frame + b"\x00" * pad
    length_b = encode_varint(pn_len + len(payload) + 16)
    pn_offset = len(prefix) + len(length_b)
    pn_b = packet_number.to_bytes(pn_len, "big")
    aad = prefix + length_b + pn_b
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, "big")))
    packet = bytearray(aad + AESGCM(key).encrypt(nonce, payload, aad))

    sample = bytes(packet[pn_offset + 4 : pn_offset + 20])
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)
