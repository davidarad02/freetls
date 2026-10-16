"""An independent QUIC Initial extractor for pcap files (no freetls imports).

Used to verify, from the actual loopback traffic, that the ClientHello the engine
put into a QUIC Initial really produces the reported JA4q. It deliberately shares
no code with ``freetls.fingerprint.quic``: this is the second implementation, so
a bug in one does not hide a bug in the other.
"""

from __future__ import annotations

import hmac
import struct
from hashlib import sha256

# RFC 9001 §5.2 (v1) and RFC 9369 §3.3.2 (v2).
QUIC_V2 = 0x6B3343CF
SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
LABELS = {
    0x00000001: (b"quic key", b"quic iv", b"quic hp"),
    0x6B3343CF: (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
}

_LINKTYPE_ETHERNET = 1
_LINKTYPE_LINUX_SLL = 113

# Diagnostics: Initial packets the most recent client_hellos() call could not
# key. A non-zero value is not itself a failure (a capture may hold later
# flights), but it is worth asserting on when a test expects exactly one flight.
last_skipped = 0


def _read_pcap(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("unsupported capture format (need classic pcap)")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    packets = []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        packets.append(data[off : off + incl])
        off += incl
    return linktype, packets


def _udp_payloads(path: str):
    """Yield (src_port, dst_port, payload) for every UDP datagram in the capture."""
    linktype, packets = _read_pcap(path)
    for pkt in packets:
        if linktype == _LINKTYPE_ETHERNET:
            if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
                continue
            ip = pkt[14:]
        elif linktype == _LINKTYPE_LINUX_SLL:
            if len(pkt) < 16 or pkt[14:16] != b"\x08\x00":
                continue
            ip = pkt[16:]
        else:
            continue
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        sport, dport, ulen = struct.unpack(">HHH", udp[:6])
        yield sport, dport, udp[8 : 8 + max(0, ulen - 8)]


def _varint(buf: bytes, off: int) -> tuple[int, int]:
    length = 1 << (buf[off] >> 6)
    value = buf[off] & 0x3F
    for b in buf[off + 1 : off + length]:
        value = (value << 8) | b
    return value, off + length


def _expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _initial_keys(version: int, dcid: bytes) -> tuple[bytes, bytes, bytes]:
    initial = hmac.new(SALTS[version], dcid, sha256).digest()
    secret = _expand_label(initial, b"client in", 32)
    key_label, iv_label, hp_label = LABELS[version]
    return (
        _expand_label(secret, key_label, 16),
        _expand_label(secret, iv_label, 12),
        _expand_label(secret, hp_label, 16),
    )


def client_hellos(path: str, port: int) -> list[bytes]:
    """Decrypt client Initial packets sent to ``port`` and return the ClientHello(s)."""
    global last_skipped
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    chunks: dict[int, bytes] = {}
    last_skipped = 0
    keys: tuple[bytes, bytes, bytes] | None = None
    for _src, dst, packet in _udp_payloads(path):
        if dst != port or len(packet) < 7:
            continue
        if not packet[0] & 0x80:
            continue
        version = int.from_bytes(packet[1:5], "big")
        if version not in SALTS:
            continue
        # v1 Initial type bits are 0b00; v2's are 0b01 (RFC 9369 §3.2).
        if ((packet[0] >> 4) & 0x03) != (0b01 if version == QUIC_V2 else 0b00):
            continue  # not a long-header Initial

        off = 5
        dcid_len = packet[off]
        off += 1
        dcid = packet[off : off + dcid_len]
        off += dcid_len
        scid_len = packet[off]
        off += 1 + scid_len
        token_len, off = _varint(packet, off)
        off += token_len
        length, off = _varint(packet, off)
        pn_offset = off
        end = off + length
        if end > len(packet) or pn_offset + 20 > end:
            continue

        # RFC 9001 §5.2: the whole client flight is keyed from the *first*
        # client Initial's Destination Connection ID. Later client Initials
        # carry the server's connection ID as their DCID, so deriving per packet
        # would use the wrong keys.
        if keys is None:
            keys = _initial_keys(version, dcid)
        key, iv, hp = keys
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(packet[pn_offset + 4 : pn_offset + 20]) + enc.finalize()
        first = packet[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytearray(packet[pn_offset : pn_offset + pn_len])
        for i in range(pn_len):
            pn_bytes[i] ^= mask[1 + i]
        pn = int.from_bytes(pn_bytes, "big")

        header = bytearray(packet[:pn_offset])
        header[0] = first
        header += pn_bytes
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        try:
            frames = AESGCM(key).decrypt(nonce, packet[pn_offset + pn_len : end], bytes(header))
        except Exception:
            # Not a client Initial we can key (e.g. a post-Retry flight, keyed
            # from a connection ID this capture does not establish). Skipping is
            # correct for a capture parser; the assertions live in the test.
            last_skipped += 1
            continue

        i = 0
        while i < len(frames):
            ftype = frames[i]
            if ftype == 0x00:  # PADDING
                i += 1
                continue
            if ftype != 0x06:  # CRYPTO
                break
            i += 1
            coff, i = _varint(frames, i)
            clen, i = _varint(frames, i)
            chunks[coff] = frames[i : i + clen]
            i += clen

    out = bytearray()
    for offset in sorted(chunks):
        if offset != len(out):
            break
        out += chunks[offset]
    return [bytes(out)] if out else []
