"""A minimal, independent pcap -> TLS handshake extractor (no freetls imports).

Used to verify, from the actual loopback traffic, that the ClientHello the
engine put on the wire really produces the reported JA4.
"""

from __future__ import annotations

import struct


def _read_pcap(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, linktype = "<", struct.unpack("<I", data[20:24])[0]
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, linktype = ">", struct.unpack(">I", data[20:24])[0]
    else:
        raise ValueError("unsupported capture format (need classic pcap)")
    off = 24
    packets = []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        packets.append(data[off : off + incl])
        off += incl
    return linktype, packets


def _tcp_payload(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800:
            return None
        ip = frame[14:]
    elif linktype == 101:  # raw IP
        ip = frame
    else:
        return None
    if len(ip) < 20 or ip[9] != 6:  # TCP
        return None
    ihl = (ip[0] & 0x0F) * 4
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    doff = (tcp[12] >> 4) * 4
    return tcp[doff:]


def client_hellos(path: str) -> list[bytes]:
    linktype, packets = _read_pcap(path)
    out = []
    for p in packets:
        payload = _tcp_payload(p, linktype)
        if not payload:
            continue
        off = 0
        while off + 5 <= len(payload):
            rtype = payload[off]
            rlen = struct.unpack(">H", payload[off + 3 : off + 5])[0]
            rec = payload[off + 5 : off + 5 + rlen]
            if rtype == 0x16 and len(rec) >= 4 and rec[0] == 1:
                hs_len = int.from_bytes(rec[1:4], "big")
                out.append(rec[: 4 + hs_len])
            off += 5 + rlen
    return out


def server_hellos(path: str) -> list[bytes]:
    linktype, packets = _read_pcap(path)
    out = []
    for p in packets:
        payload = _tcp_payload(p, linktype)
        if not payload:
            continue
        off = 0
        while off + 5 <= len(payload):
            rtype = payload[off]
            rlen = struct.unpack(">H", payload[off + 3 : off + 5])[0]
            rec = payload[off + 5 : off + 5 + rlen]
            if rtype == 0x16 and len(rec) >= 4 and rec[0] == 2:
                hs_len = int.from_bytes(rec[1:4], "big")
                out.append(rec[: 4 + hs_len])
            off += 5 + rlen
    return out
