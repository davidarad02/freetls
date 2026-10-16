"""Verify the on-the-wire QUIC Initial produces the reported JA4q.

Captures loopback UDP with a capability-bearing tcpdump, then decrypts the
Initial packets with an independent extractor (tests/pcap/_quic.py) and
recomputes JA4q from the ClientHello it recovers.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _quic  # noqa: E402

import freetls  # noqa: E402
from freetls.model import (  # noqa: E402
    TLS13,
    Extension,
    FingerprintSpec,
    QuicInitialSpec,
    TransportParameter,
)

pytestmark = pytest.mark.pcap


@pytest.fixture()
def capture_udp(tcpdump_bin, tmp_path):
    """Factory: capture_udp(port) -> path, starting/stopping tcpdump."""
    procs: list[subprocess.Popen] = []

    def _start(port: int, name: str = "quic.pcap") -> str:
        out = str(tmp_path / name)
        proc = subprocess.Popen(
            [tcpdump_bin, "-i", "lo", "-U", "-w", out, f"udp port {port}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(proc)
        time.sleep(0.6)
        return out

    yield _start
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _quic_spec(server_name: str = "localhost") -> FingerprintSpec:
    return FingerprintSpec(
        ciphers=[0x1301, 0x1302, 0x1303],
        extensions=[
            Extension.sni(server_name),
            Extension.supported_versions(TLS13),
            Extension.supported_curves(0x001D, 0x0017),
            Extension.signature_algorithms(0x0403, 0x0804),
            Extension.key_share(0x001D),
            Extension.psk_key_exchange_modes(1),
            Extension.alpn("h3"),
            Extension.quic_transport_parameters(
                TransportParameter.varint("max_idle_timeout", 30000),
                TransportParameter.varint("initial_max_data", 1048576),
                TransportParameter.grease(4),
            ),
        ],
        vers_min=TLS13,
        vers_max=TLS13,
        server_name=server_name,
        quic=QuicInitialSpec(dcid_len=8, scid_len=0),
    )


def test_wire_quic_ja4q_matches(capture_udp, h3_server):
    path = capture_udp(h3_server.port)
    with freetls.QUICSession(_quic_spec()) as session:
        session.connect("127.0.0.1", h3_server.port, server_hostname="localhost", timeout=15)
        reported_ja4q = session.ja4q
    time.sleep(0.6)

    hellos = _quic.client_hellos(path, h3_server.port)
    assert hellos, "no QUIC Initial captured on the wire"
    assert _quic.last_skipped == 0, "every client Initial should be keyable"
    assert reported_ja4q is not None
    assert freetls.ja4_from_bytes(hellos[0], transport="q")["ja4"] == reported_ja4q


def test_wire_quic_ja4q_matches_for_preset(capture_udp, h3_server):
    """A uQUIC preset's ClientHello is what reaches the wire, too."""
    path = capture_udp(h3_server.port, "quic_preset.pcap")
    spec = FingerprintSpec(quic_id="QUICFirefox_116", server_name="localhost")
    with freetls.QUICSession(spec) as session:
        session.connect("127.0.0.1", h3_server.port, server_hostname="localhost", timeout=15)
        reported_ja4q = session.ja4q
    time.sleep(0.6)

    hellos = _quic.client_hellos(path, h3_server.port)
    assert hellos, "no QUIC Initial captured on the wire"
    assert freetls.ja4_from_bytes(hellos[0], transport="q")["ja4"] == reported_ja4q


def test_wire_quic_ja4q_matches_without_sni(capture_udp, h3_server):
    """Connecting by IP sends no SNI; the reported JA4q must match the wire.

    Regression for a bug where the offline build used a fixed ServerName, so it
    always carried an SNI the wire omitted (a different JA4q flag and ext count).
    """
    path = capture_udp(h3_server.port, "quic_nosni.pcap")
    spec = FingerprintSpec(quic_id="QUICFirefox_116")  # no server_name -> no SNI
    with freetls.QUICSession(spec) as session:
        session.connect("127.0.0.1", h3_server.port, timeout=15)  # no server_hostname
        reported_ja4q = session.ja4q
    time.sleep(0.6)

    hellos = _quic.client_hellos(path, h3_server.port)
    assert hellos, "no QUIC Initial captured on the wire"
    wire = freetls.ja4_from_bytes(hellos[0], transport="q")["ja4"]
    assert wire == reported_ja4q
    assert wire[3] == "i"  # the no-SNI flag in JA4_a (q<ver><sni>...)
