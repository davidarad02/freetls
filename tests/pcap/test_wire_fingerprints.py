"""Verify the on-the-wire ClientHello/ServerHello produce the reported JA4/JA3/JA4S.

Captures loopback with a capability-bearing tcpdump, then parses the pcap with an
independent extractor (tests/pcap/_pcap.py) and recomputes the fingerprints.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _pcap  # noqa: E402

import freetls  # noqa: E402

pytestmark = pytest.mark.pcap


@pytest.fixture()
def capture(tcpdump_bin, tmp_path):
    """Factory: capture(port) -> path, starting/stopping tcpdump."""

    procs: list[subprocess.Popen] = []

    def _start(port: int, name: str = "cap.pcap") -> str:
        out = str(tmp_path / name)
        proc = subprocess.Popen(
            [tcpdump_bin, "-i", "lo", "-U", "-w", out, f"tcp port {port}"],
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


def test_wire_baseline_ja4_matches(capture, tls_server_13):
    path = capture(tls_server_13.port)
    spec = freetls.modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        s.recv(64)
        reported_ja4, reported_ja3, reported_ja4s = s.ja4, s.ja3, s.ja4s
    time.sleep(0.6)

    chs = _pcap.client_hellos(path)
    shs = _pcap.server_hellos(path)
    assert chs, "no ClientHello captured on the wire"
    wire_ja4 = freetls.ja4_from_bytes(chs[0])
    wire_ja3 = freetls.ja3_from_bytes(chs[0])
    assert wire_ja4["ja4"] == reported_ja4
    assert wire_ja3["ja3"] == reported_ja3
    if shs:
        assert freetls.ja4s_from_bytes(shs[0])["ja4s"] == reported_ja4s


def test_wire_random_mode_ja4_matches(capture, tls_server_13):
    path = capture(tls_server_13.port, "cap_rand.pcap")
    spec = freetls.modes.true_random(
        server_name="localhost", seed=None, n_ciphers=70, n_extensions=30
    )
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        reported = s.ja4
    time.sleep(0.6)
    chs = _pcap.client_hellos(path)
    assert chs
    assert freetls.ja4_from_bytes(chs[0])["ja4"] == reported
