"""End-to-end tests: real handshakes reproduce catalog fingerprints."""

from __future__ import annotations

import freetls
from freetls import profiles

# Browser presets that negotiate against a TLS 1.3 server.
TLS13_ALIASES = [
    "chrome_155",
    "chrome_133",
    "firefox_148",
    "firefox_120",
    "edge_106",
    "safari_26_3",
    "safari_16_0",
    "chrome_133_h1",
    "chrome_133_nosni",
]


def _connect(spec, port, sni):
    s = freetls.TLSSession(spec)
    s.connect("127.0.0.1", port, server_hostname=sni)
    return s


def test_browser_profiles_reproduce_ja4(tls_server_13):
    for alias in TLS13_ALIASES:
        prof = profiles.get(alias)
        assert prof is not None, f"missing profile {alias}"
        with _connect(prof.spec(server_name="localhost"), tls_server_13.port, "localhost") as s:
            assert s.ja4 == prof.ja4, f"{alias}: {s.ja4} != {prof.ja4}"


def test_profile_nosni_has_no_sni(tls_server_13):
    prof = profiles.get("chrome_133_nosni")
    with _connect(prof.spec(server_name="localhost"), tls_server_13.port, "") as s:
        assert s.fingerprints["sni"] == "i"
        assert s.ja4 == prof.ja4


def test_tls12_profile_against_tls12_server(tls_server_12):
    prof = profiles.get("android_11_okhttp")
    assert prof.ja4.startswith("t12")
    with _connect(prof.spec(server_name="localhost"), tls_server_12.port, "localhost") as s:
        assert s.ja4 == prof.ja4
