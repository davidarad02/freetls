"""End-to-end tests for the three freetls modes."""
from __future__ import annotations

import freetls
from freetls import modes


def _connect(spec, port):
    s = freetls.TLSSession(spec)
    s.connect("127.0.0.1", port, server_hostname="localhost")
    return s


def test_specific_mode_exact_ciphers(tls_server_13):
    ciphers = [0x1301, 0x1302, 0x1303]
    spec = modes.specific(ciphers=ciphers, server_name="localhost")
    with _connect(spec, tls_server_13.port) as s:
        assert s.fingerprints["ciphers"] == ciphers
        assert s.ja4.split("_")[0][4:6] == "03"


def test_partial_random_mode(tls_server_13):
    spec = modes.partial_random(server_name="localhost", seed=11)
    with _connect(spec, tls_server_13.port) as s:
        assert s.ja4.startswith("t13")
        # baseline + 10 padding ciphers
        assert len(s.fingerprints["ciphers"]) == len(modes.DEFAULT_CIPHERS) + 10


def test_true_random_mode(tls_server_13):
    spec = modes.true_random(server_name="localhost", seed=3, n_ciphers=90, n_extensions=40)
    with _connect(spec, tls_server_13.port) as s:
        assert s.ja4.startswith("t13")
        assert len(s.fingerprints["ciphers"]) >= 90


def test_modes_produce_distinct_fingerprints(tls_server_13):
    specs = [
        modes.baseline_spec(server_name="localhost"),
        modes.partial_random(server_name="localhost", seed=1),
        modes.true_random(server_name="localhost", seed=2, n_ciphers=80, n_extensions=40),
    ]
    ja4s = []
    for spec in specs:
        with _connect(spec, tls_server_13.port) as s:
            ja4s.append(s.ja4)
    assert len(set(ja4s)) == 3
