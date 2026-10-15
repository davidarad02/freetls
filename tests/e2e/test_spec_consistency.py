"""The offline spec-derived JA4 must equal the JA4 the engine actually emits."""
from __future__ import annotations

import freetls
from freetls import modes
from freetls.fingerprint import ja4_from_spec


def _check(spec, port):
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", port, server_hostname="localhost")
        actual = s.ja4
        from_bytes = freetls.ja4_from_bytes(s.client_hello)["ja4"]
    return actual, from_bytes, ja4_from_spec(spec)["ja4"]


def test_baseline_spec_matches_engine(tls_server_13):
    a, b, c = _check(modes.baseline_spec(server_name="localhost"), tls_server_13.port)
    assert a == b == c


def test_true_random_spec_matches_engine(tls_server_13):
    spec = modes.true_random(server_name="localhost", seed=7, n_ciphers=60, n_extensions=20)
    a, b, c = _check(spec, tls_server_13.port)
    assert a == b == c


def test_partial_random_spec_matches_engine(tls_server_13):
    spec = modes.partial_random(server_name="localhost", seed=3, n_random_ciphers=8, n_random_extensions=6)
    a, b, c = _check(spec, tls_server_13.port)
    assert a == b == c
