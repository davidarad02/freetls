"""Unit tests for self-verification helpers."""
from __future__ import annotations

from types import SimpleNamespace

import _build as B
import pytest
from freetls import verify
from freetls.errors import FingerprintError
from freetls.fingerprint import ja3_from_bytes, ja4_from_bytes, ja4s_from_bytes


def _session():
    ch = B.build_client_hello(
        [0x1301],
        [B.sni_ext("a.com"), B.alpn_ext("http/1.1"), B.supported_versions_ext(0x0304)],
    )
    sh = B.build_server_hello(0x1301, [B.ext(0x002B, b"\x03\x04")])
    j4 = ja4_from_bytes(ch)
    return SimpleNamespace(
        client_hello=ch,
        server_hello=sh,
        ja4=j4["ja4"],
        ja3=ja3_from_bytes(ch)["ja3"],
        ja4s=ja4s_from_bytes(sh)["ja4s"],
    )


def test_fingerprints_recomputed():
    s = _session()
    fp = verify.fingerprints(s)
    assert fp["ja4"] == s.ja4
    assert fp["ja3"] == s.ja3
    assert fp["ja4s"] == s.ja4s


def test_assert_consistent_passes():
    verify.assert_consistent(_session())


def test_assert_consistent_detects_mismatch():
    s = _session()
    s.ja4 = "t13d0000h2_deadbeef0000_cafebabe0000"
    with pytest.raises(FingerprintError):
        verify.assert_consistent(s)
