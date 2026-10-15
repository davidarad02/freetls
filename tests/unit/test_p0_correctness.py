"""P0 correctness: error propagation, verify default, spec error reasons."""

from __future__ import annotations

import pytest

from freetls import (
    FingerprintSpec,
    TLSSession,
    get_default_verify,
    set_default_verify,
)
from freetls.engine import EngineSession
from freetls.errors import EngineError, FreeTLSError


def test_io_before_connect_raises():
    s = TLSSession(FingerprintSpec())
    with pytest.raises(FreeTLSError):
        s.recv(16)
    with pytest.raises(FreeTLSError):
        s.sendall(b"x")
    with pytest.raises(FreeTLSError):
        s.send(b"x")
    with pytest.raises(FreeTLSError):
        s.do_handshake()


def test_do_handshake_without_socket_raises():
    s = TLSSession(FingerprintSpec())
    with pytest.raises(FreeTLSError):
        s.do_handshake()


def test_default_verify_toggle():
    prev = get_default_verify()
    try:
        set_default_verify(False)
        assert FingerprintSpec().verify is False
        set_default_verify(True)
        assert FingerprintSpec().verify is True
        # explicit value always wins
        assert FingerprintSpec(verify=False).verify is False
    finally:
        set_default_verify(prev)


def test_invalid_spec_reason_is_surfaced():
    with pytest.raises(EngineError) as exc:
        EngineSession({"ciphers": [], "extensions": [{"type": "nope"}]})
    msg = str(exc.value).lower()
    assert "extension" in msg or "unknown" in msg
