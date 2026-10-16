"""Runtime engine switching: use_engine / engine_context / coexistence.

Requires both engines built (`make native native-go`); otherwise skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import freetls
from freetls import Engine

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"


@pytest.fixture(autouse=True)
def _restore_engine():
    yield
    freetls.use_engine(Engine.WIDE)


def _both_built() -> bool:
    return (NATIVE / "libfreetls.so").exists() and (NATIVE / "libfreetls_go.so").exists()


def test_use_engine_switches_supported_ciphers():
    if not _both_built():
        pytest.skip("both engines not built (run `make native native-go`)")
    assert freetls.use_engine(Engine.WIDE).kind is Engine.WIDE
    wide = len(freetls.engine.supported_ciphers())
    assert freetls.use_engine(Engine.GO).kind is Engine.GO
    go = len(freetls.engine.supported_ciphers())
    assert (wide, go) == (51, 27)
    assert freetls.use_engine(Engine.WIDE).kind is Engine.WIDE
    assert len(freetls.engine.supported_ciphers()) == wide


def test_current_engine_and_context_manager():
    if not _both_built():
        pytest.skip("both engines not built")
    freetls.use_engine(Engine.WIDE)
    with freetls.engine_context(Engine.GO):
        assert freetls.current_engine().kind is Engine.GO
        assert len(freetls.engine.supported_ciphers()) == 27
    assert freetls.current_engine().kind is Engine.WIDE
    assert len(freetls.engine.supported_ciphers()) == 51


def test_live_session_survives_switch(tls_server_13):
    if not _both_built():
        pytest.skip("both engines not built")
    spec = freetls.modes.baseline_spec(server_name="localhost", verify=False)
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"
        # Switch to the Go-only engine; the live session must keep working
        # (it is bound to the engine it was created with).
        freetls.use_engine(Engine.GO)
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        buf = b""
        for _ in range(50):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"HTTP/" in buf:
                break
        assert b"HTTP/" in buf
        assert s.state.version == "TLS1.3"


def test_two_engines_coexist_and_handshake(tls_server_13):
    if not _both_built():
        pytest.skip("both engines not built")
    spec = freetls.modes.baseline_spec(server_name="localhost", verify=False)
    for _ in range(4):
        for kind in (Engine.WIDE, Engine.GO):
            freetls.use_engine(kind)
            with freetls.TLSSession(spec) as s:
                s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
                assert s.state.version == "TLS1.3"
