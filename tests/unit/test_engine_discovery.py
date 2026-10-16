"""Unit tests for engine discovery/loading and the engine-switch API."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from freetls import engine
from freetls.engine import _cffi


def test_candidate_paths_includes_env(monkeypatch, tmp_path):
    fake = str(tmp_path / "libfreetls.so")
    monkeypatch.setenv("FREETLS_LIB", fake)
    cands = _cffi._candidate_paths()
    assert cands[0] == fake
    assert any("_lib" in p for p in cands)


def test_lib_filename_is_platform_specific():
    name = _cffi._lib_filename()
    assert name in ("libfreetls.so", "libfreetls.dylib", "freetls.dll")


def test_go_lib_filename_derives_from_default():
    name = _cffi._go_lib_filename()
    assert name in ("libfreetls_go.so", "libfreetls_go.dylib", "freetls_go.dll")


def test_engine_enum_members():
    assert engine.Engine.WIDE.value == "wide"
    assert engine.Engine.GO.value == "go"


def test_load_raises_when_no_engine(monkeypatch):
    monkeypatch.setattr(_cffi, "_current", None)
    monkeypatch.setattr(_cffi, "_engines", {})
    monkeypatch.setattr(_cffi, "_candidate_paths", lambda name=None: ["/nonexistent/lib.so"])
    with pytest.raises(_cffi.EngineError):
        _cffi._load()


def test_use_engine_rejects_strings():
    with pytest.raises(TypeError):
        _cffi.use_engine("wide")  # type: ignore[arg-type]


def test_current_engine_reports_kind_and_path():
    info = _cffi.current_engine()
    assert info.kind in (engine.Engine.WIDE, engine.Engine.GO, None)
    assert info.path


def test_use_engine_file_missing_path_raises():
    with pytest.raises(_cffi.EngineError):
        _cffi.use_engine_file("/nonexistent/libfreetls.so")


def test_engine_state_peer_cert_decoding():
    st = _cffi.EngineState.from_json('{"peer_cert_b64": "AAEC"}')
    assert st.peer_cert_der == b"\x00\x01\x02"
    assert _cffi.EngineState().peer_cert_der == b""


def test_engine_state_from_bad_json():
    st = _cffi.EngineState.from_json("not json")
    assert st.version == "" and st.cipher_suite == 0


def test_update_openssl_script_requires_tag():
    script = Path(__file__).resolve().parents[2] / "tools" / "update_openssl.sh"
    proc = subprocess.run(["sh", str(script)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "usage" in (proc.stdout + proc.stderr).lower()
