"""Unit tests for engine discovery/loading helpers (portability paths)."""

from __future__ import annotations

import os

import pytest

from freetls.engine import _cffi


def test_native_source_dir_points_at_go_module():
    d = _cffi._native_source_dir()
    assert d is None or os.path.exists(os.path.join(d, "go.mod"))


def test_find_go_returns_path_or_none():
    go = _cffi._find_go()
    assert go is None or os.path.isabs(go) or os.path.exists(go)


def test_find_go_honours_env(monkeypatch):
    monkeypatch.setenv("FREETLS_GO", "/nonexistent/go-binary")
    # An explicit but missing path falls through to PATH/common lookup.
    assert _cffi._find_go() is None or os.path.exists(_cffi._find_go())


def test_candidate_paths_includes_env(monkeypatch, tmp_path):
    fake = str(tmp_path / "libfreetls.so")
    monkeypatch.setenv("FREETLS_LIB", fake)
    cands = _cffi._candidate_paths()
    assert cands[0] == fake
    assert any(p.endswith("_lib") or "_lib" in p for p in cands)


def test_lib_filename_is_platform_specific():
    name = _cffi._lib_filename()
    assert name in ("libfreetls.so", "libfreetls.dylib", "freetls.dll")


def test_load_raises_when_no_engine(monkeypatch):
    monkeypatch.setattr(_cffi, "_lib", None)
    monkeypatch.setattr(_cffi, "_ffi", None)
    monkeypatch.setattr(_cffi, "_candidate_paths", lambda: ["/nonexistent/lib.so"])
    monkeypatch.setattr(_cffi, "_autobuild", lambda: None)
    with pytest.raises(_cffi.EngineError):
        _cffi._load()


def test_engine_state_peer_cert_decoding():
    st = _cffi.EngineState.from_json('{"peer_cert_b64": "AAEC"}')
    assert st.peer_cert_der == b"\x00\x01\x02"
    assert _cffi.EngineState().peer_cert_der == b""


def test_engine_state_from_bad_json():
    st = _cffi.EngineState.from_json("not json")
    assert st.version == "" and st.cipher_suite == 0
