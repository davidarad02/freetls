"""Unit tests for the P5 fingerprint surface (model + modes)."""

from __future__ import annotations

import json

import pytest

from freetls import modes
from freetls.engine._cffi import EngineState
from freetls.model import Extension, FingerprintSpec


def test_padding_extension_fixed_and_boring():
    fixed = Extension.padding(300)
    assert fixed.to_engine() == {"type": "padding", "padding_len": 300}
    assert Extension.padding().to_engine() == {"type": "padding"}


def test_record_size_limit_extension():
    assert Extension.record_size_limit(16385).to_engine() == {
        "type": "record_size_limit",
        "values": [16385],
    }
    assert Extension.record_size_limit().to_engine() == {
        "type": "record_size_limit",
        "values": [0],
    }


def test_pre_shared_key_and_application_settings():
    assert Extension.pre_shared_key().to_engine() == {"type": "pre_shared_key"}
    assert Extension.application_settings("h2").to_engine() == {
        "type": "application_settings",
        "strings": ["h2"],
    }


def test_grease_extension_random_and_fixed():
    assert Extension.grease().to_engine() == {"type": "grease"}
    assert Extension.grease(0x0A0A).to_engine() == {
        "type": "generic",
        "id": 0x0A0A,
        "data": "",
    }


def test_grease_values_are_the_sixteen_reserved():
    assert modes.GREASE_VALUES == [v * 0x101 for v in range(0x0A, 0x100, 0x10)]
    assert len(modes.GREASE_VALUES) == 16
    assert all((v >> 8) == (v & 0xFF) for v in modes.GREASE_VALUES)


def test_spec_compression_and_session_cache_roundtrip():
    spec = FingerprintSpec(compression=[0], session_cache=32)
    eng = spec.to_engine()
    assert eng["compression"] == [0]
    assert eng["session_cache"] == 32
    clone = spec.copy()
    clone.compression.append(1)
    clone.session_cache = 8
    assert spec.compression == [0]
    assert spec.session_cache == 32


def test_add_grease_fixed_inserts_slots():
    spec = modes.baseline_spec(server_name="example.com")
    modes.add_grease(spec, strategy="fixed")
    assert spec.ciphers[0] == 0x0A0A
    assert spec.ciphers[1] != 0x0A0A
    assert spec.find("supported_curves").values[0] == 0x0A0A
    assert spec.find("supported_versions").values[0] == 0x0A0A
    assert spec.extensions[0].kind == "generic"
    assert spec.extensions[0].id == 0x0A0A


def test_add_grease_random_is_seeded_and_uses_grease_values():
    spec = modes.baseline_spec(server_name="example.com")
    modes.add_grease(spec, strategy="random", seed=7)
    assert spec.ciphers[0] in modes.GREASE_VALUES
    assert spec.find("supported_curves").values[0] in modes.GREASE_VALUES


def test_add_grease_rejects_unknown_strategy():
    spec = modes.baseline_spec()
    with pytest.raises(ValueError):
        modes.add_grease(spec, strategy="nope")


def test_baseline_grease_flag():
    plain = modes.baseline_spec(server_name="example.com")
    greased = modes.baseline_spec(server_name="example.com", grease=True, seed=1)
    assert plain.ciphers[0] not in modes.GREASE_VALUES
    assert greased.ciphers[0] in modes.GREASE_VALUES


def test_engine_state_exposes_response_extras():
    state = EngineState.from_json(
        json.dumps(
            {
                "did_resume": True,
                "ocsp_response_b64": "AAEC",
                "sct_b64": ["AwQF", "BgcI"],
                "peer_alps_b64": "CQoL",
            }
        )
    )
    assert state.did_resume is True
    assert state.ocsp_response == b"\x00\x01\x02"
    assert state.signed_certificate_timestamps == [b"\x03\x04\x05", b"\x06\x07\x08"]
    assert state.peer_application_settings == b"\x09\x0a\x0b"
