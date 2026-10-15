"""Unit tests for JSON-defined presets and runtime profile registration."""

from __future__ import annotations

import json

import _build as B
import pytest

from freetls import FingerprintSpec, engine, profiles
from freetls.errors import SpecError
from freetls.fingerprint import ja4_from_bytes


def test_chlo_raw_builds_offline():
    raw = engine.chlo_raw(B.CHLO_JSON)
    assert raw
    out = ja4_from_bytes(raw)
    assert out["ja4"].startswith("t13d")
    assert out["ja4_a"][4:6] == "04"  # four ciphers


def test_chlo_raw_invalid_raises_not_crashes():
    with pytest.raises(SpecError):
        engine.chlo_raw('{"nonsense": true}')


def test_spec_to_engine_includes_chlo_json():
    spec = FingerprintSpec(chlo_json=B.CHLO_JSON)
    assert spec.to_engine()["chlo_json"] == B.CHLO_JSON


def test_add_profile_from_chlo_json():
    p = profiles.add_profile("unit_json", chlo_json=B.CHLO_JSON)
    assert p.ja4.startswith("t13d")
    assert profiles.get("unit_json") is p
    assert "unit_json" in profiles.names()
    assert profiles.get("unit_json").spec().chlo_json == B.CHLO_JSON
    assert profiles.catalog_info()["registered"] >= 1


def test_add_profile_from_preset():
    p = profiles.add_profile("unit_ff", preset="HelloFirefox_148", alias="unit_ff")
    assert p.ja4.startswith("t13d")
    assert p.ja3 and len(p.ja3) == 32
    assert profiles.get("unit_ff").ja4 == p.ja4


def test_add_profile_requires_one_source():
    with pytest.raises(ValueError):
        profiles.add_profile("x")
    with pytest.raises(ValueError):
        profiles.add_profile("x", preset="HelloChrome_155", chlo_json=B.CHLO_JSON)


def test_add_profile_unknown_preset_raises():
    with pytest.raises(ValueError):
        profiles.add_profile("bad", preset="HelloDoesNotExist")


def test_load_file(tmp_path):
    f = tmp_path / "extra.json"
    f.write_text(
        json.dumps(
            {
                "profiles": [
                    {"name": "file_json", "chlo_json": B.CHLO_JSON},
                    {"name": "file_chrome", "preset": "HelloChrome_155", "alias": "file_chrome"},
                ]
            }
        )
    )
    n = profiles.load_file(str(f))
    assert n == 2
    assert profiles.get("file_json") is not None
    assert profiles.get("file_chrome") is not None


def test_generated_preset_map_is_current():
    names = engine.preset_list()
    assert len(names) >= 40
    for required in (
        "HelloChrome_155",
        "HelloFirefox_148",
        "HelloSafari_26_3",
        "HelloChrome_Auto",
        "HelloFirefox_Auto",
        "HelloSafari_Auto",
    ):
        assert required in names, required
