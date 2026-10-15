"""Unit tests for the common-JA4 profile catalog."""
from __future__ import annotations

import freetls
from freetls import engine, profiles
from freetls.fingerprint import ja4_from_bytes


def test_catalog_size():
    info = profiles.catalog_info()
    assert info["count"] >= 100
    assert info["distinct_ja4"] >= 50


def test_known_aliases_exist():
    for alias in ("chrome_133", "chrome_155", "firefox_120", "firefox_148",
                  "safari_16_0", "safari_26_3", "edge_106", "ios_14",
                  "android_11_okhttp", "golang"):
        assert profiles.get(alias) is not None, alias


def test_profile_spec_shape():
    spec = profiles.get("chrome_133").spec(server_name="example.com")
    d = spec.to_engine()
    assert d["preset"] == "HelloChrome_133"
    assert d["server_name"] == "example.com"


def test_variant_specs():
    h1 = profiles.get("chrome_133_h1").spec()
    assert h1.to_engine()["preset_alpn"] == ["http/1.1"]
    noalpn = profiles.get("chrome_133_noalpn").spec()
    assert noalpn.to_engine().get("preset_alpn_remove") is True
    nosni = profiles.get("chrome_133_nosni").spec()
    assert nosni.to_engine()["preset_no_sni"] is True


def test_every_profile_reproduces_its_ja4():
    """Offline determinism: each catalog entry's spec yields its stored JA4."""
    engine_lib = engine  # ensure loaded
    checked = 0
    for prof in profiles.list_profiles():
        raw = engine.preset_raw_opts(
            prof.preset, no_sni=prof.no_sni, alpn=prof.alpn
        )
        assert raw, f"empty ClientHello for {prof.alias}"
        got = ja4_from_bytes(raw)["ja4"]
        assert got == prof.ja4, f"{prof.alias}: {got} != {prof.ja4}"
        checked += 1
    assert checked >= 100


def test_unknown_profile_raises():
    import pytest

    with pytest.raises(KeyError):
        profiles.spec("does_not_exist")
