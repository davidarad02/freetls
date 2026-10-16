"""Unit tests for the common-JA4 profile catalog."""

from __future__ import annotations

from freetls import engine, profiles
from freetls.fingerprint import ja4_from_bytes


def test_catalog_size():
    info = profiles.catalog_info()
    assert info["count"] >= 100
    assert info["distinct_ja4"] >= 50


def test_known_aliases_exist():
    for alias in (
        "chrome_133",
        "chrome_155",
        "firefox_120",
        "firefox_148",
        "safari_16_0",
        "safari_26_3",
        "edge_106",
        "ios_14",
        "android_11_okhttp",
        "golang",
    ):
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
    """Offline determinism: each catalog entry's spec yields its stored JA4/JA4q."""
    checked = 0
    for prof in profiles.list_profiles():
        if prof.quic_id is not None:
            raw = engine.quic_id_raw(prof.quic_id, no_sni=prof.no_sni, alpn=prof.alpn)
            assert raw, f"empty QUIC ClientHello for {prof.alias}"
            got = ja4_from_bytes(raw, transport="q")["ja4"]
            assert got == prof.ja4q, f"{prof.alias}: {got} != {prof.ja4q}"
            checked += 1
            continue
        if prof.chlo_json is not None:
            raw = engine.chlo_raw(prof.chlo_json)
        else:
            raw = engine.preset_raw_opts(prof.preset, no_sni=prof.no_sni, alpn=prof.alpn)
        assert raw, f"empty ClientHello for {prof.alias}"
        got = ja4_from_bytes(raw)["ja4"]
        assert got == prof.ja4, f"{prof.alias}: {got} != {prof.ja4}"
        checked += 1
    assert checked >= 100


def test_quic_catalog_entries():
    info = profiles.catalog_info()
    assert info["quic_count"] >= 20
    assert info["distinct_ja4q"] >= 5
    prof = profiles.get("QUICChrome_146_IPv4")
    assert prof is not None and prof.quic_id == "QUICChrome_146_IPv4"
    assert prof.ja4q.startswith("q")
    assert profiles.find_ja4(prof.ja4q)
    assert profiles.search("quicchrome")


def test_quic_variant_specs():
    spec = profiles.get("quicchrome_146_ipv4").spec()
    assert spec.to_engine()["transport"] == "quic"
    assert spec.to_engine()["quic_id"] == "QUICChrome_146_IPv4"
    noalpn = profiles.get("quicchrome_146_ipv4_noalpn").spec()
    assert noalpn.to_engine()["preset_alpn_remove"] is True
    nosni = profiles.get("quicchrome_146_ipv4_nosni").spec()
    assert nosni.to_engine()["preset_no_sni"] is True


def test_h3_bundle():
    spec = profiles.h3_bundle("QUICFirefox_116A", datagrams=True)
    assert spec.quic_id == "QUICFirefox_116A"
    assert spec.quic_datagrams is True


def test_unknown_profile_raises():
    import pytest

    with pytest.raises(KeyError):
        profiles.spec("does_not_exist")
