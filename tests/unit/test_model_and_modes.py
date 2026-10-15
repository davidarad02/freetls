"""Unit tests for IANA tables, the spec model, and modes."""

from __future__ import annotations

import pytest

from freetls import Extension, SpecError, modes
from freetls.fingerprint import tables


def test_assigned_universe_counts():
    u = tables.universe()
    assert u["counts"]["ciphers"] == 356
    assert u["counts"]["extensions"] == 64
    assert u["counts"]["sigalgs"] == 49
    assert 0x1301 in u["ciphers"]
    assert 0 in u["extensions"]


def test_table_lookups():
    assert tables.cipher_name(0x1301) == "TLS_AES_128_GCM_SHA256"
    assert tables.extension_name(0x0000) == "server_name"
    assert tables.sigalg_value("rsa_pss_rsae_sha256") == 0x0804


def test_extension_requires_id_for_generic():
    with pytest.raises(SpecError):
        Extension("generic")
    with pytest.raises(SpecError):
        Extension("nonsense")


def test_extension_to_engine_shape():
    e = Extension.generic(0x1234, "aabb")
    assert e.to_engine() == {"type": "generic", "id": 0x1234, "data": "aabb"}


def test_spec_to_engine_roundtrip():
    spec = modes.baseline_spec(server_name="example.com")
    d = spec.to_engine()
    assert d["server_name"] == "example.com"
    assert any(e["type"] == "sni" for e in d["extensions"])
    assert any(e["type"] == "supported_versions" for e in d["extensions"])


def test_spec_copy_is_deep():
    spec = modes.baseline_spec()
    clone = spec.copy()
    clone.extensions.append(Extension.generic(0x1234))
    assert len(clone.extensions) == len(spec.extensions) + 1


def test_baseline_is_functional():
    spec = modes.baseline_spec(server_name="a.com")
    kinds = {e.kind for e in spec.extensions}
    for required in (
        "sni",
        "supported_versions",
        "key_share",
        "signature_algorithms",
        "supported_curves",
        "alpn",
    ):
        assert required in kinds


def test_partial_random_deterministic_with_seed():
    a = modes.partial_random(seed=42)
    b = modes.partial_random(seed=42)
    c = modes.partial_random(seed=43)
    assert a.ciphers == b.ciphers
    assert [e.to_engine() for e in a.extensions] == [e.to_engine() for e in b.extensions]
    assert a.ciphers != c.ciphers


def test_partial_random_adds_padding():
    base = modes.baseline_spec()
    part = modes.partial_random(n_random_ciphers=10, n_random_extensions=8, seed=1)
    assert len(part.ciphers) == len(base.ciphers) + 10
    assert len(part.extensions) == len(base.extensions) + 8


def test_random_modes_use_assigned_values_only():
    universe = tables.universe()
    allowed_c = set(universe["ciphers"])
    allowed_e = set(modes.SAFE_PADDING_EXT_IDS)
    for spec in (
        modes.partial_random(seed=5),
        modes.true_random(seed=5, n_ciphers=100, n_extensions=40),
    ):
        assert set(spec.ciphers) <= allowed_c
        generic = [e.id for e in spec.extensions if e.kind == "generic"]
        assert set(generic) <= allowed_e


def test_true_random_keeps_functional_core():
    spec = modes.true_random(seed=7, n_ciphers=80, n_extensions=40)
    # functional cipher present
    assert 0x1301 in spec.ciphers
    kinds = {e.kind for e in spec.extensions}
    assert {"supported_versions", "key_share", "signature_algorithms"} <= kinds


def test_safe_padding_excludes_known_unsafe():
    for unsafe in (0x0001, 0x000E, 0x001B, 0x0029, 0x002F, 0x0032):
        assert unsafe not in modes.SAFE_PADDING_EXT_IDS
