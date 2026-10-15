"""Unit tests for the named constants (enums) and name coercion."""
from __future__ import annotations

import pytest
from freetls import (
    Cipher,
    ExtensionType,
    Extension,
    NamedGroup,
    SignatureScheme,
    modes,
)
from freetls.constants import cipher_id, extension_id, group_id, sigalg_id
from freetls.fingerprint import tables


def test_enum_sizes_match_assigned_universe():
    u = tables.universe()["counts"]
    assert len(Cipher) == u["ciphers"] == 356
    assert len(ExtensionType) == u["extensions"] == 64
    assert len(SignatureScheme) == u["sigalgs"] == 49
    assert len(NamedGroup) == u["groups"] == 59


def test_cipher_enum_lookup():
    assert Cipher.TLS_AES_128_GCM_SHA256 == 0x1301
    assert Cipher["TLS_AES_128_GCM_SHA256"] == 0x1301
    assert Cipher(0x1301).name == "TLS_AES_128_GCM_SHA256"


def test_extension_enum_aliases():
    assert ExtensionType.SERVER_NAME == 0x0000
    assert ExtensionType.ALPN == 0x0010
    assert ExtensionType.SNI == 0x0000
    assert ExtensionType.SUPPORTED_VERSIONS == 0x002B
    assert ExtensionType.KEY_SHARE == 0x0033


def test_sigalg_and_group_enums():
    assert SignatureScheme.RSA_PSS_RSAE_SHA256 == 0x0804
    assert NamedGroup.X25519 == 0x001D
    assert NamedGroup.SECP256R1 == 0x0017


def test_id_helpers_accept_enum_int_and_name():
    assert cipher_id(Cipher.TLS_AES_128_GCM_SHA256) == 0x1301
    assert cipher_id("tls_aes_128_gcm_sha256") == 0x1301  # case-insensitive
    assert cipher_id(0x1301) == 0x1301
    assert extension_id("application_layer_protocol_negotiation") == 0x0010
    assert sigalg_id("rsa_pss_rsae_sha256") == 0x0804
    assert group_id("x25519") == 0x001D


def test_id_helpers_reject_bad_input():
    with pytest.raises(ValueError):
        cipher_id("NOT_A_CIPHER")
    with pytest.raises(TypeError):
        cipher_id(True)
    with pytest.raises(TypeError):
        cipher_id(1.5)


def test_specific_accepts_names_and_enums():
    spec = modes.specific(
        ciphers=[Cipher.TLS_AES_128_GCM_SHA256, "TLS_AES_256_GCM_SHA384", 0x1303],
        groups=[NamedGroup.X25519, "secp256r1"],
        sigalgs=["rsa_pss_rsae_sha256", SignatureScheme.ECDSA_SECP256R1_SHA256],
    )
    d = spec.to_engine()
    assert d["ciphers"] == [0x1301, 0x1302, 0x1303]
    assert spec.find("supported_curves").values == [0x001D, 0x0017]
    assert spec.find("signature_algorithms").values == [0x0804, 0x0403]


def test_extension_constructors_accept_names():
    assert Extension.supported_curves("x25519", NamedGroup.SECP384R1).values == [0x001D, 0x0018]
    assert Extension.signature_algorithms("rsa_pss_rsae_sha256").values == [0x0804]
    assert Extension.key_share("x25519").values == [0x001D]


def test_extension_rejects_unknown_group_name():
    with pytest.raises(ValueError):
        Extension.supported_curves("not-a-group")
