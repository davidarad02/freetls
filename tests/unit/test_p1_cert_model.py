"""P1: certificate options flow through the spec model."""

from __future__ import annotations

from freetls import FingerprintSpec


def test_cert_options_to_engine():
    spec = FingerprintSpec(
        verify=True,
        check_hostname=False,
        system_roots=False,
        root_ca="/ca.pem",
        ca_dir="/ca.d",
        cadata="PEM",
        client_cert="/c.pem",
        client_key="/k.pem",
        pinned_sha256=["abc"],
    )
    d = spec.to_engine()
    assert d["check_hostname"] is False
    assert d["system_roots"] is False
    assert d["root_ca"] == "/ca.pem"
    assert d["ca_dir"] == "/ca.d"
    assert d["cadata"] == "PEM"
    assert d["client_cert"] == "/c.pem"
    assert d["client_key"] == "/k.pem"
    assert d["pinned_sha256"] == ["abc"]


def test_cert_options_omitted_when_unset():
    d = FingerprintSpec().to_engine()
    for k in ("check_hostname", "system_roots", "ca_dir", "cadata", "client_cert", "pinned_sha256"):
        assert k not in d


def test_copy_preserves_cert_options():
    spec = FingerprintSpec(
        pinned_sha256=["x"], check_hostname=False, client_cert_pem="C", client_key_pem="K"
    )
    clone = spec.copy()
    assert clone.pinned_sha256 == ["x"]
    assert clone.check_hostname is False
    assert clone.client_cert_pem == "C" and clone.client_key_pem == "K"
