"""Unit tests for the ssl.SSLContext-style TLSContext API."""

from __future__ import annotations

from freetls import TLS12, TLS13, TLSContext


def test_default_context_has_baseline_spec():
    ctx = TLSContext()
    assert ctx.spec.ciphers
    assert ctx.spec.vers_max == TLS13


def test_mode_constructors():
    assert TLSContext.baseline(server_name="a.com").spec.server_name == "a.com"
    assert TLSContext.partial_random(seed=1).spec.ciphers
    assert TLSContext.true_random(seed=1).spec.ciphers
    assert TLSContext.specific(ciphers=[0x1301]).spec.ciphers == [0x1301]


def test_set_ciphers():
    ctx = TLSContext.baseline()
    ctx.set_ciphers([0x1301, 0x1302])
    assert ctx.spec.ciphers == [0x1301, 0x1302]


def test_set_alpn_protocols_replaces_existing():
    ctx = TLSContext.baseline()
    ctx.set_alpn_protocols(["h3"])
    alpn = [e for e in ctx.spec.extensions if e.kind == "alpn"]
    assert len(alpn) == 1
    assert alpn[0].strings == ["h3"]


def test_set_versions_updates_supported_versions():
    ctx = TLSContext.baseline()
    ctx.set_versions(TLS12, TLS13)
    sv = ctx.spec.find("supported_versions")
    assert sorted(sv.values) == [TLS12, TLS13]


def test_set_server_name_adds_and_removes_sni():
    ctx = TLSContext.baseline(server_name="old.com")
    ctx.set_server_name("new.com")
    assert ctx.spec.find("sni").server_name == "new.com"
    ctx.set_server_name(None)
    assert ctx.spec.find("sni") is None


def test_set_verify_and_load_locations():
    ctx = TLSContext.baseline(verify=False)
    ctx.set_verify(True, "/tmp/ca.pem")
    assert ctx.spec.verify is True and ctx.spec.root_ca == "/tmp/ca.pem"
    ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
    assert ctx.spec.verify is True


def test_context_manager():
    with TLSContext.baseline() as ctx:
        assert isinstance(ctx, TLSContext)
