"""QUICSession request-authority handling (IPv6 bracketing, non-default ports)."""

from __future__ import annotations

from freetls.model import FingerprintSpec
from freetls.quic import QUICSession


def _session(sni: str = "", remote: tuple[str, int] | None = None) -> QUICSession:
    s = QUICSession(FingerprintSpec())
    s._sni = sni
    s._remote = remote
    return s


def test_authority_brackets_ipv6():
    s = _session(remote=("::1", 8443))
    assert s._authority() == "[::1]:8443"


def test_authority_omits_default_port():
    assert _session(remote=("127.0.0.1", 443))._authority() == "127.0.0.1"
    assert _session(remote=("127.0.0.1", 8443))._authority() == "127.0.0.1:8443"


def test_authority_prefers_sni_host():
    assert _session(sni="example.com", remote=("127.0.0.1", 443))._authority() == "example.com"
    assert (
        _session(sni="example.com", remote=("127.0.0.1", 8443))._authority() == "example.com:8443"
    )


def test_authority_explicit_override_and_empty():
    assert _session(remote=("127.0.0.1", 8443))._authority("other:1234") == "other:1234"
    assert _session()._authority() == ""


def test_authority_only_brackets_real_ipv6():
    # A non-IPv6 host containing ':' must not be bracketed.
    assert _session(sni="example.com:8443")._authority() == "example.com:8443"
    # An already-bracketed literal is left alone.
    assert _session(sni="[::1]:8443")._authority() == "[::1]:8443"
