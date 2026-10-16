"""Safe/unsafe mode: reject specs the engine cannot fully back.

Unsafe is the default (backward compatible); safe mode is opt-in per spec
(``FingerprintSpec.safe``) or globally (``freetls.set_safe_mode``). See
``docs/route-b-plan.md`` §6.
"""

from __future__ import annotations

import pytest

import freetls
from freetls import Extension, FingerprintSpec, modes, profiles, safety


def _baseline(**kw) -> FingerprintSpec:
    return modes.baseline_spec(server_name="localhost", verify=False, **kw)


def test_default_mode_is_unsafe():
    assert freetls.get_safe_mode() is False
    spec = _baseline()
    spec.ciphers = [0xC001]  # static-ECDH suite; never backed by the engine
    safety.validate(spec)  # no raise while safe mode is off


def test_baseline_passes_when_safe():
    spec = _baseline()
    spec.safe = True
    safety.validate(spec)


@pytest.mark.parametrize("ext_id", [0x7550, 0xFE0D, 0xCA34, 0x0022])
def test_unsupported_extensions_rejected(ext_id):
    spec = _baseline()
    spec.safe = True
    spec.extensions.append(Extension.generic(ext_id, ""))
    with pytest.raises(freetls.SpecError):
        safety.validate(spec)


def test_unsupported_cipher_rejected():
    spec = _baseline()
    spec.safe = True
    spec.ciphers = [0x1301, 0xC001]
    with pytest.raises(freetls.SpecError):
        safety.validate(spec)


def test_grease_is_exempt():
    spec = _baseline(grease=True)
    spec.safe = True
    safety.validate(spec)  # GREASE ciphers/extensions are ignored


def test_whitelisted_extensions_pass():
    spec = _baseline()
    spec.safe = True
    spec.extensions.extend([Extension("sct"), Extension("session_ticket")])
    safety.validate(spec)


def test_browser_preset_fails_safe_mode():
    spec = FingerprintSpec(preset="HelloChrome_133", safe=True)
    with pytest.raises(freetls.SpecError):
        safety.validate(spec)


def test_spec_override_beats_global():
    freetls.set_safe_mode(True)
    try:
        spec = _baseline()
        spec.safe = False
        spec.ciphers = [0xC001]
        safety.validate(spec)  # spec opts out of the global default
    finally:
        freetls.set_safe_mode(False)
    spec = _baseline()
    spec.safe = True
    spec.ciphers = [0xC001]
    with pytest.raises(freetls.SpecError):
        safety.validate(spec)


def test_safe_random_passes_and_completes(tls_server_13):
    spec = modes.safe_random(server_name="localhost", verify=False, seed=7)
    spec.safe = True
    safety.validate(spec)
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.state.version == "TLS1.3"


def test_connect_rejects_unsafe_spec(tls_server_13):
    spec = FingerprintSpec(
        preset="HelloChrome_133", safe=True, server_name="localhost", verify=False
    )
    with freetls.TLSSession(spec) as s:
        with pytest.raises(freetls.SpecError):
            s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")


def test_profile_catalog_safe_ratio():
    names = profiles.names()
    assert names
    passed = 0
    for name in names:
        spec = profiles.spec(name)
        spec.safe = True
        try:
            safety.validate(spec)
            passed += 1
        except freetls.SpecError:
            pass
    # Browser presets carry ECH/trust_anchors and unbacked ciphers, so only a
    # subset of the catalog is fully backed.
    assert 0 < passed < len(names)
