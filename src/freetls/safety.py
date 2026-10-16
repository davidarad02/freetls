"""Safe-mode validation.

Safe mode rejects any spec whose *effective* ClientHello contains a cipher or
extension the engine cannot directly support. The effective hello is built
offline by the engine (from the spec, a preset, or a ``chlo_json`` document) and
parsed, so presets and custom documents are validated exactly as emitted.

Unsafe is the default (backward compatible). See ``docs/route-b-plan.md`` §6.
"""

from __future__ import annotations

from .engine import chlo_raw, preset_raw_opts, spec_raw, supported_ciphers, supported_extensions
from .errors import SpecError
from .fingerprint.parse import is_grease, parse_client_hello
from .model import FingerprintSpec, get_safe_mode


def is_safe(spec: FingerprintSpec) -> bool:
    """True if safe mode applies to ``spec`` (per-spec override or global)."""
    return get_safe_mode() if spec.safe is None else bool(spec.safe)


def effective_hello(spec: FingerprintSpec) -> bytes:
    """Build the ClientHello ``spec`` will emit, offline (no network)."""
    if spec.chlo_json is not None:
        return chlo_raw(spec.chlo_json)
    if spec.quic_id is not None:
        from .engine import quic_id_raw

        raw = quic_id_raw(spec.quic_id, spec.preset_no_sni, spec.preset_alpn)
        if not raw:
            raise SpecError(f"safe mode: cannot build QUIC preset {spec.quic_id!r}")
        return raw
    if spec.preset is not None:
        raw = preset_raw_opts(spec.preset, spec.preset_no_sni, spec.preset_alpn)
        if not raw:
            raise SpecError(f"safe mode: cannot build preset {spec.preset!r}")
        return raw
    return spec_raw(spec.to_engine())


def validate(spec: FingerprintSpec) -> None:
    """Raise ``SpecError`` if safe mode is on and ``spec`` is not fully backed."""
    if not is_safe(spec):
        return
    hello = parse_client_hello(effective_hello(spec))
    allowed_ciphers = set(supported_ciphers())
    allowed_exts = set(supported_extensions())
    bad_ciphers = sorted({c for c in hello.ciphers if not is_grease(c)} - allowed_ciphers)
    bad_exts = sorted({e for e in hello.ext_types if not is_grease(e)} - allowed_exts)
    if bad_ciphers or bad_exts:
        parts = []
        if bad_ciphers:
            parts.append("unsupported ciphers " + ", ".join(f"0x{c:04x}" for c in bad_ciphers))
        if bad_exts:
            parts.append("unsupported extensions " + ", ".join(f"0x{e:04x}" for e in bad_exts))
        raise SpecError("safe mode: " + "; ".join(parts))
