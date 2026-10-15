"""Specification builders for the three freetls modes.

- Specific:   exact user-chosen ciphers/extensions/sigalgs/alpn/versions.
- Partial:    a functional baseline plus a configurable amount of randomized
              padding drawn from the assigned IANA universe.
- Random:     maximal randomization from the assigned universe, with a minimal
              functional baseline so the handshake still completes.
"""
from __future__ import annotations

import random
from typing import Iterable, Optional, Sequence

from .fingerprint.tables import as_cipher, as_group, as_sigalg, universe
from .model import (
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    Extension,
    FingerprintSpec,
)

# A broad, Chrome-like cipher list that works against virtually all servers.
DEFAULT_CIPHERS = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]

DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
DEFAULT_GROUPS = [0x001D, 0x0017, 0x0018]
DEFAULT_ALPN = ["h2", "http/1.1"]

# Assigned IANA universe (loaded once).
_U = universe()
_CIPHER_POOL = [c for c in _U["ciphers"] if c not in (0x0000,)]
_EXT_POOL = _U["extensions"]
_SIGALG_POOL = _U["sigalgs"]

# Extension IDs that must not be shadowed by generic padding.
_FUNCTIONAL_EXT_IDS = {
    0x0000,  # server_name
    0x000A,  # supported_groups
    0x000B,  # ec_point_formats
    0x000D,  # signature_algorithms
    0x0010,  # alpn
    0x0017,  # extended_master_secret
    0x0023,  # session_ticket
    0x002B,  # supported_versions
    0x002D,  # psk_key_exchange_modes
    0x0033,  # key_share
    0x0005,  # status_request
}

# Assigned extension IDs that a server will safely ignore when sent with empty
# data (empirically verified against an OpenSSL 3.5 server). The six assigned
# extensions that provoke an alert with empty data (0x0001, 0x000e, 0x001b,
# 0x0029, 0x002f, 0x0032) are deliberately excluded, so random modes keep an
# assigned-only universe AND complete real handshakes.
SAFE_PADDING_EXT_IDS = [
    0x0002, 0x0003, 0x0004, 0x0006, 0x0007, 0x0008, 0x0009, 0x000C, 0x000F,
    0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0018, 0x0019, 0x001A,
    0x001C, 0x001D, 0x001E, 0x001F, 0x0020, 0x0021, 0x0022, 0x0024, 0x0025,
    0x0026, 0x0027, 0x002A, 0x002C, 0x0030, 0x0031, 0x0034, 0x0035, 0x0036,
    0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0xFD00,
    0xFE0D, 0xFF01,
]


def _versions_list(vers_min: int, vers_max: int) -> list[int]:
    order = [TLS13, TLS12, TLS11, TLS10]
    return [v for v in order if vers_min <= v <= vers_max]


def functional_extensions(
    server_name: Optional[str],
    alpn: Sequence[str],
    groups: Sequence[int | str],
    sigalgs: Sequence[int | str],
    vers_min: int,
    vers_max: int,
) -> list[Extension]:
    groups = [as_group(g) for g in groups]
    sigalgs = [as_sigalg(s) for s in sigalgs]
    exts: list[Extension] = []
    if server_name:
        exts.append(Extension.sni(server_name))
    exts.append(Extension("extended_master_secret"))
    exts.append(Extension.supported_versions(*_versions_list(vers_min, vers_max)))
    exts.append(Extension.supported_curves(*groups))
    exts.append(Extension.ec_point_formats(0))
    exts.append(Extension.signature_algorithms(*sigalgs))
    exts.append(Extension.key_share(groups[0] if groups else 0x001D))
    exts.append(Extension.psk_key_exchange_modes(1))
    exts.append(Extension.alpn(*alpn))
    exts.append(Extension("status_request"))
    return exts


def baseline_spec(
    server_name: Optional[str] = None,
    ciphers: Optional[Sequence[int | str]] = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    verify: bool = False,
) -> FingerprintSpec:
    """A functional, high-compatibility baseline (TLS 1.2/1.3 by default)."""
    ciphers = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_CIPHERS)]
    sigalgs = [as_sigalg(s) for s in sigalgs]
    groups = [as_group(g) for g in groups]
    return FingerprintSpec(
        ciphers=ciphers,
        extensions=functional_extensions(
            server_name, alpn, groups, sigalgs, vers_min, vers_max
        ),
        vers_min=vers_min,
        vers_max=vers_max,
        server_name=server_name,
        verify=verify,
    )


def specific(
    ciphers: Optional[Iterable[int]] = None,
    extensions: Optional[Iterable[Extension]] = None,
    server_name: Optional[str] = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    verify: bool = False,
) -> FingerprintSpec:
    """Specific mode: exact control. Missing functional extensions are added."""
    spec = baseline_spec(
        server_name=server_name,
        ciphers=list(ciphers) if ciphers is not None else DEFAULT_CIPHERS,
        alpn=alpn,
        sigalgs=sigalgs,
        groups=groups,
        vers_min=vers_min,
        vers_max=vers_max,
        verify=verify,
    )
    if extensions is not None:
        # Replace the functional set with the user's explicit list.
        spec.extensions = list(extensions)
    return spec


def _random_generic_exts(rng: random.Random, n: int, used: set[int]) -> list[Extension]:
    out = []
    pool = [e for e in SAFE_PADDING_EXT_IDS if e not in used]
    for ext_id in rng.sample(pool, min(n, len(pool))):
        used.add(ext_id)
        out.append(Extension.generic(ext_id, ""))
    return out


def _random_cipher_padding(rng: random.Random, n: int, used: set[int]) -> list[int]:
    pool = [c for c in _CIPHER_POOL if c not in used]
    picks = rng.sample(pool, min(n, len(pool)))
    return picks


def partial_random(
    server_name: Optional[str] = None,
    ciphers: Optional[Sequence[int | str]] = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    n_random_ciphers: int = 10,
    n_random_extensions: int = 8,
    seed: Optional[int] = None,
    verify: bool = False,
) -> FingerprintSpec:
    """Partial-random mode: functional baseline + randomized padding."""
    rng = random.Random(seed)
    base = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_CIPHERS)]
    used_c = set(base)
    base += _random_cipher_padding(rng, n_random_ciphers, used_c)

    spec = baseline_spec(
        server_name=server_name, ciphers=base, alpn=alpn,
        vers_min=vers_min, vers_max=vers_max, verify=verify,
    )
    used_e = set(_FUNCTIONAL_EXT_IDS)
    spec.extensions += _random_generic_exts(rng, n_random_extensions, used_e)
    return spec


def true_random(
    server_name: Optional[str] = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    n_ciphers: int = 60,
    n_extensions: int = 40,
    seed: Optional[int] = None,
    verify: bool = False,
) -> FingerprintSpec:
    """True-random mode: maximal random padding, minimal functional baseline.

    A small functional core (one working cipher + required extensions) is always
    injected so the handshake can complete against a real server.
    """
    rng = random.Random(seed)
    core = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    used_c = set(core)
    ciphers = core + _random_cipher_padding(rng, max(0, n_ciphers - len(core)), used_c)

    spec = baseline_spec(
        server_name=server_name, ciphers=ciphers, alpn=alpn,
        vers_min=vers_min, vers_max=vers_max, verify=verify,
    )
    used_e = set(_FUNCTIONAL_EXT_IDS)
    spec.extensions += _random_generic_exts(rng, n_extensions, used_e)
    return spec
