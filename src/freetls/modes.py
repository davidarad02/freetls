"""Specification builders for the three freetls modes.

- Specific:   exact user-chosen ciphers/extensions/sigalgs/alpn/versions.
- Partial:    a functional baseline plus a configurable amount of randomized
              padding drawn from the assigned IANA universe.
- Random:     maximal randomization from the assigned universe, with a minimal
              functional baseline so the handshake still completes.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable, Sequence

from .fingerprint.tables import as_cipher, as_group, as_sigalg, universe
from .model import (
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    Extension,
    FingerprintSpec,
    get_safe_mode,
)

# A broad, Chrome-like cipher list that works against virtually all servers.
DEFAULT_CIPHERS = [
    0x1301,
    0x1302,
    0x1303,
    0xC02B,
    0xC02F,
    0xC02C,
    0xC030,
    0xCCA9,
    0xCCA8,
    0xC013,
    0xC014,
    0x009C,
    0x009D,
    0x002F,
    0x0035,
]

DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
DEFAULT_GROUPS = [0x001D, 0x0017, 0x0018]
DEFAULT_ALPN = ["h2", "http/1.1"]

# The 16 reserved GREASE values (RFC 8701). Servers ignore these code points,
# so injecting them makes a ClientHello look browser-like without changing the
# negotiated cryptography. JA4/JA3 exclude GREASE by value.
GREASE_VALUES = [v * 0x101 for v in range(0x0A, 0x100, 0x10)]

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
    0x0002,
    0x0003,
    0x0004,
    0x0006,
    0x0007,
    0x0008,
    0x0009,
    0x000C,
    0x000F,
    0x0011,
    0x0012,
    0x0013,
    0x0014,
    0x0015,
    0x0016,
    0x0018,
    0x0019,
    0x001A,
    0x001C,
    0x001D,
    0x001E,
    0x001F,
    0x0020,
    0x0021,
    0x0022,
    0x0024,
    0x0025,
    0x0026,
    0x0027,
    0x002A,
    0x002C,
    0x0030,
    0x0031,
    0x0034,
    0x0035,
    0x0036,
    0x0037,
    0x0038,
    0x0039,
    0x003A,
    0x003B,
    0x003C,
    0x003D,
    0x003E,
    0xFD00,
    0xFE0D,
    0xFF01,
]


def _versions_list(vers_min: int, vers_max: int) -> list[int]:
    order = [TLS13, TLS12, TLS11, TLS10]
    return [v for v in order if vers_min <= v <= vers_max]


def functional_extensions(
    server_name: str | None,
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
    server_name: str | None = None,
    ciphers: Sequence[int | str] | None = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    verify: bool | None = None,
    grease: bool = False,
    grease_strategy: str = "random",
    seed: int | None = None,
) -> FingerprintSpec:
    """A functional, high-compatibility baseline (TLS 1.2/1.3 by default)."""
    cipher_list = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_CIPHERS)]
    sigalgs = [as_sigalg(s) for s in sigalgs]
    groups = [as_group(g) for g in groups]
    spec = FingerprintSpec(
        ciphers=cipher_list,
        extensions=functional_extensions(server_name, alpn, groups, sigalgs, vers_min, vers_max),
        vers_min=vers_min,
        vers_max=vers_max,
        server_name=server_name,
        verify=verify,
    )
    if grease:
        add_grease(spec, strategy=grease_strategy, seed=seed)
    return spec


def add_grease(
    spec: FingerprintSpec,
    *,
    ciphers: bool = True,
    groups: bool = True,
    versions: bool = True,
    extensions: bool = True,
    strategy: str = "random",
    seed: int | None = None,
) -> FingerprintSpec:
    """Inject GREASE code points into a spec's cipher/group/version/extension slots.

    ``strategy`` is ``"random"`` (a fresh GREASE value per slot) or ``"fixed"``
    (always ``0x0a0a``). GREASE slots are inserted at the front of each list,
    matching how mainstream browsers emit them; servers ignore the values.
    """
    if strategy not in ("random", "fixed"):
        raise ValueError(f"unknown grease strategy: {strategy!r}")
    rng = random.Random(seed)

    def pick() -> int:
        return 0x0A0A if strategy == "fixed" else rng.choice(GREASE_VALUES)

    if ciphers:
        spec.ciphers = [pick(), *spec.ciphers]
    if groups:
        ext = spec.find("supported_curves")
        if ext is not None:
            ext.values = [pick(), *ext.values]
    if versions:
        ext = spec.find("supported_versions")
        if ext is not None:
            ext.values = [pick(), *ext.values]
    if extensions:
        spec.extensions.insert(0, Extension.grease(pick()))
    return spec


def specific(
    ciphers: Iterable[int] | None = None,
    extensions: Iterable[Extension] | None = None,
    server_name: str | None = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    verify: bool | None = None,
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


# Optional extension kinds on the safe-mode whitelist that are safe to send
# empty (or with a benign value). Safe randomization draws a random subset of
# these instead of generic padding, which would fail safe-mode validation.
_SAFE_OPTIONAL_EXT_KINDS: dict[str, tuple[int, Callable[[], Extension]]] = {
    "sct": (0x0012, lambda: Extension("sct")),
    "session_ticket": (0x0023, lambda: Extension("session_ticket")),
    "renegotiation_info": (0xFF01, lambda: Extension("renegotiation_info")),
    "record_size_limit": (0x001C, lambda: Extension.record_size_limit(16385)),
    "padding": (0x0015, lambda: Extension.padding()),
}


def _adaptive_random_count(available: int) -> int:
    """Draw size that maximises the number of distinct subsets.

    ``C(n, k)`` is largest near ``k = n/2``, so half the pool yields the most
    distinct sets (and hence JA4_b / JA4_c values). Drawing the *whole* pool
    would be deterministic (one set)."""
    return max(1, available // 2)


def _free_safe_ext_count() -> int:
    """Number of safe-mode whitelist extensions not already in the baseline."""
    return sum(1 for eid, _ in _SAFE_OPTIONAL_EXT_KINDS.values() if eid not in _FUNCTIONAL_EXT_IDS)


# Default number of random generic extensions for the *unsafe* random modes.
# Half the padding pool maximises C(47, k); the old defaults (8 / 40) were far
# from optimal (C(47,8) and C(47,40)=C(47,7)).
_UNSAFE_RANDOM_EXT_COUNT = _adaptive_random_count(len(SAFE_PADDING_EXT_IDS))


def _supported_cipher_pool() -> list[int]:
    from .engine import supported_ciphers

    return [c for c in supported_ciphers() if c not in (0x0000, 0x00FF, 0x5600)]


def _safe_random_cipher_padding(rng: random.Random, n: int, used: set[int]) -> list[int]:
    pool = [c for c in _supported_cipher_pool() if c not in used]
    return rng.sample(pool, min(n, len(pool)))


def _safe_random_exts(rng: random.Random, n: int, used: set[int]) -> list[Extension]:
    out: list[Extension] = []
    pool = [k for k, (eid, _) in _SAFE_OPTIONAL_EXT_KINDS.items() if eid not in used]
    for kind in rng.sample(pool, min(n, len(pool))):
        eid, build = _SAFE_OPTIONAL_EXT_KINDS[kind]
        used.add(eid)
        out.append(build())
    return out


def partial_random(
    server_name: str | None = None,
    ciphers: Sequence[int | str] | None = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    n_random_ciphers: int | None = None,
    n_random_extensions: int | None = None,
    seed: int | None = None,
    verify: bool | None = None,
    safe: bool | None = None,
) -> FingerprintSpec:
    """Partial-random mode: functional baseline + randomized padding.

    ``n_random_ciphers`` / ``n_random_extensions`` default to 10 / 23 (half the
    padding pool, which maximises the number of distinct extension sets). With
    ``safe`` (or global safe mode) the cipher count defaults to *half of the
    engine's backed pool* and the extension count to a random subset of the
    whitelist's free extensions, and ciphers/extensions are drawn only from the
    backed set + whitelist, so the result passes safe-mode validation.
    """
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    base = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_CIPHERS)]
    used_c = set(base)
    if n_random_ciphers is None:
        if use_safe:
            pool = _supported_cipher_pool()
            available = sum(1 for c in pool if c not in used_c)
            n_random_ciphers = _adaptive_random_count(available)
        else:
            n_random_ciphers = 10
    if use_safe:
        base += _safe_random_cipher_padding(rng, n_random_ciphers, used_c)
    else:
        base += _random_cipher_padding(rng, n_random_ciphers, used_c)

    spec = baseline_spec(
        server_name=server_name,
        ciphers=base,
        alpn=alpn,
        vers_min=vers_min,
        vers_max=vers_max,
        verify=verify,
    )
    if n_random_extensions is None:
        if use_safe:
            n_random_extensions = rng.randint(0, _free_safe_ext_count())
        else:
            n_random_extensions = _UNSAFE_RANDOM_EXT_COUNT
    used_e = set(_FUNCTIONAL_EXT_IDS)
    if use_safe:
        spec.extensions += _safe_random_exts(rng, n_random_extensions, used_e)
    else:
        spec.extensions += _random_generic_exts(rng, n_random_extensions, used_e)
    return spec


def true_random(
    server_name: str | None = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    n_ciphers: int | None = None,
    n_extensions: int | None = None,
    seed: int | None = None,
    verify: bool | None = None,
    safe: bool | None = None,
) -> FingerprintSpec:
    """True-random mode: maximal random padding, minimal functional baseline.

    A small functional core (one working cipher + required extensions) is always
    injected so the handshake can complete against a real server. ``n_ciphers`` /
    ``n_extensions`` default to 60 / 23 (half the padding pool, which maximises
    the number of distinct extension sets). With ``safe`` (or global safe mode)
    the total cipher count defaults to the core plus *half of the backed pool* (so
    it varies instead of saturating), and padding is drawn only from the engine's
    supported ciphers and the safe-mode extension whitelist.
    """
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    core = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    used_c = set(core)
    if n_ciphers is None:
        if use_safe:
            pool = _supported_cipher_pool()
            available = sum(1 for c in pool if c not in used_c)
            n_ciphers = len(core) + _adaptive_random_count(available)
        else:
            n_ciphers = 60
    if use_safe:
        ciphers = core + _safe_random_cipher_padding(rng, max(0, n_ciphers - len(core)), used_c)
    else:
        ciphers = core + _random_cipher_padding(rng, max(0, n_ciphers - len(core)), used_c)

    spec = baseline_spec(
        server_name=server_name,
        ciphers=ciphers,
        alpn=alpn,
        vers_min=vers_min,
        vers_max=vers_max,
        verify=verify,
    )
    if n_extensions is None:
        if use_safe:
            n_extensions = rng.randint(0, _free_safe_ext_count())
        else:
            n_extensions = _UNSAFE_RANDOM_EXT_COUNT
    used_e = set(_FUNCTIONAL_EXT_IDS)
    if use_safe:
        spec.extensions += _safe_random_exts(rng, n_extensions, used_e)
    else:
        spec.extensions += _random_generic_exts(rng, n_extensions, used_e)
    return spec


def safe_random(
    server_name: str | None = None,
    alpn: Sequence[str] = DEFAULT_ALPN,
    vers_min: int = TLS12,
    vers_max: int = TLS13,
    n_ciphers: int | None = None,
    n_extensions: int | None = None,
    seed: int | None = None,
    verify: bool | None = None,
) -> FingerprintSpec:
    """Safe randomization: a functional baseline plus a random subset of the
    engine's supported ciphers and the safe-mode extension whitelist. Always
    passes safe-mode validation.

    ``n_ciphers`` / ``n_extensions`` default to half of the engine's backed pool
    and to the whitelist's free extensions, which maximises the number of
    distinct JA4 values. Pass explicit counts to offer more (browser-like) or
    fewer ciphers."""
    return partial_random(
        server_name=server_name,
        alpn=alpn,
        vers_min=vers_min,
        vers_max=vers_max,
        n_random_ciphers=n_ciphers,
        n_random_extensions=n_extensions,
        seed=seed,
        verify=verify,
        safe=True,
    )
