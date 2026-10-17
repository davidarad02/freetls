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
    QuicInitialSpec,
    TransportParameter,
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

# QUIC is TLS 1.3 only, offers h3, and has a QUIC-specific cipher pool.
DEFAULT_QUIC_ALPN = ["h3"]
DEFAULT_QUIC_CIPHERS = [0x1301, 0x1302, 0x1303]

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

# Assigned extension IDs a server will safely ignore when sent with empty data,
# validated against every server stack the test-suite uses (OpenSSL s_server,
# Python ssl and Go net/http). Two groups are excluded, so random modes keep an
# assigned-only universe AND complete real handshakes against all of them:
#   - the six that provoke an OpenSSL alert with empty data
#     (0x0001, 0x000e, 0x001b, 0x0029, 0x002f, 0x0032);
#   - the four whose *empty* encoding Go's crypto/tls rejects as malformed
#     (0x002a early_data, 0x002c cookie, 0x0039 quic_transport_parameters,
#     0xff01 renegotiation_info).
# 0x0023 (session_ticket) is included: an empty session_ticket is valid on the
# wire and accepted by all three stacks.
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
    0x0023,
    0x0024,
    0x0025,
    0x0026,
    0x0027,
    0x0030,
    0x0031,
    0x0034,
    0x0035,
    0x0036,
    0x0037,
    0x0038,
    0x003A,
    0x003B,
    0x003C,
    0x003D,
    0x003E,
    0xFD00,
    0xFE0D,
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
    """Specific mode: exact control. Passing ``extensions`` replaces the set."""
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


def _used_ext_ids(spec: FingerprintSpec, base: set[int]) -> set[int]:
    """Extension IDs already present in ``spec`` so padding never duplicates one.

    The random modes build from ``baseline_spec``, but a caller-supplied
    ``session_ticket`` (resumption) must not be shadowed by a generic 0x0023.
    """
    used = set(base)
    if any(
        e.kind == "session_ticket" or (e.kind == "generic" and e.id == 0x0023)
        for e in spec.extensions
    ):
        used.add(0x0023)
    return used


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


def _random_padding_count(rng: random.Random, available: int, base_len: int) -> int:
    """Draw a padding count that maximises the reachable JA4 space.

    ``JA4_a`` encodes the offered cipher/extension counts as a two-digit field
    (``min(len, 99)`` in ``ja4.py``). Fixing the count — e.g. always half the
    pool — collapses that field to a *single* value, which is a deterministic
    tell; drawing it uniformly over the whole feasible range makes every count a
    distinct ``JA4_a``, and the number of distinct JA4 values is the product of
    the reachable counts and the set hashes. The set itself is drawn uniformly,
    which saturates the 48-bit ``JA4_b`` / ``JA4_c`` hashes (``C(n, k)`` exceeds
    2^48 at ``k ≈ 8``, so the pool size is irrelevant beyond that).

    The range is clamped so the total count stays under 100 and never saturates
    the two-digit field (a saturated count would collapse the diversity again).
    """
    hi = min(available, max(0, 99 - base_len))
    return rng.randint(0, hi) if hi > 0 else 0


def _free_safe_ext_count() -> int:
    """Number of safe-mode whitelist extensions not already in the baseline."""
    return sum(1 for eid, _ in _SAFE_OPTIONAL_EXT_KINDS.values() if eid not in _FUNCTIONAL_EXT_IDS)


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

    ``n_random_ciphers`` / ``n_random_extensions`` default to a uniform draw over
    the whole feasible range, so the ``JA4_a`` cipher/extension *counts* vary per
    call (fixing them freezes that field) and the number of distinct JA4 values is
    maximised. With ``safe`` (or global safe mode) ciphers/extensions are drawn
    only from the engine's backed set and the whitelist, so the result passes
    safe-mode validation.
    """
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    base = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_CIPHERS)]
    used_c = set(base)
    pool_c = _supported_cipher_pool() if use_safe else _CIPHER_POOL
    if n_random_ciphers is None:
        available = sum(1 for c in pool_c if c not in used_c)
        n_random_ciphers = _random_padding_count(rng, available, len(base))
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
        pool_e = _free_safe_ext_count() if use_safe else len(SAFE_PADDING_EXT_IDS)
        n_random_extensions = _random_padding_count(rng, pool_e, len(_FUNCTIONAL_EXT_IDS))
    used_e = _used_ext_ids(spec, _FUNCTIONAL_EXT_IDS)
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
    ``n_extensions`` default to a uniform draw over the whole feasible range, so
    the ``JA4_a`` counts vary per call and the number of distinct JA4 values is
    maximised. With ``safe`` (or global safe mode) padding is drawn only from the
    engine's supported ciphers and the safe-mode extension whitelist.
    """
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    core = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    used_c = set(core)
    pool_c = _supported_cipher_pool() if use_safe else _CIPHER_POOL
    if n_ciphers is None:
        available = sum(1 for c in pool_c if c not in used_c)
        n_ciphers = len(core) + _random_padding_count(rng, available, len(core))
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
        pool_e = _free_safe_ext_count() if use_safe else len(SAFE_PADDING_EXT_IDS)
        n_extensions = _random_padding_count(rng, pool_e, len(_FUNCTIONAL_EXT_IDS))
    used_e = _used_ext_ids(spec, _FUNCTIONAL_EXT_IDS)
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

    ``n_ciphers`` / ``n_extensions`` default to a uniform draw over the whole
    feasible range, so the ``JA4_a`` counts vary per call (a fixed count is a
    deterministic tell) and the number of distinct JA4 values is maximised. Pass
    explicit counts to pin them."""
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


# ---------------------------------------------------------------------------
# QUIC / HTTP-3 modes
# ---------------------------------------------------------------------------
#
# QUIC is TLS 1.3 only and offers ``h3``. The transport-parameter extension
# (0x0039) carries the Initial's parameters; note that its *contents and order*
# do NOT change JA4q, which hashes extension type IDs only. Randomising them
# therefore varies the wire, not the fingerprint — the JA4q is driven by the
# cipher list and the set of extension types.

# Extension 0x0039 must never be duplicated by generic padding.
_QUIC_FUNCTIONAL_EXT_IDS = _FUNCTIONAL_EXT_IDS | {0x0039}


def default_quic_transport_parameters() -> list[TransportParameter]:
    """A realistic, browser-like default QUIC transport-parameter set.

    Use this as the base for a custom ``transport_parameters=`` list: uQUIC takes
    the transport parameters from the spec alone, so a partial list still
    handshakes but then breaks every HTTP/3 request (the peer cannot open its
    control/QPACK streams).
    """
    return [
        TransportParameter.varint("max_idle_timeout", 30000),
        TransportParameter.varint("max_udp_payload_size", 1472),
        TransportParameter.varint("initial_max_data", 1048576),
        TransportParameter.varint("initial_max_stream_data_bidi_local", 262144),
        TransportParameter.varint("initial_max_stream_data_bidi_remote", 262144),
        TransportParameter.varint("initial_max_stream_data_uni", 262144),
        TransportParameter.varint("initial_max_streams_bidi", 100),
        TransportParameter.varint("initial_max_streams_uni", 3),
        TransportParameter.varint("max_ack_delay", 25),
        TransportParameter.varint("active_connection_id_limit", 2),
        TransportParameter.grease(2),
    ]


def _quic_cipher_pool() -> list[int]:
    return [c for c in _supported_cipher_pool() if 0x1301 <= c <= 0x1305]


def quic_functional_extensions(
    server_name: str | None,
    alpn: Sequence[str],
    groups: Sequence[int | str],
    sigalgs: Sequence[int | str],
    transport_parameters: Sequence[TransportParameter],
) -> list[Extension]:
    groups = [as_group(g) for g in groups]
    sigalgs = [as_sigalg(s) for s in sigalgs]
    exts: list[Extension] = []
    if server_name:
        exts.append(Extension.sni(server_name))
    exts.append(Extension.supported_versions(TLS13))
    exts.append(Extension.supported_curves(*groups))
    exts.append(Extension.signature_algorithms(*sigalgs))
    exts.append(Extension.key_share(groups[0] if groups else 0x001D))
    exts.append(Extension.psk_key_exchange_modes(1))
    exts.append(Extension.alpn(*alpn))
    exts.append(Extension.quic_transport_parameters(*transport_parameters))
    return exts


def quic_baseline_spec(
    server_name: str | None = None,
    ciphers: Sequence[int | str] | None = None,
    alpn: Sequence[str] = DEFAULT_QUIC_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    transport_parameters: Sequence[TransportParameter] | None = None,
    quic: QuicInitialSpec | None = None,
    datagrams: bool = False,
    verify: bool | None = None,
) -> FingerprintSpec:
    """A functional QUIC ClientHello baseline (TLS 1.3 only, ALPN ``h3``)."""
    cipher_list = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_QUIC_CIPHERS)]
    tps = (
        list(transport_parameters)
        if transport_parameters is not None
        else default_quic_transport_parameters()
    )
    return FingerprintSpec(
        ciphers=cipher_list,
        extensions=quic_functional_extensions(server_name, alpn, groups, sigalgs, tps),
        vers_min=TLS13,
        vers_max=TLS13,
        server_name=server_name,
        quic=quic if quic is not None else QuicInitialSpec(),
        quic_datagrams=datagrams,
        verify=verify,
    )


def quic_specific(
    ciphers: Iterable[int] | None = None,
    extensions: Iterable[Extension] | None = None,
    server_name: str | None = None,
    alpn: Sequence[str] = DEFAULT_QUIC_ALPN,
    sigalgs: Sequence[int | str] = DEFAULT_SIGALGS,
    groups: Sequence[int | str] = DEFAULT_GROUPS,
    transport_parameters: Sequence[TransportParameter] | None = None,
    quic: QuicInitialSpec | None = None,
    datagrams: bool = False,
    verify: bool | None = None,
) -> FingerprintSpec:
    """Specific QUIC mode: exact control. Passing ``extensions`` replaces the set."""
    spec = quic_baseline_spec(
        server_name=server_name,
        ciphers=list(ciphers) if ciphers is not None else DEFAULT_QUIC_CIPHERS,
        alpn=alpn,
        sigalgs=sigalgs,
        groups=groups,
        transport_parameters=transport_parameters,
        quic=quic,
        datagrams=datagrams,
        verify=verify,
    )
    if extensions is not None:
        spec.extensions = list(extensions)
    return spec


def _quic_random_cipher_padding(rng: random.Random, n: int, used: set[int]) -> list[int]:
    pool = [c for c in _quic_cipher_pool() if c not in used]
    return rng.sample(pool, min(n, len(pool)))


def quic_partial_random(
    server_name: str | None = None,
    ciphers: Sequence[int | str] | None = None,
    alpn: Sequence[str] = DEFAULT_QUIC_ALPN,
    n_random_ciphers: int | None = None,
    n_random_extensions: int | None = None,
    transport_parameters: Sequence[TransportParameter] | None = None,
    quic: QuicInitialSpec | None = None,
    datagrams: bool = False,
    seed: int | None = None,
    verify: bool | None = None,
    safe: bool | None = None,
) -> FingerprintSpec:
    """Partial-random QUIC mode: baseline + randomized TLS 1.3 cipher/extension padding."""
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    base = [as_cipher(c) for c in (ciphers if ciphers is not None else DEFAULT_QUIC_CIPHERS)]
    used_c = set(base)
    if n_random_ciphers is None:
        available = sum(1 for c in _quic_cipher_pool() if c not in used_c)
        n_random_ciphers = _random_padding_count(rng, available, len(base))
    base += _quic_random_cipher_padding(rng, n_random_ciphers, used_c)

    spec = quic_baseline_spec(
        server_name=server_name,
        ciphers=base,
        alpn=alpn,
        transport_parameters=transport_parameters,
        quic=quic,
        datagrams=datagrams,
        verify=verify,
    )
    if n_random_extensions is None:
        pool_e = _free_safe_ext_count() if use_safe else len(SAFE_PADDING_EXT_IDS)
        n_random_extensions = _random_padding_count(rng, pool_e, len(_QUIC_FUNCTIONAL_EXT_IDS))
    used_e = _used_ext_ids(spec, _QUIC_FUNCTIONAL_EXT_IDS)
    if use_safe:
        spec.extensions += _safe_random_exts(rng, n_random_extensions, used_e)
    else:
        spec.extensions += _random_generic_exts(rng, n_random_extensions, used_e)
    return spec


def quic_true_random(
    server_name: str | None = None,
    alpn: Sequence[str] = DEFAULT_QUIC_ALPN,
    n_ciphers: int | None = None,
    n_extensions: int | None = None,
    transport_parameters: Sequence[TransportParameter] | None = None,
    quic: QuicInitialSpec | None = None,
    datagrams: bool = False,
    seed: int | None = None,
    verify: bool | None = None,
    safe: bool | None = None,
) -> FingerprintSpec:
    """True-random QUIC mode: maximal padding over the TLS 1.3 cipher pool."""
    use_safe = get_safe_mode() if safe is None else bool(safe)
    rng = random.Random(seed)
    core = [0x1301]
    used_c = set(core)
    if n_ciphers is None:
        available = sum(1 for c in _quic_cipher_pool() if c not in used_c)
        n_ciphers = len(core) + _random_padding_count(rng, available, len(core))
    ciphers = core + _quic_random_cipher_padding(rng, max(0, n_ciphers - len(core)), used_c)

    spec = quic_baseline_spec(
        server_name=server_name,
        ciphers=ciphers,
        alpn=alpn,
        transport_parameters=transport_parameters,
        quic=quic,
        datagrams=datagrams,
        verify=verify,
    )
    if n_extensions is None:
        pool_e = _free_safe_ext_count() if use_safe else len(SAFE_PADDING_EXT_IDS)
        n_extensions = _random_padding_count(rng, pool_e, len(_QUIC_FUNCTIONAL_EXT_IDS))
    used_e = _used_ext_ids(spec, _QUIC_FUNCTIONAL_EXT_IDS)
    if use_safe:
        spec.extensions += _safe_random_exts(rng, n_extensions, used_e)
    else:
        spec.extensions += _random_generic_exts(rng, n_extensions, used_e)
    return spec
