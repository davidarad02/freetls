#!/usr/bin/env python3
"""Generate the common-JA4 profile catalog for freetls.

The catalog is built from uTLS's real, shipped ClientHello presets (Chrome,
Firefox, Safari, Edge, iOS, Android/OkHttp, 360, QQ, Go) plus realistic
variants that real clients exhibit: HTTP/1.1-only ALPN, no ALPN, and no SNI
(connecting by IP). Each entry is produced *offline* by the engine's
preset builder, and its JA4/JA3 are computed and stored for verification.

It also merges the **QUIC** fingerprints: uQUIC's 7 unique browser parrots
(Firefox 116 A/B/C, Chrome 115/146 IPv4/IPv6) expanded over the QUIC variants
(base ``h3``, ``_noalpn``, ``_nosni``, ``_nosni_noalpn``). Their JA4q is stored
instead of JA4/JA3. The ``_h1`` variant is not emitted for QUIC: offering
HTTP/1.1 over QUIC is meaningless.

Network is never used.

Profiles are emitted only when their JA4 (or JA4q) is stable across repeated
builds; JA3 (which is order-sensitive) is recorded only when it is stable too,
and is left blank for extension-shuffling presets.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

from freetls import engine  # noqa: E402
from freetls.fingerprint import ja3_from_bytes, ja4_from_bytes  # noqa: E402

OUT = os.path.join(ROOT, "src", "freetls", "profiles", "catalog.json")

# Variants: (suffix, no_sni, alpn)
VARIANTS = [
    ("", False, None),
    ("_h1", False, ["http/1.1"]),
    ("_noalpn", False, []),
    ("_nosni", True, None),
    ("_nosni_noalpn", True, []),
]

# QUIC variants: no _h1 (HTTP/1.1 over QUIC is meaningless).
QUIC_VARIANTS = [
    ("", False, None),
    ("_noalpn", False, []),
    ("_nosni", True, None),
    ("_nosni_noalpn", True, []),
]

# The three aliases uQUIC defines point at the most common variant, so they are
# not expanded (they would duplicate an existing fingerprint).
QUIC_ALIASES = {"QUICFirefox_116", "QUICChrome_115", "QUICChrome_146"}


def alias_for(preset: str, suffix: str) -> str:
    base = preset
    if base.startswith("Hello"):
        base = base[len("Hello") :]
    return base.lower() + suffix


def tcp_profiles() -> list[dict]:
    presets = [p for p in engine.preset_list() if "Randomized" not in p]
    profiles = []
    seen = set()
    for preset in presets:
        for suffix, no_sni, alpn in VARIANTS:
            # Build the variant several times: only include it when the JA4 is
            # stable (extension shufflers with GREASE-dependent padding vary).
            raws = [engine.preset_raw_opts(preset, no_sni=no_sni, alpn=alpn) for _ in range(25)]
            raws = [r for r in raws if r]
            if not raws:
                continue
            ja4_values = {ja4_from_bytes(r)["ja4"] for r in raws}
            if len(ja4_values) != 1 or not next(iter(ja4_values)):
                continue
            j4 = ja4_from_bytes(raws[0])
            # JA3 is order-sensitive, so it is unstable for shufflers; record it
            # only when every build agrees, otherwise leave it blank.
            ja3_values = {ja3_from_bytes(r)["ja3"] for r in raws}
            j3 = {"ja3": next(iter(ja3_values)) if len(ja3_values) == 1 else ""}
            name = preset + suffix
            alias = alias_for(preset, suffix)
            key = (alias, j4["ja4"])
            if key in seen:
                continue
            seen.add(key)
            profiles.append(
                {
                    "name": name,
                    "alias": alias,
                    "preset": preset,
                    "no_sni": no_sni,
                    "alpn": alpn,
                    "ja4": j4["ja4"],
                    "ja4_a": j4["ja4_a"],
                    "ja3": j3["ja3"],
                }
            )
    return profiles


def quic_profiles() -> list[dict]:
    ids = [p for p in engine.quic_id_list() if p not in QUIC_ALIASES]
    profiles = []
    seen = set()
    for quic_id in ids:
        for suffix, no_sni, alpn in QUIC_VARIANTS:
            raws = [engine.quic_id_raw(quic_id, no_sni=no_sni, alpn=alpn) for _ in range(25)]
            raws = [r for r in raws if r]
            if not raws:
                continue
            ja4q_values = {ja4_from_bytes(r, transport="q")["ja4"] for r in raws}
            if len(ja4q_values) != 1 or not next(iter(ja4q_values)):
                continue
            j4q = ja4_from_bytes(raws[0], transport="q")
            name = quic_id + suffix
            alias = alias_for(quic_id, suffix)
            key = (alias, j4q["ja4"])
            if key in seen:
                continue
            seen.add(key)
            profiles.append(
                {
                    "name": name,
                    "alias": alias,
                    "quic_id": quic_id,
                    "no_sni": no_sni,
                    "alpn": alpn,
                    "ja4q": j4q["ja4"],
                    "ja4q_a": j4q["ja4_a"],
                }
            )
    return profiles


def main() -> int:
    tcp = tcp_profiles()
    quic = quic_profiles()
    profiles = tcp + quic
    catalog = {
        "generated_by": "tools/gen_catalog.py",
        "engine_version": engine.version(),
        "count": len(profiles),
        "tcp_count": len(tcp),
        "quic_count": len(quic),
        "profiles": profiles,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=1, sort_keys=True)
    distinct_ja4 = len({p["ja4"] for p in tcp if p.get("ja4")})
    distinct_ja4q = len({p["ja4q"] for p in quic if p.get("ja4q")})
    print(
        f"[ok] {len(profiles)} profiles "
        f"({len(tcp)} TCP / {distinct_ja4} distinct JA4, "
        f"{len(quic)} QUIC / {distinct_ja4q} distinct JA4q) -> {OUT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
