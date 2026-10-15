#!/usr/bin/env python3
"""Generate the common-JA4 profile catalog for freetls.

The catalog is built from uTLS's real, shipped ClientHello presets (Chrome,
Firefox, Safari, Edge, iOS, Android/OkHttp, 360, QQ, Go) plus realistic
variants that real clients exhibit: HTTP/1.1-only ALPN, no ALPN, and no SNI
(connecting by IP). Each entry is produced *offline* by the engine's
preset builder, and its JA4/JA3 are computed and stored for verification.

Network is never used.

Profiles are emitted only when their JA4 is stable across repeated builds;
JA3 (which is order-sensitive) is recorded only when it is stable too, and is
left blank for extension-shuffling presets.
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


def alias_for(preset: str, suffix: str) -> str:
    base = preset
    if base.startswith("Hello"):
        base = base[len("Hello"):]
    return base.lower() + suffix


def main() -> int:
    presets = [p for p in engine.preset_list() if "Randomized" not in p]
    profiles = []
    seen = set()
    for preset in presets:
        for suffix, no_sni, alpn in VARIANTS:
            # Build the variant several times: only include it when the JA4 is
            # stable (extension shufflers with GREASE-dependent padding vary).
            raws = [
                engine.preset_raw_opts(preset, no_sni=no_sni, alpn=alpn)
                for _ in range(25)
            ]
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
            profiles.append({
                "name": name,
                "alias": alias,
                "preset": preset,
                "no_sni": no_sni,
                "alpn": alpn,
                "ja4": j4["ja4"],
                "ja4_a": j4["ja4_a"],
                "ja3": j3["ja3"],
            })
    catalog = {
        "generated_by": "tools/gen_catalog.py",
        "engine_version": engine.version(),
        "count": len(profiles),
        "profiles": profiles,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=1, sort_keys=True)
    distinct = len({p["ja4"] for p in profiles})
    print(f"[ok] {len(profiles)} profiles ({distinct} distinct JA4) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
