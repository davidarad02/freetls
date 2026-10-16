"""Subprocess helper: print the JA4 of named presets from the loaded engine.

Used by the Route B byte-parity regression test. ``FREETLS_LIB`` selects which
engine to load (default or libcrypto-enabled). Each preset is sampled
``FREETLS_PRESET_SAMPLES`` times (default 1) so the caller can tell
deterministic presets (a single distinct JA4) from nondeterministic ones.

Usage: python tests/_route_b_presets.py <name> [<name> ...]
Output: JSON ``{name: [distinct ja4, ...]}`` (sorted).
"""

from __future__ import annotations

import json
import os
import sys

from freetls import engine, ja4_from_bytes


def main() -> int:
    samples = int(os.environ.get("FREETLS_PRESET_SAMPLES", "1"))
    out: dict[str, list[str]] = {}
    for name in sys.argv[1:]:
        seen: set[str] = set()
        for _ in range(samples):
            raw = engine.preset_raw(name)
            if not raw:
                break
            try:
                seen.add(ja4_from_bytes(raw)["ja4"])
            except Exception:  # noqa: BLE001
                break
        out[name] = sorted(seen)
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
