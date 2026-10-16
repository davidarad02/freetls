"""Subprocess helper: print the JA4 of named presets from the loaded engine.

Used by the Route B byte-parity regression test. ``FREETLS_LIB`` selects which
engine to load (default or libcrypto-enabled). Presets whose JA4 is stable are
compared across the two engines to prove the offered ciphers/extensions are
unchanged.

Usage: python tests/_route_b_presets.py <name> [<name> ...]
"""

from __future__ import annotations

import json
import sys

from freetls import engine, ja4_from_bytes


def main() -> int:
    out: dict[str, str | None] = {}
    for name in sys.argv[1:]:
        raw = engine.preset_raw(name)
        if not raw:
            out[name] = None
            continue
        try:
            out[name] = ja4_from_bytes(raw)["ja4"]
        except Exception:  # noqa: BLE001
            out[name] = None
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
