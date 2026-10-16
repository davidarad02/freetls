#!/usr/bin/env python3
"""Estimate the JA4 universe and birthday statistics for a freetls mode.

Given the mode "knobs" (safe/unsafe, cipher/extension counts, engine) and a fleet
size, this computes the theoretical space of distinct JA4 values and the
birthday statistics (n50, collision probability, expected distinct), and can
verify them empirically by sampling specs and hashing them.

JA4 = ``a_b_c`` where ``b`` (cipher hash) and ``c`` (extension hash) are each 12
hex chars, i.e. capped at 2**48. This tool models ``S = b_space * c_space``
(the two hashes are independent), matching the numbers reported for Route B.

Examples
--------
  # wide engine, safe random, 10k workers
  tools/ja4_universe.py --engine wide --mode safe_random --safe --workers 10000

  # unsafe partial_random with 40 extra ciphers, 50k workers
  tools/ja4_universe.py --mode partial_random --unsafe \
      --n-random-ciphers 40 --workers 50000

  # verify the theory by sampling 20k specs
  tools/ja4_universe.py --engine wide --mode true_random --safe --empirical 20000

  # machine-readable
  tools/ja4_universe.py --engine wide --mode safe_random --safe --json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from math import comb
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
SRC = ROOT / "src"

CAP = 1 << 48  # JA4_b / JA4_c are 12 hex chars


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--engine",
        choices=["auto", "default", "wide"],
        default="auto",
        help="engine to load (default: whatever FREETLS_LIB / the loader picks)",
    )
    p.add_argument("--lib", help="explicit engine .so path (overrides --engine)")
    p.add_argument(
        "--mode",
        choices=["baseline", "specific", "partial_random", "true_random", "safe_random"],
        default="safe_random",
    )
    sw = p.add_mutually_exclusive_group()
    sw.add_argument("--safe", dest="safe", action="store_true", default=None)
    sw.add_argument("--unsafe", dest="safe", action="store_false")
    p.add_argument("--workers", type=int, default=10000, help="fleet size (default 10000)")
    p.add_argument(
        "--base", type=int, default=None, help="fixed baseline cipher count (partial/safe_random)"
    )
    p.add_argument("--core", type=int, default=None, help="fixed core cipher count (true_random)")
    p.add_argument("--n-random-ciphers", type=int, default=None, dest="n_random_ciphers")
    p.add_argument("--n-ciphers", type=int, default=None, dest="n_ciphers")
    p.add_argument("--n-random-extensions", type=int, default=None, dest="n_random_extensions")
    p.add_argument("--n-extensions", type=int, default=None, dest="n_extensions")
    p.add_argument("--vers-min", type=lambda s: int(s, 0), default=0x0303, dest="vers_min")
    p.add_argument("--vers-max", type=lambda s: int(s, 0), default=0x0304, dest="vers_max")
    p.add_argument("--seed", type=int, default=0, help="base seed (empirical mode uses seed+i)")
    p.add_argument(
        "--empirical",
        type=int,
        default=0,
        metavar="N",
        help="sample N specs (seeds base..base+N-1) and measure distinct JA4 / collisions",
    )
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument(
        "-e",
        "--explain",
        dest="explain",
        action="store_true",
        default=False,
        help="print a plain-language explanation of the metrics",
    )
    p.add_argument("--list-pools", action="store_true", help="print pool sizes and exit")
    return p


def select_engine(args: argparse.Namespace) -> None:
    if args.lib:
        os.environ["FREETLS_LIB"] = args.lib
    elif args.engine in ("default", "wide"):
        name = "libfreetls_libcrypto.so" if args.engine == "wide" else "libfreetls.so"
        path = NATIVE / name
        if not path.exists():
            sys.exit(
                f"engine not found: {path}\n"
                "  build it with `make native` (wide) or `make native-go` (Go-only)."
            )
        os.environ["FREETLS_LIB"] = str(path)
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))


def resolve_safe(args: argparse.Namespace) -> bool:
    if args.mode == "safe_random":
        return True
    return bool(args.safe)


def cipher_space(
    mode: str, pool: int, safe: bool, args: argparse.Namespace
) -> tuple[int, int, int]:
    """Return (space, fixed_count, random_count)."""
    if mode == "baseline":
        return 1, pool, 0
    if mode == "specific":
        k = args.n_ciphers
        if k is None:
            return min(2**pool - 1, CAP), 0, pool
        k = max(0, min(k, pool))
        return min(comb(pool, k), CAP), 0, k

    if mode in ("partial_random", "safe_random"):
        base = args.base
        if base is None:
            from freetls import modes

            base = len(modes.DEFAULT_CIPHERS)
        n = args.n_random_ciphers
        if n is None:
            if safe:
                from freetls import modes

                n = modes._adaptive_random_count(max(0, pool - base))
            else:
                n = 10
        avail = max(0, pool - base)
        return min(comb(avail, min(n, avail)), CAP), base, n

    # true_random
    core = args.core if args.core is not None else 5
    total = args.n_ciphers
    if total is None:
        if safe:
            from freetls import modes

            total = core + modes._adaptive_random_count(max(0, pool - core))
        else:
            total = 60
    n = max(0, total - core)
    avail = max(0, pool - core)
    return min(comb(avail, min(n, avail)), CAP), core, n


def extension_space(
    mode: str, ext_pool: int, safe: bool, args: argparse.Namespace
) -> tuple[int, int | None]:
    """Return (space, random_count_or_None_for_random_subset)."""
    if mode == "baseline":
        return 1, 0
    if mode == "specific":
        k = args.n_extensions
        if k is None:
            return min(2**ext_pool - 1, CAP), None
        k = max(0, min(k, ext_pool))
        return min(comb(ext_pool, k), CAP), k

    n = args.n_random_extensions if mode in ("partial_random", "safe_random") else args.n_extensions
    if n is None:
        if safe:
            # safe default is a random subset of the free extensions: 0..ext_pool
            return min(2**ext_pool, CAP), None
        from freetls import modes

        n = modes._UNSAFE_RANDOM_EXT_COUNT
    n = max(0, min(n, ext_pool))
    return min(comb(ext_pool, n), CAP), n


def build_factory(args: argparse.Namespace, safe: bool) -> Callable[[int], Any]:
    from freetls import modes

    server_name = "example.com"
    kw: dict[str, Any] = {
        "server_name": server_name,
        "vers_min": args.vers_min,
        "vers_max": args.vers_max,
    }
    if args.mode == "baseline":
        return lambda seed: modes.baseline_spec(**kw)
    if args.mode == "safe_random":
        return lambda seed: modes.safe_random(
            seed=seed, n_ciphers=args.n_ciphers, n_extensions=args.n_extensions, **kw
        )
    if args.mode == "partial_random":
        return lambda seed: modes.partial_random(
            seed=seed,
            safe=safe,
            n_random_ciphers=args.n_random_ciphers,
            n_random_extensions=args.n_random_extensions,
            **kw,
        )
    if args.mode == "true_random":
        return lambda seed: modes.true_random(
            seed=seed, safe=safe, n_ciphers=args.n_ciphers, n_extensions=args.n_extensions, **kw
        )

    # specific: seeded random cipher subset (+ optional seeded extension subset)
    from freetls import engine

    pool = list(engine.supported_ciphers()) if safe else list(modes._CIPHER_POOL)
    k = args.n_ciphers if args.n_ciphers is not None else min(20, len(pool))

    def factory(seed: int) -> Any:
        rng = random.Random(seed)
        ciphers = rng.sample(pool, min(k, len(pool)))
        return modes.specific(ciphers=ciphers, **kw)

    return factory


# Counts below this are shown in full (with thousands separators); larger ones
# use scientific notation to stay readable.
SCI_THRESHOLD = 1e12


def fmt(n: float) -> str:
    """Plain digits below a trillion, scientific notation above."""
    if abs(n) < SCI_THRESHOLD:
        return f"{n:,.0f}"
    return f"{n:.3e}"


def main() -> int:
    args = build_parser().parse_args()
    select_engine(args)

    import freetls  # noqa: F401  (ensures the engine loads / auto-builds)
    from freetls import engine, modes

    safe = resolve_safe(args)
    if safe:
        pool = len(modes._supported_cipher_pool())
        pool_kind = "backed"
        ext_pool = modes._free_safe_ext_count()
        ext_kind = "free safe whitelist"
    else:
        pool = len(modes._CIPHER_POOL)
        pool_kind = "assigned IANA"
        ext_pool = len(modes.SAFE_PADDING_EXT_IDS)
        ext_kind = "assigned padding"

    if args.list_pools:
        print(
            f"engine: {engine.abi_version()} (ABI), {len(engine.supported_ciphers())} backed ciphers"
        )
        print(
            f"unsafe cipher pool: {len(modes._CIPHER_POOL)}   safe cipher pool: {len(modes._supported_cipher_pool())}"
        )
        print(
            f"unsafe extension pool: {len(modes.SAFE_PADDING_EXT_IDS)}   safe free extensions: {modes._free_safe_ext_count()}"
        )
        return 0

    b_space, fixed, n_ciphers = cipher_space(args.mode, pool, safe, args)
    c_space, n_ext = extension_space(args.mode, ext_pool, safe, args)
    S = b_space * c_space
    n = args.workers
    n50 = 1.1774 * math.sqrt(S) if S else 0.0
    # expm1 keeps precision when n/S is tiny (huge S).
    p_collision = -math.expm1(-(n * (n - 1)) / (2 * S)) if S else 1.0
    expected_distinct = S * -math.expm1(-n / S) if S else 0.0

    result: dict[str, Any] = {
        "engine": args.engine if not args.lib else args.lib,
        "mode": args.mode,
        "safe": safe,
        "cipher_pool": pool,
        "cipher_pool_kind": pool_kind,
        "fixed_ciphers": fixed,
        "random_ciphers": n_ciphers,
        "offered_ciphers": fixed + n_ciphers,
        "extension_pool": ext_pool,
        "extension_pool_kind": ext_kind,
        "random_extensions": n_ext,
        "ja4_b_space": b_space,
        "ja4_c_space": c_space,
        "total_space": S,
        "workers": n,
        "n50": n50,
        "p_collision": p_collision,
        "p_collision_percent": p_collision * 100,
        "expected_distinct": expected_distinct,
    }

    if args.empirical:
        from freetls.fingerprint import ja4_from_spec

        factory = build_factory(args, safe)
        seen: dict[str, int] = {}
        collisions = 0
        for i in range(args.empirical):
            spec = factory(args.seed + i)
            j = ja4_from_spec(spec)["ja4"]
            if j in seen:
                collisions += 1
            else:
                seen[j] = i
        result["empirical_samples"] = args.empirical
        result["empirical_distinct"] = len(seen)
        result["empirical_collisions"] = collisions

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    if args.mode == "baseline":
        b_desc = "1 (fixed hello)"
    elif args.mode == "specific":
        b_desc = f"C({pool},{n_ciphers})" if args.n_ciphers is not None else f"2^{pool}-1"
    else:
        b_desc = f"C({pool - fixed},{n_ciphers})"

    if args.mode == "baseline":
        c_desc = "1 (fixed hello)"
    elif args.mode == "specific":
        c_desc = f"C({ext_pool},{n_ext})" if n_ext is not None else f"2^{ext_pool}-1"
    elif safe:
        c_desc = f"2^{ext_pool} (any subset of the free whitelisted extensions)"
    else:
        c_desc = f"C({ext_pool},{n_ext})"

    pct = p_collision * 100
    pct_str = "0%" if pct == 0 else f"{pct:.4g}%"
    ext_shown = "random subset" if n_ext is None else str(n_ext)

    print(
        f"engine      : ABI {engine.abi_version()}, {len(engine.supported_ciphers())} backed ciphers"
    )
    print(f"mode        : {args.mode}  ({'safe' if safe else 'unsafe'} mode)")
    print(
        f"ciphers     : pool {pool} ({pool_kind}); {fixed} fixed + {n_ciphers} random "
        f"= {fixed + n_ciphers} offered"
    )
    print(f"extensions  : pool {ext_pool} ({ext_kind}); {ext_shown}")
    print(f"JA4_b space : {fmt(b_space):>24}   = {b_desc}")
    print(f"JA4_c space : {fmt(c_space):>24}   = {c_desc}")
    print(f"total S     : {fmt(S):>24}   = JA4_b x JA4_c distinct JA4 values")
    print(f"workers n   : {n:>24,}")
    print(f"n50         : {fmt(n50):>24}   = fleet size for a ~50% chance of a collision")
    print(f"P(collision): {pct_str:>24}   = chance >= 2 of {n:,} workers share a JA4")
    print(f"E[distinct] : {fmt(expected_distinct):>24}   = expected distinct JA4s among workers")
    if args.empirical:
        print(
            f"empirical   : {result['empirical_distinct']} distinct, "
            f"{result['empirical_collisions']} collisions over {args.empirical} sampled specs"
        )

    if args.explain:
        print(
            "\n"
            "How to read this\n"
            "----------------\n"
            "JA4 = a_b_c.  'a' encodes the TLS version, SNI presence, cipher count,\n"
            "extension count and ALPN.  'b' is a 12-hex hash of the (sorted) cipher\n"
            "list; 'c' is a 12-hex hash of the extension list.  'b' and 'c' each top\n"
            "out at 2^48 values, so the largest possible JA4 space is 2^96.\n"
            "\n"
            "- JA4_b space : distinct cipher sets this mode can emit (capped at 2^48).\n"
            "- JA4_c space : distinct extension sets it can emit (capped at 2^48).\n"
            "  In safe mode this is 2^(free whitelisted extensions); the free set is\n"
            "  small, so it is 32 - it does not depend on the cipher pool or engine.\n"
            "- total S     : b_space x c_space = the number of distinct JA4s available.\n"
            "  Bigger S means fewer collisions.\n"
            "- n50         : the fleet size at which a collision is as likely as not\n"
            "  (n50 = 1.1774 * sqrt(S)).\n"
            "- P(collision): probability that at least two of your N workers share a\n"
            "  JA4 (1 - exp(-N(N-1)/(2S))), shown as a percentage.\n"
            "- E[distinct] : expected number of distinct JA4s among the N workers.\n"
            "\n"
            "Rule of thumb: keep P(collision) below ~1%; if it is higher, increase the\n"
            "cipher variety (wide engine, more random ciphers, or 'specific' mode) -\n"
            "the cipher hash is the dominant lever in safe mode."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
