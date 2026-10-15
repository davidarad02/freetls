"""Large-range JA4 distinctness (offline, from specs)."""
from __future__ import annotations

import re

from freetls import modes
from freetls.fingerprint import ja4_from_spec

JA4_RE = re.compile(r"^t1[0-3][di]\d{4}[0-9a-zA-Z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")

N = 10000


def test_wide_range_distinctness():
    seen = set()
    for i in range(N):
        spec = modes.true_random(
            server_name="example.com",
            seed=i,
            n_ciphers=40 + (i % 60),
            n_extensions=10 + (i % 30),
        )
        ja4 = ja4_from_spec(spec)["ja4"]
        assert JA4_RE.match(ja4), ja4
        seen.add(ja4)
    # With 2^48 per-part space, 10k samples should be essentially collision-free.
    assert len(seen) >= int(N * 0.99)


def test_specific_specs_have_expected_counts():
    for n in (0, 1, 5, 99, 100):
        spec = modes.specific(ciphers=list(range(0x1301, 0x1301 + n)))
        out = ja4_from_spec(spec)
        expected = min(n, 99)
        assert out["ja4_a"][4:6] == f"{expected:02d}"
