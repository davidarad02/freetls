"""P9 unit tests: C-ABI version, panic-safety and parser fuzzing."""

from __future__ import annotations

import random

import pytest

from freetls import engine
from freetls.errors import EngineError, SpecError
from freetls.fingerprint import ja4_from_bytes, parse_client_hello
from freetls.fingerprint.ja4h import ja4h


def test_abi_version_matches_binding():
    assert engine.abi_version() == 1
    assert engine.version().startswith("freetls/")


def test_malformed_chlo_json_raises_not_panics():
    for bad in ['{"cipher_suites": ["NOPE"]}', "{", "[1,2,3]", '{"extensions":[{"name":"nope"}]}']:
        with pytest.raises((SpecError, EngineError)):
            engine.chlo_raw(bad)


def test_malformed_spec_json_raises_not_panics():
    with pytest.raises((SpecError, EngineError)):
        engine.EngineSession({"ciphers": "not-a-list", "extensions": []})


def test_parser_fuzz_never_crashes():
    rng = random.Random(1234)
    for _ in range(1000):
        n = rng.randrange(0, 96)
        blob = bytes(rng.randrange(256) for _ in range(n))
        try:
            ch = parse_client_hello(blob)
            ja4_from_bytes(blob)
            assert isinstance(ch.ext_types, list)
        except Exception as exc:  # noqa: BLE001 - any parse error is acceptable
            assert exc.__class__.__name__ in {
                "ParseError",
                "ValueError",
                "IndexError",
                "UnicodeDecodeError",
                "struct.error",
                "KeyError",
                "TypeError",
            }, f"unexpected {type(exc).__name__}: {exc}"


def test_ja4h_handles_odd_inputs():
    result = ja4h("GET", [], version=None)
    assert result["ja4h"].startswith("ge11nn00")
    result = ja4h("WEIRD", [(":path", "/"), ("X", "1")], cookies=["", "a=b=c"])
    assert result["ja4h"].startswith("we")


def test_offline_ja4_counts_new_extension_kinds():
    from freetls import modes
    from freetls.fingerprint import ja4_from_spec
    from freetls.model import Extension

    base = modes.baseline_spec(server_name="example.com")
    before = int(ja4_from_spec(base)["ja4"].split("_")[0][6:8])
    base.extensions.append(Extension.record_size_limit(16385))
    base.extensions.append(Extension.pre_shared_key())
    after = int(ja4_from_spec(base)["ja4"].split("_")[0][6:8])
    assert after - before == 2
