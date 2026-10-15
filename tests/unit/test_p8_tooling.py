"""P8 unit tests: profile tooling, chlo_json round-trip, retry policy."""

from __future__ import annotations

import json

import pytest

from freetls import profiles
from freetls.fingerprint import chlo_json_from_raw, ja4_from_bytes
from freetls.transport.retry import Retry


def test_find_ja4_matches_prefix_and_full():
    first = profiles.list_profiles()[0]
    assert first.ja4
    found = profiles.find_ja4(first.ja4)
    assert any(p.ja4 == first.ja4 for p in found)
    prefix = first.ja4[:10]
    assert profiles.find_ja4(prefix)
    assert profiles.find_ja4("") == []
    assert profiles.find_ja4("zzzz-not-a-ja4") == []


def test_search_by_name():
    matches = profiles.search("chrome", limit=5)
    assert matches
    assert all("chrome" in p.name.lower() or "chrome" in p.alias.lower() for p in matches)


def test_export_and_save_roundtrip(tmp_path):
    data = profiles.export()
    assert isinstance(data, list) and data
    assert set(data[0]) >= {"name", "alias", "ja4"}

    path = tmp_path / "profiles.json"
    count = profiles.save_file(str(path))
    assert count == len(data)
    payload = json.loads(path.read_text())
    assert payload["profiles"][0]["name"] == data[0]["name"]

    n = profiles.load_file(str(path))
    assert n == count


def test_h2_bundle_applies_controls():
    name = profiles.names()[0]
    spec = profiles.h2_bundle(
        name,
        settings=[[1, 65536], [4, 131072]],
        window_update=15663105,
        pseudo_header_order=["m", "a", "s", "p"],
        server_name="example.com",
    )
    assert spec.h2_settings == [[1, 65536], [4, 131072]]
    assert spec.h2_window_update == 15663105
    assert spec.h2_pseudo_header_order == ["m", "a", "s", "p"]


def test_chlo_json_from_raw_roundtrip():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from _build import CHLO_JSON

    from freetls import engine

    raw = engine.chlo_raw(CHLO_JSON)
    converted = chlo_json_from_raw(raw)
    raw2 = engine.chlo_raw(converted)
    assert ja4_from_bytes(raw)["ja4"] == ja4_from_bytes(raw2)["ja4"]


def test_retry_runs_until_success():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError("boom")
        return "ok"

    retry = Retry(total=5, backoff=0.0, jitter=False)
    sleeps = []
    assert retry.run(flaky, sleep=sleeps.append) == "ok"
    assert calls["n"] == 3
    assert sleeps == [0.0, 0.0]


def test_retry_status_forcelist():
    class Resp:
        def __init__(self, status):
            self.status_code = status

    seq = iter([Resp(503), Resp(200)])

    def call():
        return next(seq)

    retry = Retry(total=3, backoff=0.0, jitter=False)
    result = retry.run(call, sleep=lambda _s: None, on_status=True)
    assert result.status_code == 200
    assert retry.should_retry_status(503)
    assert not retry.should_retry_status(404)


def test_retry_raises_after_exhaustion():
    retry = Retry(total=2, backoff=0.0, jitter=False)
    with pytest.raises(OSError):
        retry.run(lambda: (_ for _ in ()).throw(OSError("nope")), sleep=lambda _s: None)
