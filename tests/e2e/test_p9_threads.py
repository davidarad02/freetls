"""P9 e2e: the engine is safe to drive from multiple threads."""

from __future__ import annotations

import gc
from concurrent.futures import ThreadPoolExecutor

from freetls import engine, modes
from freetls.session import TLSSession


def test_concurrent_handshakes_are_isolated_and_leak_free(app_server):
    spec = modes.baseline_spec(server_name="localhost")
    baseline = engine.active_sessions()

    def one(_i: int) -> str | None:
        s = TLSSession(spec)
        s.connect("127.0.0.1", app_server.port, server_hostname="localhost")
        try:
            return s.ja4
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(one, range(12)))

    assert all(r and r.startswith("t13") for r in results)
    assert len(set(results)) == 1
    assert engine.active_sessions() == baseline


def test_unclosed_session_is_gc_finalized(app_server):
    spec = modes.baseline_spec(server_name="localhost")
    baseline = engine.active_sessions()
    s = TLSSession(spec)
    s.connect("127.0.0.1", app_server.port, server_hostname="localhost")
    assert engine.active_sessions() == baseline + 1
    del s
    gc.collect()
    assert engine.active_sessions() <= baseline
