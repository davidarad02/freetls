"""End-to-end: a JSON-defined (custom) preset drives a real handshake."""
from __future__ import annotations

import _build as B
from freetls import FingerprintSpec, engine, profiles, TLSSession


def test_chlo_json_handshake(tls_server_13):
    spec = FingerprintSpec(chlo_json=B.CHLO_JSON, server_name="localhost", verify=False)
    with TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        # The live fingerprint matches the offline build of the same JSON.
        assert s.ja4 == engine_chlo_ja4()
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        assert b"HTTP/1.0 200" in s.recv(256)


def test_registered_profile_handshakes(tls_server_13):
    profiles.add_profile("e2e_json", chlo_json=B.CHLO_JSON)
    spec = profiles.get("e2e_json").spec(server_name="localhost")
    with TLSSession(spec) as s:
        s.connect("127.0.0.1", tls_server_13.port, server_hostname="localhost")
        assert s.ja4 == profiles.get("e2e_json").ja4


def engine_chlo_ja4() -> str:
    from freetls.fingerprint import ja4_from_bytes

    return ja4_from_bytes(engine.chlo_raw(B.CHLO_JSON))["ja4"]
