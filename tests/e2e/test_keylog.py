"""NSS key-log (SSLKEYLOGFILE) export."""

from __future__ import annotations

import freetls
from freetls import modes


def test_keylog_written(go_server, tmp_path):
    path = tmp_path / "keys.log"
    spec = modes.baseline_spec(server_name="localhost")
    spec.keylog = str(path)
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", go_server.port, server_hostname="localhost")
        assert s.ja4 is not None
    text = path.read_text()
    # NSS key-log lines, e.g. "CLIENT_HANDSHAKE_TRAFFIC_SECRET <rand> <secret>".
    assert "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in text or "CLIENT_RANDOM" in text


def test_keylog_not_written_by_default(go_server, tmp_path):
    path = tmp_path / "keys.log"
    spec = modes.baseline_spec(server_name="localhost")
    with freetls.TLSSession(spec) as s:
        s.connect("127.0.0.1", go_server.port, server_hostname="localhost")
    assert not path.exists()
