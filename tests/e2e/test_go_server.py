"""Tests against a local Go net/http TLS server (independent stack + HTTP/2)."""

from __future__ import annotations

import freetls
from freetls import modes


def _get(port, alpn):
    spec = modes.baseline_spec(server_name="localhost", alpn=alpn)
    s = freetls.TLSSession(spec)
    s.connect("127.0.0.1", port, server_hostname="localhost")
    return s


def test_go_server_http11(go_server):
    with _get(go_server.port, ["http/1.1"]) as s:
        assert s.state.version == "TLS1.3"
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        data = s.recv(512)
    assert b"HTTP/1.1 200" in data
    assert b"hello-go" in data


def test_go_server_negotiates_h2(go_server):
    with _get(go_server.port, ["h2", "http/1.1"]) as s:
        assert s.selected_alpn_protocol() == "h2"
        assert s.ja4.split("_")[0].endswith("h2")


def test_go_server_via_requests(go_server):
    import warnings

    requests = __import__("requests")
    from freetls.transport import JA4Adapter

    adapter = JA4Adapter(spec=modes.baseline_spec(server_name="localhost", alpn=["http/1.1"]))
    session = requests.Session()
    session.mount("https://", adapter)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = session.get(f"https://127.0.0.1:{go_server.port}/", verify=False)
    assert r.status_code == 200
    assert "hello-go" in r.text
