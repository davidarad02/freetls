"""HTTP/2 (Go-side) fingerprint-control tests against a local Go h2 server."""
from __future__ import annotations

import freetls
from freetls import modes


def _connect(port, spec):
    s = freetls.TLSSession(spec)
    s.connect("127.0.0.1", port, server_hostname="localhost")
    return s


def _h2_spec():
    spec = modes.baseline_spec(server_name="localhost", alpn=["h2"])
    spec.h2_settings = [[1, 65536], [2, 0], [4, 6291456], [6, 262144]]
    spec.h2_window_update = 15663105
    spec.h2_pseudo_header_order = ["method", "authority", "scheme", "path"]
    return spec


def test_h2_basic_request(go_server):
    with _connect(go_server.port, _h2_spec()) as s:
        assert s.selected_alpn_protocol() == "h2"
        r = s.h2_request("/", headers=[["user-agent", "freetls"], ["accept", "*/*"]])
    assert r["status"] == 200
    assert b"hello-go" in r["body"]
    assert b"HTTP/2.0" in r["body"]


def test_h2_settings_reported(go_server):
    with _connect(go_server.port, _h2_spec()) as s:
        r = s.h2_request("/")
    assert [(x["id"], x["value"]) for x in r["sent_settings"]] == [
        (1, 65536), (2, 0), (4, 6291456), (6, 262144)
    ]
    assert r["sent_window_update"] == 15663105
    assert r["sent_pseudo_header_order"] == ["method", "authority", "scheme", "path"]


def test_h2_default_settings_when_unset(go_server):
    spec = modes.baseline_spec(server_name="localhost", alpn=["h2"])
    with _connect(go_server.port, spec) as s:
        r = s.h2_request("/")
    # Chrome-like defaults are used.
    assert len(r["sent_settings"]) == 4
    assert r["sent_pseudo_header_order"] == ["method", "scheme", "authority", "path"]


def test_h2_custom_pseudo_header_order(go_server):
    spec = _h2_spec()
    spec.h2_pseudo_header_order = ["method", "path", "scheme", "authority"]
    with _connect(go_server.port, spec) as s:
        r = s.h2_request("/")
    assert r["status"] == 200
    assert r["sent_pseudo_header_order"] == ["method", "path", "scheme", "authority"]


def test_h2_post_body(go_server):
    with _connect(go_server.port, _h2_spec()) as s:
        r = s.h2_request("/", method="POST", body=b"hello", headers=[["content-length", "5"]])
    assert r["status"] == 200


def test_h2_request_headers_echoed(go_server):
    with _connect(go_server.port, _h2_spec()) as s:
        r = s.h2_request("/headers", headers=[["x-test", "abc"]])
    names = {k.lower(): v for k, v in r["headers"]}
    assert names.get("x-echo-X-Test".lower()) == "abc" or any(
        k.lower() == "x-echo-x-test" and v == "abc" for k, v in r["headers"]
    )
