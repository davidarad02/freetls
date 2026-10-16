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


def test_h2_forwards_request_headers(go_server):
    """The transport must forward request headers (regression: Mapping handling)."""
    import requests

    from freetls import JA4Adapter

    spec = modes.baseline_spec(server_name="localhost", alpn=["h2", "http/1.1"])
    adapter = JA4Adapter(spec=spec)
    session = requests.Session()
    session.mount("https://", adapter)
    try:
        r = session.get(
            f"https://127.0.0.1:{go_server.port}/headers",
            headers={"X-Test": "abc", "X-Two": "def"},
        )
        assert r.status_code == 200
        assert r.headers.get("x-echo-x-test") == "abc"
        assert r.headers.get("x-echo-x-two") == "def"
    finally:
        session.close()


def test_fingerprint_survives_large_padded_hello(go_server):
    """A ClientHello spanning multiple TLS records still yields JA4/JA3."""
    spec = modes.baseline_spec(server_name="localhost", alpn=["h2"])
    spec.extensions.append(freetls.Extension.padding(20000))
    with _connect(go_server.port, spec) as s:
        assert s.ja4 is not None and s.ja4.startswith("t13")
        assert s.ja3 is not None


def test_h2_multiple_requests_one_connection(go_server):
    """A single H2 connection serves many requests (no preface re-send)."""
    with _connect(go_server.port, _h2_spec()) as s:
        r1 = s.h2_request("/")
        r2 = s.h2_request("/")
        r3 = s.h2_request("/headers", headers=[["x-test", "abc"]])
    assert r1["status"] == 200
    assert r2["status"] == 200
    assert r3["status"] == 200
    assert {k.lower(): v for k, v in r3["headers"]}.get("x-echo-x-test") == "abc"


def test_h2_large_body_is_split(go_server):
    """A body larger than MAX_FRAME_SIZE is split and delivered (flow control)."""
    with _connect(go_server.port, _h2_spec()) as s:
        r = s.h2_request("/echo-body", method="POST", body=b"x" * 200_000)
    assert r["status"] == 200
    assert r["body"] == b"len=200000"


def test_h2_settings_reported(go_server):
    with _connect(go_server.port, _h2_spec()) as s:
        r = s.h2_request("/")
    assert [(x["id"], x["value"]) for x in r["sent_settings"]] == [
        (1, 65536),
        (2, 0),
        (4, 6291456),
        (6, 262144),
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
