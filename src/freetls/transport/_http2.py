"""Shared HTTP/2 execution over a :class:`~freetls.TLSSession`.

The Go engine speaks HTTP/2; this module turns a request into the engine's
``h2_request`` call and adapts the result for the different HTTP clients.
"""

from __future__ import annotations

# Hop-by-hop / HTTP/1.1-only headers that must not be sent in HTTP/2.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "host",  # carried by :authority
    "proxy-authenticate",
    "proxy-authorization",
}


def negotiated_h2(session) -> bool:
    """True when the connection negotiated HTTP/2 via ALPN."""
    try:
        return session.selected_alpn_protocol() == "h2"
    except Exception:  # noqa: BLE001
        return False


def execute(
    session,
    method: str,
    path: str,
    headers=None,
    body: bytes = b"",
):
    """Run an HTTP/2 request; return the engine response dict."""
    if isinstance(headers, dict):
        pairs = list(headers.items())
    else:
        pairs = [
            (item[0], item[1])
            for item in (headers or [])
            if isinstance(item, (list, tuple)) and len(item) == 2
        ]
    req_headers = [[str(k), str(v)] for k, v in pairs if str(k).lower() not in _HOP_BY_HOP]
    if isinstance(body, str):
        body = body.encode()
    resp = session.h2_request(path, method=method, headers=req_headers, body=body or b"")
    if resp.get("error"):
        raise RuntimeError(f"HTTP/2 request failed: {resp['error']}")
    return resp


def header_tuples(resp: dict) -> list:
    return [(str(k), str(v)) for k, v in resp.get("headers", [])]


def status_of(resp: dict) -> int:
    return int(resp.get("status", 0))
