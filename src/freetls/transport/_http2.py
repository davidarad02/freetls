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
    return negotiated_protocol(session) == "h2"


def negotiated_protocol(session) -> str | None:
    """Return ``"h3"``, ``"h2"`` or ``None`` for the session's ALPN."""
    try:
        alpn = session.selected_alpn_protocol()
    except Exception:  # noqa: BLE001
        return None
    return alpn if alpn in ("h3", "h2") else None


def _header_pairs(headers) -> list:
    """Normalise headers to ``[(name, value), ...]``.

    Accepts a mapping (``dict``, ``CaseInsensitiveDict``, ``HTTPHeaderDict``,
    ``httpx.Headers``, ...) or an iterable of 2-tuples, preserving duplicates
    and order for the iterable case.
    """
    if headers is None:
        return []
    items = getattr(headers, "items", None)
    if items is not None:
        return [(str(k), str(v)) for k, v in items()]
    return [
        (str(item[0]), str(item[1]))
        for item in headers
        if isinstance(item, (list, tuple)) and len(item) == 2
    ]


def execute(
    session,
    method: str,
    path: str,
    headers=None,
    body: bytes = b"",
):
    """Run an HTTP/2 request; return the engine response dict."""
    pairs = _header_pairs(headers)
    req_headers = [[k, v] for k, v in pairs if k.lower() not in _HOP_BY_HOP]
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
