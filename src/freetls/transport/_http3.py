"""Shared HTTP/3 execution over a :class:`~freetls.QUICSession`.

The Go engine speaks HTTP/3 (uQUIC's ``http3`` package); this module turns a
request into the engine's ``h3_request`` call and adapts the result for the
different HTTP clients, mirroring :mod:`freetls.transport._http2`.
"""

from __future__ import annotations

from ._http2 import _HOP_BY_HOP, _header_pairs, header_tuples, status_of

__all__ = ["execute", "header_tuples", "status_of"]


def execute(
    session,
    method: str,
    path: str,
    headers=None,
    body: bytes = b"",
):
    """Run an HTTP/3 request; return the engine response dict."""
    req_headers = [[k, v] for k, v in _header_pairs(headers) if k.lower() not in _HOP_BY_HOP]
    if isinstance(body, str):
        body = body.encode()
    resp = session.request(path, method=method, headers=req_headers, body=body or b"")
    if resp.get("error"):
        raise RuntimeError(f"HTTP/3 request failed: {resp['error']}")
    return resp
