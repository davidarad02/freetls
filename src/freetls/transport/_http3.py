"""Shared HTTP/3 execution over a :class:`~freetls.QUICSession`.

The Go engine speaks HTTP/3 (uQUIC's ``http3`` package); this module turns a
request into the engine's ``h3_request`` call and adapts the result for the
different HTTP clients, mirroring :mod:`freetls.transport._http2`.
"""

from __future__ import annotations

from ._http2 import _HOP_BY_HOP, header_tuples, status_of

__all__ = ["negotiated_h3", "negotiated_protocol", "execute", "header_tuples", "status_of"]


def negotiated_h3(session) -> bool:
    """True when the connection negotiated HTTP/3 via ALPN."""
    try:
        return session.selected_alpn_protocol() == "h3"
    except Exception:  # noqa: BLE001
        return False


def negotiated_protocol(session) -> str | None:
    """Return ``"h3"``, ``"h2"`` or ``None`` for the session's ALPN."""
    from ._http2 import negotiated_protocol as _np

    return _np(session)


def execute(
    session,
    method: str,
    path: str,
    headers=None,
    body: bytes = b"",
):
    """Run an HTTP/3 request; return the engine response dict."""
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
    resp = session.request(path, method=method, headers=req_headers, body=body or b"")
    if resp.get("error"):
        raise RuntimeError(f"HTTP/3 request failed: {resp['error']}")
    return resp
