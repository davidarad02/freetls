"""Akamai HTTP/2 fingerprint.

The canonical form is
``SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS`` where SETTINGS is the
``id:value`` list in wire order, WINDOW_UPDATE is the connection-level increment
(``0`` if none), PRIORITY is the priority frame spec (``0`` if none) and
PSEUDO_HEADERS is the first letter of each pseudo-header in order
(``m,a,s,p`` for method, authority, scheme, path).
"""

from __future__ import annotations

__all__ = ["akamai_h2_fingerprint"]

_PSEUDO_LETTER = {"method": "m", "authority": "a", "scheme": "s", "path": "p"}


def akamai_h2_fingerprint(
    settings,
    window_update: int = 0,
    pseudo_order=None,
    priority: str = "0",
) -> str:
    """Return the Akamai HTTP/2 fingerprint for the given wire parameters.

    ``settings`` is an ordered iterable of ``(id, value)`` pairs (or dicts with
    ``id``/``value`` keys, as returned by the engine's ``sent_settings``).
    """
    parts = []
    for s in settings or []:
        if isinstance(s, dict):
            parts.append(f"{int(s['id'])}:{int(s['value'])}")
        else:
            parts.append(f"{int(s[0])}:{int(s[1])}")
    settings_str = ";".join(parts)
    order = list(pseudo_order) if pseudo_order else ["method", "scheme", "authority", "path"]
    pseudo_str = ",".join(_PSEUDO_LETTER.get(p, p[:1].lower()) for p in order)
    return f"{settings_str}|{int(window_update or 0)}|{priority}|{pseudo_str}"
