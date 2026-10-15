"""JA4L / JA4LS: TCP latency and TTL fingerprint (report-only).

Given the three TCP handshake timestamps ``t_a`` (client SYN), ``t_b`` (server
SYN-ACK) and ``t_c`` (client ACK) plus the observed TTLs, JA4L reports the
client and server latency (in half the timestamp unit, matching FoxIO) tagged
with the corresponding TTL:

``JA4L_C = <(t_c - t_b)/2>_<client TTL>`` and
``JA4L_S = <(t_b - t_a)/2>_<server TTL>``.
"""

from __future__ import annotations

__all__ = ["ja4l", "ja4l_c", "ja4l_s"]


def _half_diff(later: int, earlier: int) -> int:
    diff = int(later) - int(earlier)
    return diff // 2 if diff >= 0 else 0


def ja4l_c(t_b: int, t_c: int, client_ttl: int = 0) -> str:
    """Client latency component (``t_c`` ACK, ``t_b`` SYN-ACK)."""
    return f"{_half_diff(t_c, t_b)}_{int(client_ttl)}"


def ja4l_s(t_a: int, t_b: int, server_ttl: int = 0) -> str:
    """Server latency component (``t_b`` SYN-ACK, ``t_a`` SYN)."""
    return f"{_half_diff(t_b, t_a)}_{int(server_ttl)}"


def ja4l(t_a: int, t_b: int, t_c: int, client_ttl: int = 0, server_ttl: int = 0) -> dict:
    """Return both JA4L components as a dict (``ja4l_c`` / ``ja4l_s``)."""
    return {
        "ja4l_c": ja4l_c(t_b, t_c, client_ttl),
        "ja4l_s": ja4l_s(t_a, t_b, server_ttl),
    }
