"""JA4T / JA4TS: TCP SYN and SYN-ACK fingerprint (report-only).

``JA4T = <window size>_<options>_<mss>_<window scale>`` computed from the
client's initial SYN; ``JA4TS`` is the same from the server's SYN-ACK. TCP
option kinds are joined with ``-`` (or ``00`` when there are none); MSS is
zero-padded to two digits; a window scale of 0 prints as ``00``, otherwise
unpadded. Follows the FoxIO JA4T definition.
"""

from __future__ import annotations

__all__ = ["ja4t", "ja4ts"]


def ja4t(
    window_size: int, options=(), mss: int | None = None, window_scale: int | None = None
) -> str:
    """Compute JA4T from SYN fields."""
    opts = "-".join(str(int(k)) for k in options) or "00"
    mss_s = f"{mss or 0:02d}"
    scale = window_scale or 0
    scale_s = "00" if scale == 0 else str(scale)
    return f"{int(window_size)}_{opts}_{mss_s}_{scale_s}"


def ja4ts(
    window_size: int, options=(), mss: int | None = None, window_scale: int | None = None
) -> str:
    """Compute JA4TS from SYN-ACK fields (same layout as JA4T)."""
    return ja4t(window_size, options, mss, window_scale)
