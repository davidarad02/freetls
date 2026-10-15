"""Content decoding helpers shared by the transports."""

from __future__ import annotations

import gzip
import zlib
from collections.abc import Iterable


def _split_encodings(value: str) -> list[str]:
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def _decompress_one(enc: str, data: bytes) -> bytes | None:
    """Decode a single ``Content-Encoding``; None if the codec is unavailable."""
    if enc in ("gzip", "x-gzip"):
        try:
            return gzip.decompress(data)
        except OSError:
            return None
    if enc == "deflate":
        try:
            return zlib.decompress(data)
        except zlib.error:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                return None
    if enc == "br":
        try:
            import brotli  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            return brotli.decompress(data)
        except Exception:  # noqa: BLE001 - brotli.error
            return None
    if enc == "zstd":
        try:
            import zstandard  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            return zstandard.ZstdDecompressor().decompress(data)
        except Exception:  # noqa: BLE001 - zstandard.ZstdError
            return None
    return None


def decode_content(data: bytes, headers: list) -> tuple[bytes, list]:
    """Decode ``Content-Encoding`` that the host client wouldn't for us.

    Supports gzip, deflate, brotli (``br``) and zstd when the matching optional
    dependency is installed; unknown/unavailable codecs are left untouched.
    Encodings are applied in reverse order per HTTP semantics.
    """
    enc = ""
    for k, v in headers:
        if k.lower() == "content-encoding":
            enc = v.lower()
    if not enc:
        return data, headers

    encodings: Iterable[str] = _split_encodings(enc)
    if not encodings:
        return data, headers

    decoded = data
    applied = False
    for one in reversed(list(encodings)):
        out = _decompress_one(one, decoded)
        if out is None:
            return data, headers
        decoded = out
        applied = True
    if not applied:
        return data, headers
    headers = [
        (k, v) for (k, v) in headers if k.lower() not in ("content-encoding", "content-length")
    ]
    headers.append(("content-length", str(len(decoded))))
    return decoded, headers
