"""Unit tests for P6 content decoding and the SSE helper."""

from __future__ import annotations

import gzip
import zlib

import pytest

from freetls.sse import SSEEvent, iter_sse
from freetls.transport._content import decode_content


def _headers(enc: str):
    return [("Content-Encoding", enc), ("Content-Length", "0")]


def test_decode_gzip():
    plain = b"hello " * 50
    out, headers = decode_content(gzip.compress(plain), _headers("gzip"))
    assert out == plain
    assert headers == [("content-length", str(len(plain)))]


def test_decode_deflate():
    plain = b"deflate " * 50
    out, _ = decode_content(zlib.compress(plain), _headers("deflate"))
    assert out == plain


def test_decode_brotli_and_zstd():
    brotli = pytest.importorskip("brotli")
    zstandard = pytest.importorskip("zstandard")
    plain = b"content " * 50
    out_br, _ = decode_content(brotli.compress(plain), _headers("br"))
    assert out_br == plain
    out_zs, _ = decode_content(zstandard.ZstdCompressor().compress(plain), _headers("zstd"))
    assert out_zs == plain


def test_decode_multiple_encodings_reversed():
    brotli = pytest.importorskip("brotli")
    plain = b"stacked " * 30
    stacked = brotli.compress(gzip.compress(plain))
    out, _ = decode_content(stacked, _headers("gzip, br"))
    assert out == plain


def test_decode_unknown_encoding_is_untouched():
    data = b"raw-bytes"
    out, headers = decode_content(data, _headers("weird"))
    assert out == data
    assert headers == _headers("weird")


def test_decode_no_encoding():
    data = b"plain"
    headers = [("Content-Type", "text/plain")]
    assert decode_content(data, headers) == (data, headers)


def test_sse_parses_events_comments_and_multiline():
    stream = (
        b'event: ping\ndata: {"n": 1}\n\n'
        b"data: hello\n\n"
        b": a comment\n\n"
        b"id: 7\nretry: 1500\ndata: line1\ndata: line2\n\n"
    )
    events = list(iter_sse([stream]))
    assert [e.event for e in events] == ["ping", "", ""]
    assert events[0].data == '{"n": 1}'
    assert events[1].data == "hello"
    assert events[2].data == "line1\nline2"
    assert events[2].id == "7"
    assert events[2].retry == 1500


def test_sse_handles_split_chunks():
    chunks = [b"data: ab", b"c\n", b"\n", b"data: x\n\ndata: y\n\n"]
    events = list(iter_sse(chunks))
    assert [e.data for e in events] == ["abc", "x", "y"]


def test_sse_event_comment_only():
    assert SSEEvent().is_comment_only
    assert not SSEEvent(data="x").is_comment_only
