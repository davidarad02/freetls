"""Header normalisation for the H2/H3 transports.

Regression: requests/urllib3 pass ``Mapping`` objects (``CaseInsensitiveDict``,
``HTTPHeaderDict``) that are not ``dict``; the transport must still forward them.
"""

from __future__ import annotations

from freetls.transport._http2 import _header_pairs


def test_header_pairs_accepts_dict():
    assert _header_pairs({"A": "1"}) == [("A", "1")]


def test_header_pairs_accepts_requests_case_insensitive_dict():
    from requests.structures import CaseInsensitiveDict

    assert _header_pairs(CaseInsensitiveDict({"X-Test": "abc"})) == [("X-Test", "abc")]


def test_header_pairs_accepts_urllib3_httpheaderdict():
    from urllib3._collections import HTTPHeaderDict

    d = HTTPHeaderDict()
    d.add("X-Multi", "1")
    d.add("X-Multi", "2")
    assert _header_pairs(d) == [("X-Multi", "1"), ("X-Multi", "2")]


def test_header_pairs_preserves_pair_list_order_and_duplicates():
    assert _header_pairs([("A", "1"), ("A", "2")]) == [("A", "1"), ("A", "2")]


def test_header_pairs_none_and_empty():
    assert _header_pairs(None) == []
    assert _header_pairs([]) == []
