"""P7 unit tests: JA4+ report-only calculators (known FoxIO vectors)."""

from __future__ import annotations

from freetls.fingerprint import (
    ja4h,
    ja4l,
    ja4l_c,
    ja4l_s,
    ja4t,
    ja4ts,
    ja4x,
    ja4x_from_cert,
    oid_to_hex,
)


def test_oid_to_hex():
    assert oid_to_hex("2.5.4.3") == "550403"
    assert oid_to_hex("2.5.4.6") == "550406"
    assert oid_to_hex("1.3.6.1.5.5.7.1.1") == "2b06010505070101"
    assert oid_to_hex("550403") == "550403"


def test_ja4x_known_vector():
    value = ja4x(["2.5.4.3", "2.5.4.6"], ["2.5.4.3"], ["2.5.29.17"])
    assert value == "646f591de230_7022c563de38_6ea8df877ef2"


def test_ja4x_from_cert_matches_oid_lists(certs):
    cert_file, _ = certs
    value = ja4x_from_cert(open(cert_file, "rb").read())
    issuer, subject, extensions = value.split("_")
    assert len(issuer) == len(subject) == len(extensions) == 12
    assert all(c in "0123456789abcdef" for c in value.replace("_", ""))


def test_ja4t_known_vectors():
    assert ja4t(8192, [], None, None) == "8192_00_00_00"
    assert ja4t(5744, [2, 4, 8, 1, 3], 1436, 0) == "5744_2-4-8-1-3_1436_00"
    assert ja4t(8192, [2], 9, None) == "8192_2_09_00"
    assert ja4ts(8192, [], None, None) == "8192_00_00_00"
    assert ja4t(64240, [2, 4, 8, 1, 1, 4], 1460, 8) == "64240_2-4-8-1-1-4_1460_8"


def test_ja4l_components():
    assert ja4l_c(1200, 1300, 64) == "50_64"
    assert ja4l_s(1000, 1200, 128) == "100_128"
    assert ja4l(1000, 1200, 1300, 64, 128) == {"ja4l_c": "50_64", "ja4l_s": "100_128"}
    assert ja4l(1000, 1201, 1202) == {"ja4l_c": "0_0", "ja4l_s": "100_0"}


def test_ja4h_known_foxio_vector():
    headers = [
        ("Host", "127.0.0.1:8000"),
        ("User-Agent", "curl/7.81.0"),
        ("Accept", "*/*"),
        ("Accept-Language", "da"),
        ("Referer", "http://127.0.0.1:8000/"),
    ]
    cookies = ["yummy_cookie=choco", "tasty_cookie=strawberry"]
    result = ja4h("GET", headers, cookies=cookies, version="HTTP/1.1")
    assert result["ja4h"] == "ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"
    assert result["ja4h_ro"] == (
        "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_"
        "yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry"
    )
    assert result["ja4h_r"] == (
        "ge11cr04da00_Host,User-Agent,Accept,Accept-Language_"
        "tasty_cookie,yummy_cookie_tasty_cookie=strawberry,yummy_cookie=choco"
    )


def test_ja4h_no_cookies_or_referer():
    result = ja4h("POST", [("Host", "x"), ("Accept", "*/*")], version="HTTP/2")
    assert result["ja4h"].startswith("po20nn02")
    assert result["ja4h"].endswith("_" + "0" * 12 + "_" + "0" * 12)


def test_ja4h_http3_version_code():
    for version in ("HTTP/3", "HTTP/3.0", "h3", "3", "30"):
        result = ja4h("GET", [("Host", "x"), ("Accept", "*/*")], version=version)
        assert result["ja4h"].startswith("ge30nn02"), version
