"""JA4H: HTTP request fingerprint (report-only).

``JA4H`` is computed from the HTTP request that was actually sent: method,
HTTP version, presence of cookies/referer, header count, the first
``Accept-Language`` code, and hashes of the header names and (sorted) cookie
names/values. ``JA4H_r``/``JA4H_ro`` include the raw header names and
sorted/unsorted cookie pairs, matching the FoxIO JA4H definition.
"""

from __future__ import annotations

from hashlib import sha256

__all__ = ["ja4h", "ja4h_from_request"]


def _sha_encode(values: list[str]) -> str:
    return sha256(",".join(values).encode("utf8")).hexdigest()[:12]


def _version_code(version) -> str:
    if version is None:
        return "11"
    text = str(version)
    if text in ("3", "30", "HTTP/3", "h3", "HTTP/3.0", "http3"):
        return "30"
    if text in ("2", "20", "HTTP/2", "h2", "HTTP/2.0", "http2"):
        return "20"
    if "/" in text:
        return text.split("/")[-1].replace(".", "")
    return text.replace(".", "")


def _language(value: str) -> str:
    code = value.replace("-", "").replace(";", ",").lower().split(",")[0][:4]
    return code + "0" * (4 - len(code))


def _parse_cookies(cookies) -> list[tuple[str, str]]:
    pairs = []
    for item in cookies:
        if isinstance(item, tuple):
            pairs.append((str(item[0]).strip(), str(item[1]).strip()))
        else:
            name, _, value = str(item).partition("=")
            pairs.append((name.strip(), str(item).strip()))
    return pairs


def ja4h(method: str, headers, cookies=None, version=None) -> dict:
    """Compute JA4H, JA4H_r and JA4H_ro from a request.

    ``headers`` is an ordered iterable of ``(name, value)`` pairs. Cookies may
    be passed explicitly (list of ``"k=v"`` or ``(k, v)``) or left to be parsed
    from a ``Cookie`` header.
    """
    pairs = list(headers)

    lang = "0000"
    referer = "n"
    header_names: list[str] = []
    for name, value in pairs:
        low = name.lower()
        if low == "referer":
            referer = "r"
        if low == "accept-language":
            lang = _language(str(value))
        if name.startswith(":") or low.startswith("cookie") or low == "referer" or not name:
            continue
        header_names.append(name)

    if cookies is None:
        cookies = [v for k, v in pairs if k.lower() == "cookie"]
        raw_cookie = ";".join(cookies)
        cookies = [c for c in raw_cookie.split(";") if c.strip()] if raw_cookie else None
    cookie_pairs = _parse_cookies(cookies) if cookies else []
    cookie = "c" if cookie_pairs else "n"

    method_code = method.lower()[:2]
    version_code = _version_code(version)
    header_len = f"{min(len(header_names), 99):02d}"

    if cookie_pairs:
        sorted_pairs = sorted(cookie_pairs, key=lambda p: p[0])
        cookies_hash = _sha_encode([p[0] for p in sorted_pairs])
        cookie_values_hash = _sha_encode([p[1] for p in sorted_pairs])
    else:
        sorted_pairs = []
        cookies_hash = "0" * 12
        cookie_values_hash = "0" * 12

    prefix = f"{method_code}{version_code}{cookie}{referer}{header_len}{lang}"
    ja4h_val = f"{prefix}_{_sha_encode(header_names)}_{cookies_hash}_{cookie_values_hash}"
    raw = ",".join(header_names)
    ja4h_r = f"{prefix}_{raw}_"
    if sorted_pairs:
        ja4h_r += f"{','.join(p[0] for p in sorted_pairs)}_{','.join(p[1] for p in sorted_pairs)}"
    ja4h_ro = f"{prefix}_{raw}_"
    if cookie_pairs:
        ja4h_ro += f"{','.join(p[0] for p in cookie_pairs)}_{','.join(p[1] for p in cookie_pairs)}"
    return {"ja4h": ja4h_val, "ja4h_r": ja4h_r, "ja4h_ro": ja4h_ro}


def ja4h_from_request(method: str, headers, version=None) -> dict:
    """Convenience wrapper: derive cookies from the ``Cookie`` header."""
    return ja4h(method, headers, cookies=None, version=version)
