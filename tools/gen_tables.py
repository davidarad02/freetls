#!/usr/bin/env python3
"""Generate IANA TLS registry tables for freetls.

Fetches the authoritative IANA CSV registries and writes JSON tables into
src/freetls/fingerprint/tables/. Only *assigned* values are emitted (rows whose
description is not "Unassigned"/"Reserved"). This is the freetls value universe.

Network is used only at generation time; the generated tables are committed so
the library runtime never needs the network.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import urllib.request

IANA = "https://www.iana.org/assignments"

SOURCES = {
    "ciphers": (f"{IANA}/tls-parameters/tls-parameters-4.csv", "Description"),
    "extensions": (
        f"{IANA}/tls-extensiontype-values/tls-extensiontype-values-1.csv",
        "Extension Name",
    ),
    "sigalgs": (f"{IANA}/tls-parameters/tls-signaturescheme.csv", "Description"),
    "groups": (f"{IANA}/tls-parameters/tls-parameters-8.csv", "Description"),
}

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "src", "freetls", "fingerprint", "tables"))


def fetch(url: str, local_dir: str | None) -> str:
    if local_dir:
        for name in os.listdir(local_dir):
            if name.endswith(".csv"):
                pass
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def skip(desc: str) -> bool:
    d = (desc or "").strip().lower()
    return d in {"", "unassigned", "reserved"} or d.startswith("reserved")


def norm_key(name: str) -> str:
    return name.strip().lower()


def pick(row: dict, *candidates: str) -> str | None:
    by_norm = {norm_key(k): v for k, v in row.items() if k is not None}
    for c in candidates:
        if norm_key(c) in by_norm:
            return by_norm[norm_key(c)]
    return None


def parse_cipher_value(raw: str) -> int | None:
    raw = (raw or "").strip().strip('"')
    parts = [p.strip() for p in raw.split(",")]
    if len(parts) != 2:
        return None
    try:
        return (int(parts[0], 16) << 8) | int(parts[1], 16)
    except ValueError:
        return None


def parse_dec(raw: str) -> int | None:
    raw = (raw or "").strip().strip('"')
    try:
        return int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
    except ValueError:
        return None


def build(kind: str, url: str, desc_col: str, text: str) -> dict:
    entries = []
    for row in csv.DictReader(io.StringIO(text)):
        desc = pick(row, desc_col)
        if skip(desc):
            continue
        raw = pick(row, "Value")
        if raw is None or raw.strip() == "":
            continue
        value = parse_cipher_value(raw) if kind == "ciphers" else parse_dec(raw)
        if value is None:
            continue
        entries.append({"value": value, "hex": f"{value:04x}", "name": desc.strip()})
    seen: dict[str, dict] = {}
    for e in entries:
        seen.setdefault(str(e["value"]), e)
    entries = sorted(seen.values(), key=lambda e: e["value"])
    return {"source": url, "count": len(entries), "entries": entries}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=None, help="unused (kept for compatibility)")
    ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    for kind, (url, desc_col) in SOURCES.items():
        try:
            text = fetch(url, None)
        except Exception as exc:  # noqa: BLE001
            print(f"[error] {kind}: {exc}", file=sys.stderr)
            return 1
        table = build(kind, url, desc_col, text)
        out = os.path.join(OUT_DIR, f"{kind}.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(table, fh, indent=1, sort_keys=True)
        print(f"[ok] {kind}: {table['count']} assigned -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
