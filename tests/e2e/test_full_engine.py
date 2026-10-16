"""Route B "full" engine: static libcrypto link and symbol interposition.

``make full`` links a static, PIC libcrypto built from the OpenSSL submodule and
hides its symbols, so the engine can be loaded next to Python's ``_ssl`` (which
links the system ``libcrypto.so.3``) without interposing. These tests build the
full engine once and exercise it in a subprocess.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
OPENSSL_DIR = NATIVE / "third_party" / "openssl"
SRC = ROOT / "src"
PROBE = Path(__file__).resolve().parents[1] / "_interposition_probe.py"


def _find_go() -> str | None:
    env = os.environ.get("FREETLS_GO")
    if env:
        return env if os.path.exists(env) else shutil.which(env)
    found = shutil.which("go")
    if found:
        return found
    for cand in (os.path.expanduser("~/.local/go/bin/go"), "/usr/local/go/bin/go"):
        if os.path.exists(cand):
            return cand
    return None


@pytest.fixture(scope="session")
def full_engine(tmp_path_factory) -> str:
    go = _find_go()
    if go is None:
        pytest.skip("Go toolchain not available")
    if not (OPENSSL_DIR / "libcrypto.a").exists():
        pytest.skip("static OpenSSL not built (run `make full` first)")
    out = tmp_path_factory.mktemp("full") / "libfreetls.so"
    env = dict(os.environ)
    env.setdefault("GOPATH", os.path.expanduser("~/go"))
    env["CGO_ENABLED"] = "1"
    env["CGO_CFLAGS"] = f"-I{OPENSSL_DIR}/include"
    env["CGO_LDFLAGS"] = (
        f"{OPENSSL_DIR}/libcrypto.a -ldl -pthread -Wl,-Bsymbolic -Wl,--exclude-libs,ALL"
    )
    subprocess.run(
        [
            go,
            "build",
            "-tags",
            "freetls_libcrypto freetls_static_openssl",
            "-buildmode=c-shared",
            "-o",
            str(out),
            ".",
        ],
        cwd=NATIVE,
        check=True,
        env=env,
    )
    return str(out)


def test_full_engine_is_static_and_hidden(full_engine):
    """No libcrypto DT_NEEDED and no exported OpenSSL symbols."""
    needed = subprocess.run(["ldd", full_engine], capture_output=True, text=True).stdout
    assert "libcrypto" not in needed
    assert "libssl" not in needed
    syms = subprocess.run(
        ["nm", "-D", "--defined-only", full_engine], capture_output=True, text=True
    ).stdout
    exported = [
        line
        for line in syms.splitlines()
        if any(f" {p}" in line for p in ("EVP_", "OPENSSL_", "CRYPTO_"))
    ]
    assert exported == []


def test_interposition_with_python_ssl(full_engine, tls_server_13):
    env = dict(os.environ)
    env["FREETLS_LIB"] = full_engine
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(PROBE), "127.0.0.1", str(tls_server_13.port), "localhost"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout.strip().splitlines()[-1])
    assert data["errors"] == [], data
    assert data["results"].get("ssl") == "TLSv1.3"
    assert data["results"].get("freetls") == "TLS1.3"
