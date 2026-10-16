"""FFDHE (DHE) cipher suites: DHE-RSA, DHE-DSS and anonymous ADH.

Verifies that the wide engine completes each suite against a local
``openssl s_server`` using the RFC 7919 ``ffdhe2048`` group. The wide engine is
built once per session and driven through a subprocess (see
``tests/_dhe_client.py``).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
SRC = ROOT / "src"
CLIENT = Path(__file__).resolve().parents[1] / "_dhe_client.py"
TLS12 = 0x0303


def _find_go() -> str | None:
    env = os.environ.get("FREETLS_GO")
    if env:
        return env if os.path.exists(env) else shutil.which(env)
    found = shutil.which("go")
    if found:
        return found
    for cand in (
        os.path.expanduser("~/.local/go/bin/go"),
        "/usr/local/go/bin/go",
        "/opt/go/bin/go",
    ):
        if os.path.exists(cand):
            return cand
    return None


def _has_openssl_dev() -> bool:
    if shutil.which("pkg-config") is None:
        return False
    return (
        subprocess.run(
            ["pkg-config", "--exists", "libcrypto"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def wide_engine(tmp_path_factory) -> str:
    go = _find_go()
    if go is None:
        pytest.skip("Go toolchain not available")
    if not _has_openssl_dev():
        pytest.skip("OpenSSL development files (pkg-config libcrypto) not available")
    out = tmp_path_factory.mktemp("ffdhe") / "libfreetls_libcrypto.so"
    env = dict(os.environ)
    env.setdefault("GOPATH", os.path.expanduser("~/go"))
    env["CGO_ENABLED"] = "1"
    subprocess.run(
        [go, "build", "-tags", "freetls_libcrypto", "-buildmode=c-shared", "-o", str(out), "."],
        cwd=NATIVE,
        check=True,
        env=env,
    )
    return str(out)


@pytest.fixture(scope="session")
def rsa_certs(tmp_path_factory) -> tuple[str, str]:
    d = tmp_path_factory.mktemp("ffdhe-rsa")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture(scope="session")
def dsa_certs(tmp_path_factory) -> tuple[str, str]:
    d = tmp_path_factory.mktemp("ffdhe-dsa")
    param, cert, key = d / "param.pem", d / "cert.pem", d / "key.pem"
    r = subprocess.run(
        [
            "openssl",
            "genpkey",
            "-genparam",
            "-algorithm",
            "DSA",
            "-pkeyopt",
            "dsa_paramgen_bits:2048",
            "-out",
            str(param),
        ],
        capture_output=True,
    )
    if r.returncode != 0 or not param.exists():
        pytest.skip("local OpenSSL cannot generate DSA parameters")
    subprocess.run(["openssl", "genpkey", "-paramfile", str(param), "-out", str(key)], check=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


class _Server:
    def __init__(self, proc: subprocess.Popen, port: int):
        self.proc = proc
        self.port = port

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _start_server(certs: tuple[str, str] | None, cipher: str) -> _Server:
    port = _free_port()
    args = [
        "openssl",
        "s_server",
        "-accept",
        str(port),
        "-tls1_2",
        "-cipher",
        f"{cipher}:@SECLEVEL=0",
        "-groups",
        "ffdhe2048",
        "-www",
        "-quiet",
    ]
    if certs is None:
        args.append("-nocert")
    else:
        args += ["-cert", certs[0], "-key", certs[1]]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return _Server(proc, port)
        except OSError:
            import time

            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("openssl s_server did not start")


def _run_client(lib: str, port: int, ciphers: list[int], anonymous: bool = False) -> dict:
    env = dict(os.environ)
    env["FREETLS_LIB"] = lib
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    csv = ",".join(f"{c:04x}" for c in ciphers)
    proc = subprocess.run(
        [
            sys.executable,
            str(CLIENT),
            "127.0.0.1",
            str(port),
            csv,
            str(TLS12),
            str(TLS12),
            "localhost",
            "1" if anonymous else "0",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        raise AssertionError(f"client crashed: {proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


# (suite id, openssl server cipher name)
DHE_RSA_SUITES = [
    (0x009E, "DHE-RSA-AES128-GCM-SHA256"),
    (0x009F, "DHE-RSA-AES256-GCM-SHA384"),
    (0x0033, "DHE-RSA-AES128-SHA"),
    (0x0039, "DHE-RSA-AES256-SHA"),
    (0x0067, "DHE-RSA-AES128-SHA256"),
    (0x006B, "DHE-RSA-AES256-SHA256"),
    (0xCCAA, "DHE-RSA-CHACHA20-POLY1305"),
    (0xC052, "DHE-RSA-ARIA128-GCM-SHA256"),
    (0xC053, "DHE-RSA-ARIA256-GCM-SHA384"),
    (0xC09E, "DHE-RSA-AES128-CCM"),
    (0xC09F, "DHE-RSA-AES256-CCM"),
    (0xC0A2, "DHE-RSA-AES128-CCM8"),
    (0xC0A3, "DHE-RSA-AES256-CCM8"),
    (0x0045, "DHE-RSA-CAMELLIA128-SHA"),
    (0x0088, "DHE-RSA-CAMELLIA256-SHA"),
    (0x00BE, "DHE-RSA-CAMELLIA128-SHA256"),
    (0x00C4, "DHE-RSA-CAMELLIA256-SHA256"),
]

DHE_DSS_SUITES = [
    (0x00A2, "DHE-DSS-AES128-GCM-SHA256"),
    (0x00A3, "DHE-DSS-AES256-GCM-SHA384"),
    (0x0032, "DHE-DSS-AES128-SHA"),
    (0x0038, "DHE-DSS-AES256-SHA"),
    (0x0040, "DHE-DSS-AES128-SHA256"),
    (0x006A, "DHE-DSS-AES256-SHA256"),
    (0xC056, "DHE-DSS-ARIA128-GCM-SHA256"),
    (0xC057, "DHE-DSS-ARIA256-GCM-SHA384"),
    (0x0044, "DHE-DSS-CAMELLIA128-SHA"),
    (0x0087, "DHE-DSS-CAMELLIA256-SHA"),
    (0x00BD, "DHE-DSS-CAMELLIA128-SHA256"),
    (0x00C3, "DHE-DSS-CAMELLIA256-SHA256"),
]

ADH_SUITES = [
    (0x00A6, "ADH-AES128-GCM-SHA256"),
    (0x00A7, "ADH-AES256-GCM-SHA384"),
    (0x0034, "ADH-AES128-SHA"),
    (0x003A, "ADH-AES256-SHA"),
    (0x006C, "ADH-AES128-SHA256"),
    (0x006D, "ADH-AES256-SHA256"),
    (0x0046, "ADH-CAMELLIA128-SHA"),
    (0x0089, "ADH-CAMELLIA256-SHA"),
    (0x00BF, "ADH-CAMELLIA128-SHA256"),
    (0x00C5, "ADH-CAMELLIA256-SHA256"),
]


@pytest.mark.parametrize("suite,name", DHE_RSA_SUITES, ids=[f"{s:04x}" for s, _ in DHE_RSA_SUITES])
def test_dhe_rsa_suite_completes(wide_engine, rsa_certs, suite, name):
    srv = _start_server(rsa_certs, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite


@pytest.mark.parametrize("suite,name", DHE_DSS_SUITES, ids=[f"{s:04x}" for s, _ in DHE_DSS_SUITES])
def test_dhe_dss_suite_completes(wide_engine, dsa_certs, suite, name):
    srv = _start_server(dsa_certs, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite])
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite


@pytest.mark.parametrize("suite,name", ADH_SUITES, ids=[f"{s:04x}" for s, _ in ADH_SUITES])
def test_adh_suite_completes(wide_engine, suite, name):
    srv = _start_server(None, name)
    try:
        result = _run_client(wide_engine, srv.port, [suite], anonymous=True)
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["version"] == "TLS1.2"
    assert result["cipher_suite"] == suite
