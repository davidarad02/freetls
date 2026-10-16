"""Every registered cipher suite, negotiated end-to-end against local OpenSSL.

For each of the engine's registered suites this starts a purpose-built
``openssl s_server`` (cipher restricted to that suite, with the certificate /
PSK / anonymous configuration the suite needs) and verifies a full handshake
*plus* an application-data round trip (an HTTP GET answered by ``-www``).

Suites that local OpenSSL 3.5.5 cannot negotiate are skipped with a concrete
reason derived from ``openssl ciphers -V`` (or an explicit allow-list for the
SRP app-path limitation), so the gap is visible in the report rather than
silently counted as working.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

import freetls

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
CLIENT = Path(__file__).resolve().parents[1] / "_suite_client.py"
TLS12, TLS13 = 0x0303, 0x0304
PSK_HEX = "0102030405060708090a0b0c0d0e0f10"
PSK_ID = "freetls"
SRP_REASON = (
    "OpenSSL 3.5.5's deprecated s_server SRP app path does not complete "
    "(see tests/e2e/test_srp_suites.py); SRP is verified at the key-agreement level"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _openssl_catalog() -> dict[int, dict]:
    """id -> {name, ver, kx, au} for every cipher local OpenSSL can negotiate."""
    out = subprocess.run(
        ["openssl", "ciphers", "-V", "ALL:@SECLEVEL=0"],
        capture_output=True,
        text=True,
    ).stdout
    catalog: dict[int, dict] = {}
    for line in out.splitlines():
        m = re.search(
            r"0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})\s*-\s*(\S+)\s+(\S+)\s+Kx=(\S+)\s+Au=(\S+)",
            line,
        )
        if m:
            sid = int(m.group(1), 16) << 8 | int(m.group(2), 16)
            catalog[sid] = {
                "name": m.group(3),
                "ver": m.group(4),
                "kx": m.group(5),
                "au": m.group(6),
            }
    return catalog


CATALOG = _openssl_catalog()
ALL_SUITES = sorted(freetls.engine.supported_ciphers())


def _case(suite: int) -> tuple[int, dict | None, str | None]:
    entry = CATALOG.get(suite)
    if entry is None:
        return suite, None, "not offered by local OpenSSL 3.5.5"
    if entry["kx"] == "SRP":
        return suite, entry, SRP_REASON
    return suite, entry, None


CASES = [_case(s) for s in ALL_SUITES]


@pytest.fixture(scope="session")
def engine_path(engine_lib) -> str:
    return engine_lib


@pytest.fixture(scope="session")
def suite_certs(tmp_path_factory) -> dict[str, tuple[str, str]]:
    d = tmp_path_factory.mktemp("all-suites")

    def rsa() -> tuple[str, str]:
        cert, key = d / "rsa.pem", d / "rsa.key"
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

    def ec() -> tuple[str, str]:
        cert, key = d / "ec.pem", d / "ec.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
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

    def dsa() -> tuple[str, str] | None:
        param, cert, key = d / "dsa.param", d / "dsa.pem", d / "dsa.key"
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
            return None
        subprocess.run(
            ["openssl", "genpkey", "-paramfile", str(param), "-out", str(key)],
            check=True,
            capture_output=True,
        )
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

    return {"rsa": rsa(), "ec": ec(), "dsa": dsa()}


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


def _server_args(entry: dict, certs: dict, port: int) -> tuple[list[str] | None, str, str, str]:
    """Return (argv, client-mode, secret1, secret2) or (None, ...) if unsupported."""
    name, kx, au, ver = entry["name"], entry["kx"], entry["au"], entry["ver"]
    args = ["openssl", "s_server", "-accept", str(port), "-www", "-quiet"]
    mode, s1, s2 = "plain", "", ""

    if ver == "TLSv1.3":
        args += ["-tls1_3", "-ciphersuites", name]
        args += ["-cert", certs["rsa"][0], "-key", certs["rsa"][1]]
        return args, mode, s1, s2

    args += ["-tls1_2", "-cipher", f"{name}@SECLEVEL=0"]
    if kx in ("RSA", "ECDH") and au == "RSA":
        args += ["-cert", certs["rsa"][0], "-key", certs["rsa"][1]]
    elif kx == "ECDH" and au == "ECDSA":
        args += ["-cert", certs["ec"][0], "-key", certs["ec"][1]]
    elif kx == "DH" and au == "RSA":
        args += ["-cert", certs["rsa"][0], "-key", certs["rsa"][1], "-groups", "ffdhe2048"]
    elif kx == "DH" and au == "DSS":
        if certs["dsa"] is None:
            return None, mode, s1, s2
        args += ["-cert", certs["dsa"][0], "-key", certs["dsa"][1], "-groups", "ffdhe2048"]
    elif kx == "DH" and au in ("None", "any"):
        args += ["-nocert", "-groups", "ffdhe2048"]
        mode = "anon"
    elif kx == "PSK" and au == "PSK":
        args += ["-nocert", "-psk", PSK_HEX, "-psk_identity", PSK_ID]
        mode, s1, s2 = "psk", PSK_ID, PSK_HEX
    elif kx == "DHEPSK":
        args += ["-nocert", "-groups", "ffdhe2048", "-psk", PSK_HEX, "-psk_identity", PSK_ID]
        mode, s1, s2 = "psk", PSK_ID, PSK_HEX
    elif kx == "ECDHEPSK":
        args += ["-nocert", "-psk", PSK_HEX, "-psk_identity", PSK_ID]
        mode, s1, s2 = "psk", PSK_ID, PSK_HEX
    elif kx == "RSAPSK":
        args += [
            "-cert",
            certs["rsa"][0],
            "-key",
            certs["rsa"][1],
            "-psk",
            PSK_HEX,
            "-psk_identity",
            PSK_ID,
        ]
        mode, s1, s2 = "psk", PSK_ID, PSK_HEX
    else:
        return None, mode, s1, s2
    return args, mode, s1, s2


def _start_server(args: list[str], port: int) -> _Server:
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return _Server(proc, port)
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("openssl s_server did not start")


def _run_client(lib: str, port: int, suite: int, ver: str, mode: str, s1: str, s2: str) -> dict:
    env = dict(os.environ)
    env["FREETLS_LIB"] = lib
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    version = TLS13 if ver == "TLSv1.3" else TLS12
    proc = subprocess.run(
        [
            sys.executable,
            str(CLIENT),
            "127.0.0.1",
            str(port),
            f"{suite:04x}",
            str(version),
            str(version),
            "localhost",
            mode,
            s1,
            s2,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        raise AssertionError(f"client crashed: {proc.stderr}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("suite,entry,reason", CASES, ids=[f"{s:04x}" for s, _, _ in CASES])
def test_suite_negotiates_and_transfers(engine_path, suite_certs, suite, entry, reason):
    if reason:
        pytest.skip(reason)
    port = _free_port()
    args, mode, s1, s2 = _server_args(entry, suite_certs, port)
    if args is None:
        pytest.skip(f"no local server configuration for {entry['name']}")
    srv = _start_server(args, port)
    try:
        result = _run_client(engine_path, port, suite, entry["ver"], mode, s1, s2)
    finally:
        srv.stop()
    assert result["ok"], result
    assert result["cipher_suite"] == suite, result
    assert result["data_ok"], result
    assert result["app_bytes"] > 0, result
