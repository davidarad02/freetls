"""ctypes/cffi binding to the native freetls engine (libfreetls).

Loads the Go c-shared library and exposes a small, safe Python wrapper.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from ..errors import EngineError, HandshakeError, SpecError

_CDEF = """
char *freetls_version(void);
void freetls_free(char *);
int freetls_ping(void);
long long freetls_session_new(const char *);
void freetls_session_free(long long);
int freetls_handshake(long long, int, const char *);
long long freetls_read(long long, void *, long long);
long long freetls_write(long long, const void *, long long);
void freetls_close(long long);
char *freetls_get_client_hello(long long);
char *freetls_get_server_hello(long long);
char *freetls_get_state(long long);
char *freetls_last_error(long long);
char *freetls_preset_raw(const char *);
char *freetls_preset_raw_opts(const char *, int, const char *);
char *freetls_chlo_raw(const char *);
char *freetls_aux_error(void);
char *freetls_preset_list(void);
char *freetls_h2_request(long long, const char *);
"""

_LIB_NAMES = {
    "linux": "libfreetls.so",
    "darwin": "libfreetls.dylib",
    "windows": "freetls.dll",
}


def _lib_filename() -> str:
    return _LIB_NAMES.get(platform.system().lower(), "libfreetls.so")


def _candidate_paths() -> list[str]:
    env = os.environ.get("FREETLS_LIB")
    here = os.path.dirname(os.path.abspath(__file__))  # src/freetls/engine
    pkg = os.path.dirname(here)  # src/freetls
    proj_root = os.path.dirname(os.path.dirname(pkg))  # project root
    name = _lib_filename()
    cands = []
    if env:
        cands.append(env)
    cands += [
        os.path.join(pkg, "_lib", name),
        os.path.join(proj_root, "native", name),
        os.path.join(proj_root, "build", name),
    ]
    return cands


_ffi = None
_lib = None


def _native_source_dir() -> Optional[str]:
    """The bundled ``native/`` Go source dir, if this is a source checkout."""
    here = os.path.dirname(os.path.abspath(__file__))  # src/freetls/engine
    proj_root = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    native = os.path.join(proj_root, "native")
    if os.path.exists(os.path.join(native, "go.mod")):
        return native
    return None


def _find_go() -> Optional[str]:
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
        "/opt/homebrew/bin/go",
    ):
        if os.path.exists(cand):
            return cand
    return None


def _autobuild() -> Optional[str]:
    """Build the engine from ``native/`` into ``native/`` if possible.

    Lets a fresh source checkout work without a separate build step. Disable
    with ``FREETLS_NO_AUTOBUILD=1``.
    """
    if os.environ.get("FREETLS_NO_AUTOBUILD"):
        return None
    native = _native_source_dir()
    if native is None:
        return None
    go = _find_go()
    if go is None:
        return None
    out = os.path.join(native, _lib_filename())
    env = dict(os.environ)
    env.setdefault("GOPATH", os.path.expanduser("~/go"))
    env["CGO_ENABLED"] = "1"
    env["PATH"] = os.path.dirname(go) + os.pathsep + env.get("PATH", "")
    sys.stderr.write(f"freetls: building native engine (one-time) -> {out}\n")
    subprocess.run(
        [go, "build", "-buildmode=c-shared", "-o", out, "."],
        cwd=native,
        check=True,
        env=env,
    )
    return out


def _try_candidates(ffi):
    last_err = None
    for path in _candidate_paths():
        if not path or not os.path.exists(path):
            continue
        try:
            lib = ffi.dlopen(path)
            lib.freetls_ping()  # smoke test
            return lib
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    if last_err is not None:
        raise last_err
    return None


def _load():
    global _ffi, _lib
    if _lib is not None:
        return _ffi, _lib
    import cffi  # imported lazily so the fingerprint core works without cffi

    ffi = cffi.FFI()
    ffi.cdef(_CDEF)
    try:
        lib = _try_candidates(ffi)
    except Exception:
        lib = None
    if lib is None:
        _autobuild()
        lib = _try_candidates(ffi)
    if lib is None:
        raise EngineError(
            "could not load the native freetls engine. Build it with "
            "`make native` (or `pip install -e .`), install a prebuilt wheel, "
            "or set FREETLS_LIB=/path/to/libfreetls.so. Searched: "
            + ", ".join(p for p in _candidate_paths() if p)
        )
    _ffi, _lib = ffi, lib
    return ffi, lib


def version() -> str:
    ffi, lib = _load()
    return ffi.string(lib.freetls_version()).decode()


def preset_list() -> list:
    """Names of the built-in uTLS ClientHello presets."""
    ffi, lib = _load()
    return json.loads(ffi.string(lib.freetls_preset_list()).decode() or "[]")


def preset_raw(name: str) -> bytes:
    """Build a preset's ClientHello offline; returns the raw handshake bytes."""
    ffi, lib = _load()
    s = ffi.string(lib.freetls_preset_raw(name.encode())).decode()
    return bytes.fromhex(s) if s else b""


def preset_raw_opts(name: str, no_sni: bool = False, alpn=None) -> bytes:
    """Build a preset ClientHello with SNI/ALPN overrides (offline).

    ``alpn=None`` leaves ALPN untouched, ``alpn=[]`` removes it, otherwise a
    list of protocol strings.
    """
    ffi, lib = _load()
    if alpn is None:
        alpn_json = b""
    elif alpn == []:
        alpn_json = b"-"
    else:
        alpn_json = json.dumps(list(alpn)).encode()
    s = ffi.string(
        lib.freetls_preset_raw_opts(name.encode(), 1 if no_sni else 0, alpn_json)
    ).decode()
    return bytes.fromhex(s) if s else b""


def chlo_raw(chlo_json: str) -> bytes:
    """Build a ClientHello offline from a uTLS ClientHelloSpec JSON document.

    Returns the raw handshake message bytes, or ``b""`` if the document is
    invalid/unsupported. No network is used.
    """
    ffi, lib = _load()
    s = ffi.string(lib.freetls_chlo_raw(chlo_json.encode())).decode()
    if not s:
        reason = ffi.string(lib.freetls_aux_error()).decode() or "invalid ClientHelloSpec JSON"
        raise SpecError(f"chlo_json: {reason}")
    return bytes.fromhex(s)


@dataclass
class EngineState:
    version: str = ""
    cipher_suite: int = 0
    alpn: str = ""
    server_name: str = ""
    peer_cert_b64: str = ""
    error: str = ""

    @classmethod
    def from_json(cls, text: str) -> "EngineState":
        try:
            d = json.loads(text or "{}")
        except json.JSONDecodeError:
            d = {}
        return cls(
            version=d.get("version", ""),
            cipher_suite=d.get("cipher_suite", 0),
            alpn=d.get("alpn", ""),
            server_name=d.get("server_name", ""),
            peer_cert_b64=d.get("peer_cert_b64", ""),
            error=d.get("error", ""),
        )

    @property
    def peer_cert_der(self) -> bytes:
        import base64

        return base64.b64decode(self.peer_cert_b64) if self.peer_cert_b64 else b""


class EngineSession:
    """Low-level handle to a single native TLS session."""

    def __init__(self, spec: dict):
        ffi, lib = _load()
        self._ffi = ffi
        self._lib = lib
        spec_json = json.dumps(spec).encode()
        self._handle = lib.freetls_session_new(spec_json)
        if self._handle <= 0:
            raise EngineError("freetls_session_new failed (invalid spec)")
        self._closed = False

    def handshake(self, fd: int, sni: Optional[str] = None) -> None:
        sni_b = (sni or "").encode()
        rc = self._lib.freetls_handshake(self._handle, fd, sni_b)
        if rc != 0:
            state = self.state()
            raise HandshakeError(
                f"handshake failed (rc={rc}): {self.last_error()}", state=vars(state)
            )

    def read(self, n: int) -> bytes:
        buf = self._ffi.new("char[]", n)
        rc = self._lib.freetls_read(self._handle, buf, n)
        if rc < 0:
            raise EngineError(f"read failed: {self.last_error()}")
        return bytes(self._ffi.buffer(buf, rc))

    def write(self, data: bytes) -> int:
        buf = self._ffi.new("char[]", data)
        rc = self._lib.freetls_write(self._handle, buf, len(data))
        if rc < 0:
            raise EngineError(f"write failed: {self.last_error()}")
        return int(rc)

    def client_hello(self) -> bytes:
        s = self._ffi.string(self._lib.freetls_get_client_hello(self._handle)).decode()
        return bytes.fromhex(s) if s else b""

    def server_hello(self) -> bytes:
        s = self._ffi.string(self._lib.freetls_get_server_hello(self._handle)).decode()
        return bytes.fromhex(s) if s else b""

    def state(self) -> EngineState:
        s = self._ffi.string(self._lib.freetls_get_state(self._handle)).decode()
        return EngineState.from_json(s)

    def last_error(self) -> str:
        return self._ffi.string(self._lib.freetls_last_error(self._handle)).decode()

    def h2_request(self, req: dict) -> dict:
        """Perform an HTTP/2 request with full fingerprint control."""
        payload = json.dumps(req).encode()
        raw = self._ffi.string(
            self._lib.freetls_h2_request(self._handle, payload)
        ).decode()
        return json.loads(raw or "{}")

    def close(self) -> None:
        if not self._closed:
            self._lib.freetls_close(self._handle)
            self._closed = True

    def free(self) -> None:
        if not self._closed:
            self._lib.freetls_session_free(self._handle)
            self._closed = True
