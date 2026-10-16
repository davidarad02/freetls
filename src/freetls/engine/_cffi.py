"""ctypes/cffi binding to the native freetls engine (libfreetls).

Loads the Go c-shared library and exposes a small, safe Python wrapper.
"""

from __future__ import annotations

import enum
import json
import os
import platform
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ..errors import EngineError, HandshakeError, SpecError

_CDEF = """
char *freetls_version(void);
int freetls_abi_version(void);
void freetls_free(char *);
int freetls_ping(void);
long long freetls_session_new(const char *);
void freetls_session_free(long long);
int freetls_handshake(long long, int, const char *);
long long freetls_read(long long, void *, long long);
long long freetls_write(long long, const void *, long long);
void freetls_close(long long);
void freetls_set_timeout(long long, int);
char *freetls_get_client_hello(long long);
char *freetls_get_server_hello(long long);
char *freetls_get_state(long long);
char *freetls_last_error(long long);
long long freetls_session_count(void);
char *freetls_preset_raw(const char *);
char *freetls_preset_raw_opts(const char *, int, const char *);
char *freetls_chlo_raw(const char *);
char *freetls_aux_error(void);
char *freetls_preset_list(void);
char *freetls_h2_request(long long, const char *);
char *freetls_supported_ciphers(void);
char *freetls_supported_extensions(void);
char *freetls_spec_raw(const char *);
"""

_LIB_NAMES = {
    "linux": "libfreetls.so",
    "darwin": "libfreetls.dylib",
    "windows": "freetls.dll",
}


def _lib_filename() -> str:
    return _LIB_NAMES.get(platform.system().lower(), "libfreetls.so")


def _go_lib_filename() -> str:
    stem, dot, ext = _lib_filename().rpartition(".")
    return f"{stem}_go{dot}{ext}" if dot else f"{_lib_filename()}_go"


class Engine(enum.Enum):
    """A built-in engine variant.

    ``WIDE`` is the default (Go + a static OpenSSL ``libcrypto`` backend, 51
    completable cipher suites); ``GO`` is the Go-only engine (27 suites).
    """

    WIDE = "wide"
    GO = "go"


@dataclass(frozen=True)
class EngineInfo:
    """Identifies the engine currently in use."""

    kind: Engine | None  # None when loaded from an explicit file
    path: str


class _Engine:
    """A loaded engine shared object plus its cffi binding."""

    def __init__(self, path: str, ffi, lib, kind: Engine | None):
        self.path = path
        self.ffi = ffi
        self.lib = lib
        self.kind = kind
        self.abi = int(lib.freetls_abi_version())

    def info(self) -> EngineInfo:
        return EngineInfo(kind=self.kind, path=self.path)


# One entry per resolved path; ``_current`` is the engine new sessions use.
_engines: dict[str, _Engine] = {}
_current: _Engine | None = None


def _candidate_paths(name: str | None = None) -> list[str]:
    env = os.environ.get("FREETLS_LIB")
    here = os.path.dirname(os.path.abspath(__file__))  # src/freetls/engine
    pkg = os.path.dirname(here)  # src/freetls
    proj_root = os.path.dirname(os.path.dirname(pkg))  # project root
    name = name or _lib_filename()
    cands = []
    # $FREETLS_LIB is an explicit override for the *default* engine only.
    if env and name == _lib_filename():
        cands.append(env)
    cands += [
        os.path.join(pkg, "_lib", name),
        os.path.join(proj_root, "native", name),
        os.path.join(proj_root, "build", name),
    ]
    return cands


def _first_loadable(ffi, paths: list[str]) -> tuple[str | None, Any]:
    """Return ``(path, lib)`` for the first path that loads, else ``(None, None)``."""
    last_err = None
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        try:
            lib = ffi.dlopen(path)
            lib.freetls_ping()  # smoke test
            return path, lib
        except Exception as exc:  # noqa: BLE001
            last_err = exc
    if last_err is not None:
        raise last_err
    return None, None


def _make_ffi():
    import cffi  # imported lazily so the fingerprint core works without cffi

    ffi = cffi.FFI()
    ffi.cdef(_CDEF)
    return ffi


def _check_abi(eng: _Engine) -> None:
    if eng.abi != _EXPECTED_ABI:
        raise EngineError(
            f"native engine C-ABI version {eng.abi} is incompatible with this "
            f"Python binding (expected {_EXPECTED_ABI}); rebuild with `make native`"
        )


def _not_found(kind: Engine, paths: list[str], err: Exception | None = None) -> EngineError:
    label = "wide (Go+libcrypto)" if kind is Engine.WIDE else "Go-only"
    msg = (
        f"could not load the {label} freetls engine. Build it with `make native` "
        "(or `pip install .`), install a prebuilt wheel, or set "
        "FREETLS_LIB=/path/to/libfreetls.so. Searched: " + ", ".join(p for p in paths if p)
    )
    if err is not None:
        msg += f" (last error: {err})"
    return EngineError(msg)


def _resolve(kind: Engine) -> _Engine:
    """Locate and load a built-in engine variant (cached by path)."""
    name = _lib_filename() if kind is Engine.WIDE else _go_lib_filename()
    paths = _candidate_paths(name)
    for cand in paths:
        if not cand:
            continue
        cached = _engines.get(os.path.realpath(cand))
        if cached is not None:
            return cached
    ffi = _make_ffi()
    err: Exception | None = None
    try:
        path, lib = _first_loadable(ffi, paths)
    except Exception as exc:  # noqa: BLE001
        path, lib, err = None, None, exc
    if lib is None or path is None:
        raise _not_found(kind, paths, err)
    eng = _Engine(path, ffi, lib, kind)
    _check_abi(eng)
    _engines[os.path.realpath(path)] = eng
    return eng


def _load_file(path: str) -> _Engine:
    real = os.path.realpath(path)
    cached = _engines.get(real)
    if cached is not None:
        return cached
    if not os.path.exists(path):
        raise EngineError(f"engine not found: {path}")
    ffi = _make_ffi()
    try:
        lib = ffi.dlopen(path)
        lib.freetls_ping()
    except Exception as exc:  # noqa: BLE001
        raise EngineError(f"could not load engine {path}: {exc}") from exc
    eng = _Engine(path, ffi, lib, None)
    _check_abi(eng)
    _engines[real] = eng
    return eng


def _current_engine() -> _Engine:
    global _current
    if _current is None:
        _current = _resolve(Engine.WIDE)
    return _current


def _load():
    eng = _current_engine()
    return eng.ffi, eng.lib


def use_engine(engine: Engine) -> EngineInfo:
    """Switch the process to a built-in engine variant and return its info."""
    global _current
    if not isinstance(engine, Engine):
        raise TypeError(
            "use_engine() expects an Engine member (Engine.WIDE / Engine.GO); "
            "use use_engine_file(path) for an explicit library"
        )
    _current = _resolve(engine)
    return _current.info()


def use_engine_file(path: str) -> EngineInfo:
    """Switch the process to an explicit engine shared object."""
    global _current
    _current = _load_file(path)
    return _current.info()


def current_engine() -> EngineInfo:
    """Info about the engine new sessions will use."""
    return _current_engine().info()


@contextmanager
def engine_context(engine: Engine):
    """Temporarily switch engines within a ``with`` block."""
    global _current
    previous = _current_engine()
    _current = _resolve(engine)
    try:
        yield _current.info()
    finally:
        _current = previous


_EXPECTED_ABI = 2


def abi_version() -> int:
    """The C-ABI version reported by the loaded engine."""
    ffi, lib = _load()
    return int(lib.freetls_abi_version())


def _cstr(ptr, eng: _Engine | None = None) -> str:
    """Read a C string returned by an engine and free it (avoids leaks).

    Pass ``eng`` when the pointer came from a specific engine (e.g. a session's)
    so it is freed by the same allocator even after an engine switch.
    """
    if eng is None:
        eng = _current_engine()
    text = eng.ffi.string(ptr).decode()
    eng.lib.freetls_free(ptr)
    return text


def version() -> str:
    ffi, lib = _load()
    return _cstr(lib.freetls_version())


def active_sessions() -> int:
    """Number of live native sessions (for leak tests)."""
    ffi, lib = _load()
    return int(lib.freetls_session_count())


def preset_list() -> list:
    """Names of the built-in uTLS ClientHello presets."""
    ffi, lib = _load()
    return json.loads(_cstr(lib.freetls_preset_list()) or "[]")


def preset_raw(name: str) -> bytes:
    """Build a preset's ClientHello offline; returns the raw handshake bytes."""
    ffi, lib = _load()
    s = _cstr(lib.freetls_preset_raw(name.encode()))
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
    s = _cstr(lib.freetls_preset_raw_opts(name.encode(), 1 if no_sni else 0, alpn_json))
    return bytes.fromhex(s) if s else b""


def chlo_raw(chlo_json: str) -> bytes:
    """Build a ClientHello offline from a uTLS ClientHelloSpec JSON document.

    Returns the raw handshake message bytes, or raises ``SpecError`` if the
    document is invalid/unsupported. No network is used.
    """
    ffi, lib = _load()
    s = _cstr(lib.freetls_chlo_raw(chlo_json.encode()))
    if not s:
        reason = _cstr(lib.freetls_aux_error()) or "invalid ClientHelloSpec JSON"
        raise SpecError(f"chlo_json: {reason}")
    return bytes.fromhex(s)


def spec_raw(spec: dict) -> bytes:
    """Build a ClientHello offline from an engine spec JSON (offline).

    Returns the raw handshake message bytes, or raises ``SpecError`` if the
    spec is invalid/unsupported. No network is used.
    """
    ffi, lib = _load()
    s = _cstr(lib.freetls_spec_raw(json.dumps(spec).encode()))
    if not s:
        reason = _cstr(lib.freetls_aux_error()) or "invalid spec"
        raise SpecError(f"spec: {reason}")
    return bytes.fromhex(s)


def supported_ciphers() -> list:
    """Cipher-suite IDs this engine can complete (native union libcrypto)."""
    ffi, lib = _load()
    return json.loads(_cstr(lib.freetls_supported_ciphers()) or "[]")


def supported_extensions() -> list:
    """Extension type IDs accepted by safe mode (the engine's whitelist)."""
    ffi, lib = _load()
    return json.loads(_cstr(lib.freetls_supported_extensions()) or "[]")


@dataclass
class EngineState:
    version: str = ""
    cipher_suite: int = 0
    alpn: str = ""
    server_name: str = ""
    peer_cert_b64: str = ""
    peer_certs_b64: list = field(default_factory=list)
    did_resume: bool = False
    ocsp_b64: str = ""
    sct_b64: list = field(default_factory=list)
    peer_alps_b64: str = ""
    error: str = ""

    @classmethod
    def from_json(cls, text: str) -> EngineState:
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
            peer_certs_b64=list(d.get("peer_certs_b64") or []),
            did_resume=bool(d.get("did_resume", False)),
            ocsp_b64=d.get("ocsp_response_b64", ""),
            sct_b64=list(d.get("sct_b64") or []),
            peer_alps_b64=d.get("peer_alps_b64", ""),
            error=d.get("error", ""),
        )

    @property
    def peer_cert_der(self) -> bytes:
        return _b64(self.peer_cert_b64)

    @property
    def peer_certs_der(self) -> list:
        return [_b64(x) for x in self.peer_certs_b64]

    @property
    def ocsp_response(self) -> bytes:
        return _b64(self.ocsp_b64)

    @property
    def signed_certificate_timestamps(self) -> list:
        return [_b64(x) for x in self.sct_b64]

    @property
    def peer_application_settings(self) -> bytes:
        return _b64(self.peer_alps_b64)


def _b64(text: str) -> bytes:
    import base64

    return base64.b64decode(text) if text else b""


class EngineSession:
    """Low-level handle to a single native TLS session."""

    def __init__(self, spec: dict):
        eng = _current_engine()
        self._engine = eng
        self._ffi = eng.ffi
        self._lib = eng.lib
        spec_json = json.dumps(spec).encode()
        self._handle = self._lib.freetls_session_new(spec_json)
        if self._handle <= 0:
            reason = _cstr(self._lib.freetls_aux_error(), eng) or "invalid spec"
            raise EngineError(f"freetls_session_new failed: {reason}")
        self._closed = False
        self._freed = False

    def handshake(self, fd: int, sni: str | None = None) -> None:
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
        s = _cstr(self._lib.freetls_get_client_hello(self._handle), self._engine)
        return bytes.fromhex(s) if s else b""

    def server_hello(self) -> bytes:
        s = _cstr(self._lib.freetls_get_server_hello(self._handle), self._engine)
        return bytes.fromhex(s) if s else b""

    def state(self) -> EngineState:
        s = _cstr(self._lib.freetls_get_state(self._handle), self._engine)
        return EngineState.from_json(s)

    def last_error(self) -> str:
        return _cstr(self._lib.freetls_last_error(self._handle), self._engine)

    def h2_request(self, req: dict) -> dict:
        """Perform an HTTP/2 request with full fingerprint control."""
        payload = json.dumps(req).encode()
        raw = _cstr(self._lib.freetls_h2_request(self._handle, payload), self._engine)
        return json.loads(raw or "{}")

    def close(self) -> None:
        if not self._closed and not self._freed:
            self._lib.freetls_close(self._handle)
            self._closed = True

    def set_timeout(self, ms: int) -> None:
        """Set the per-session I/O timeout in milliseconds (0 = none)."""
        self._lib.freetls_set_timeout(self._handle, int(ms))

    def free(self) -> None:
        if not self._freed:
            self._lib.freetls_session_free(self._handle)
            self._freed = True
            self._closed = True
