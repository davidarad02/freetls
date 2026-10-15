"""Fingerprint specification model.

A :class:`FingerprintSpec` is a fully explicit description of the ClientHello
that will be emitted: cipher suite list, extension list (with arbitrary IDs and
data), supported TLS versions, SNI, ALPN, and verification settings. It maps
directly onto the native engine's JSON spec.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .errors import SpecError

# TLS version wire constants.
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

_KNOWN_KINDS = {
    "sni",
    "alpn",
    "supported_versions",
    "supported_curves",
    "ec_point_formats",
    "signature_algorithms",
    "key_share",
    "psk_key_exchange_modes",
    "extended_master_secret",
    "renegotiation_info",
    "session_ticket",
    "status_request",
    "sct",
    "compress_certificate",
    "padding",
    "application_settings",
    "generic",
    "grease",
}


@dataclass
class Extension:
    """One ClientHello extension request.

    ``kind`` names a typed extension the engine understands, or ``"generic"``
    to inject an arbitrary extension type with raw bytes.
    """

    kind: str
    id: Optional[int] = None
    data: Optional[str] = None  # hex, for generic
    values: list[int] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    modes: list[int] = field(default_factory=list)
    points: list[int] = field(default_factory=list)
    server_name: Optional[str] = None
    algorithms: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in _KNOWN_KINDS:
            raise SpecError(f"unknown extension kind: {self.kind!r}")
        if self.kind == "generic" and self.id is None:
            raise SpecError("generic extension requires an id")
        # Accept ints, IntEnum members, or names for the value lists.
        from .fingerprint.tables import as_group, as_sigalg

        coerce = {
            "supported_curves": as_group,
            "key_share": as_group,
            "signature_algorithms": as_sigalg,
        }.get(self.kind)
        if coerce is not None:
            self.values = [coerce(v) for v in self.values]
        else:
            self.values = [int(v) for v in self.values]
        self.points = [int(p) for p in self.points]
        self.modes = [int(m) for m in self.modes]
        if self.id is not None:
            self.id = int(self.id)

    def to_engine(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.kind}
        if self.id is not None:
            out["id"] = self.id
        if self.data is not None:
            out["data"] = self.data
        if self.values:
            out["values"] = self.values
        if self.strings:
            out["strings"] = self.strings
        if self.modes:
            out["modes"] = self.modes
        if self.points:
            out["points"] = self.points
        if self.server_name is not None:
            out["server_name"] = self.server_name
        if self.algorithms:
            out["algorithms"] = self.algorithms
        return out

    # Convenience constructors -------------------------------------------------
    @classmethod
    def sni(cls, host: str) -> "Extension":
        return cls("sni", server_name=host)

    @classmethod
    def alpn(cls, *protocols: str) -> "Extension":
        return cls("alpn", strings=list(protocols))

    @classmethod
    def supported_versions(cls, *versions: int) -> "Extension":
        return cls("supported_versions", values=list(versions))

    @classmethod
    def supported_curves(cls, *groups: int) -> "Extension":
        return cls("supported_curves", values=list(groups))

    @classmethod
    def ec_point_formats(cls, *points: int) -> "Extension":
        return cls("ec_point_formats", points=list(points))

    @classmethod
    def signature_algorithms(cls, *algs: int) -> "Extension":
        return cls("signature_algorithms", values=list(algs))

    @classmethod
    def key_share(cls, *groups: int) -> "Extension":
        return cls("key_share", values=list(groups))

    @classmethod
    def psk_key_exchange_modes(cls, *modes: int) -> "Extension":
        return cls("psk_key_exchange_modes", modes=list(modes))

    @classmethod
    def generic(cls, ext_id: int, data: str = "") -> "Extension":
        return cls("generic", id=ext_id, data=data)


@dataclass
class FingerprintSpec:
    """A complete ClientHello specification."""

    ciphers: list[int] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    vers_min: int = TLS12
    vers_max: int = TLS13
    server_name: Optional[str] = None
    verify: bool = True
    root_ca: Optional[str] = None
    timeout_ms: int = 30000

    # Built-in uTLS preset (used instead of ciphers/extensions when set).
    preset: Optional[str] = None
    preset_no_sni: bool = False
    # None = leave the preset's ALPN untouched; [] = remove ALPN; list = set it.
    preset_alpn: Optional[list] = None

    # HTTP/2 fingerprint controls (applied by TLSSession.h2_request / the
    # HTTP/2 transport). ``h2_settings`` is an ordered list of [id, value].
    h2_settings: Optional[list] = None
    h2_window_update: int = 0
    h2_pseudo_header_order: Optional[list] = None

    def to_engine(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ciphers": list(self.ciphers),
            "vers_min": self.vers_min,
            "vers_max": self.vers_max,
            "server_name": self.server_name or "",
            "verify": self.verify,
            "root_ca": self.root_ca or "",
            "timeout_ms": self.timeout_ms,
            "extensions": [e.to_engine() for e in self.extensions],
        }
        if self.preset is not None:
            out["preset"] = self.preset
            out["preset_no_sni"] = self.preset_no_sni
            if self.preset_alpn is not None:
                if len(self.preset_alpn) == 0:
                    out["preset_alpn_remove"] = True
                else:
                    out["preset_alpn"] = list(self.preset_alpn)
        return out

    def find(self, kind: str) -> Optional[Extension]:
        for e in self.extensions:
            if e.kind == kind:
                return e
        return None

    def replace_extension(self, new: Extension) -> None:
        for i, e in enumerate(self.extensions):
            if e.kind == new.kind:
                self.extensions[i] = new
                return
        self.extensions.append(new)

    def copy(self) -> "FingerprintSpec":
        return FingerprintSpec(
            ciphers=list(self.ciphers),
            extensions=[Extension(**asdict(e)) for e in self.extensions],
            vers_min=self.vers_min,
            vers_max=self.vers_max,
            server_name=self.server_name,
            verify=self.verify,
            root_ca=self.root_ca,
            timeout_ms=self.timeout_ms,
            preset=self.preset,
            preset_no_sni=self.preset_no_sni,
            preset_alpn=None if self.preset_alpn is None else list(self.preset_alpn),
            h2_settings=None if self.h2_settings is None else [list(s) for s in self.h2_settings],
            h2_window_update=self.h2_window_update,
            h2_pseudo_header_order=(
                None if self.h2_pseudo_header_order is None
                else list(self.h2_pseudo_header_order)
            ),
        )
