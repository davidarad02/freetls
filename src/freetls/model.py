"""Fingerprint specification model.

A :class:`FingerprintSpec` is a fully explicit description of the ClientHello
that will be emitted: cipher suite list, extension list (with arbitrary IDs and
data), supported TLS versions, SNI, ALPN, and verification settings. It maps
directly onto the native engine's JSON spec.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, cast

from .errors import SpecError

# TLS version wire constants.
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

# QUIC version wire constants (RFC 9000 / RFC 9369).
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF

# Library-wide default for certificate verification. Secure by default; tests
# and fingerprinting labs can opt out with set_default_verify(False).
DEFAULT_VERIFY = True


def set_default_verify(value: bool) -> None:
    """Set the default ``verify`` used when a spec leaves it unset."""
    global DEFAULT_VERIFY
    DEFAULT_VERIFY = bool(value)


def get_default_verify() -> bool:
    """Return the current default ``verify``."""
    return DEFAULT_VERIFY


# Library-wide default for safe mode. Unsafe by default (backward compatible);
# safe mode rejects specs whose effective ClientHello the engine cannot back.
DEFAULT_SAFE = False


def set_safe_mode(value: bool) -> None:
    """Set the default safe mode used when a spec leaves ``safe`` unset."""
    global DEFAULT_SAFE
    DEFAULT_SAFE = bool(value)


def get_safe_mode() -> bool:
    """Return the current default safe mode."""
    return DEFAULT_SAFE


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
    "record_size_limit",
    "pre_shared_key",
    "generic",
    "grease",
    "quic_transport_parameters",
}

# Transport-parameter kinds the engine can build as typed values; anything else
# must go through "fake" (an explicit id + value bytes).
_TP_VARINT_KINDS = {
    "max_idle_timeout",
    "max_udp_payload_size",
    "initial_max_data",
    "initial_max_stream_data_bidi_local",
    "initial_max_stream_data_bidi_remote",
    "initial_max_stream_data_uni",
    "initial_max_streams_bidi",
    "initial_max_streams_uni",
    "max_ack_delay",
    "active_connection_id_limit",
    "max_datagram_frame_size",
}

_TP_EMPTY_KINDS = {"disable_active_migration", "grease_quic_bit"}

_TP_KNOWN_KINDS = (
    _TP_VARINT_KINDS
    | _TP_EMPTY_KINDS
    | {
        "initial_source_connection_id",
        "version_information",
        "grease",
        "padding",
        "fake",
    }
)


@dataclass
class TransportParameter:
    """One QUIC transport parameter, carried in the ClientHello's ext 57.

    ``kind`` selects a typed parameter the engine knows how to encode; ``"fake"``
    escapes to an arbitrary id with verbatim value bytes (hex in ``data``), which
    is how vendor parameters such as Google's ``google_quic_version`` are sent.
    """

    kind: str
    id: int | None = None
    value: int | None = None
    data: str | None = None  # hex, verbatim value bytes
    length: int = 0  # for "grease"
    versions: list[int] = field(default_factory=list)  # version_information
    legacy: bool = False  # version_information: use the pre-RFC id

    def __post_init__(self) -> None:
        if self.kind not in _TP_KNOWN_KINDS:
            raise SpecError(f"unknown transport parameter kind: {self.kind!r}")
        if self.kind == "fake" and self.id is None:
            raise SpecError("fake transport parameter requires an id")
        if self.kind == "fake" and self.id == 0:
            raise SpecError("fake transport parameter id must be non-zero")
        if self.kind in _TP_VARINT_KINDS and self.value is None:
            raise SpecError(f"transport parameter {self.kind!r} requires a value")
        if self.id is not None:
            self.id = int(self.id)
        if self.value is not None:
            self.value = int(self.value)
        self.length = int(self.length)
        self.versions = [int(v) for v in self.versions]

    def to_engine(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        if self.id is not None:
            out["id"] = self.id
        if self.value is not None:
            out["value"] = self.value
        if self.data is not None:
            out["data"] = self.data
        if self.length:
            out["length"] = self.length
        if self.versions:
            out["versions"] = self.versions
        if self.legacy:
            out["legacy"] = True
        return out

    @classmethod
    def varint(cls, kind: str, value: int) -> TransportParameter:
        return cls(kind, value=value)

    @classmethod
    def grease(cls, length: int = 4) -> TransportParameter:
        return cls("grease", length=length)

    @classmethod
    def fake(cls, param_id: int, data: str = "") -> TransportParameter:
        return cls("fake", id=param_id, data=data)

    @classmethod
    def padding(cls, data: str = "") -> TransportParameter:
        return cls("padding", data=data)

    @classmethod
    def version_information(
        cls, chosen: int, *available: int, legacy: bool = False
    ) -> TransportParameter:
        return cls("version_information", value=chosen, versions=list(available), legacy=legacy)

    @classmethod
    def source_connection_id(cls, data: str = "") -> TransportParameter:
        return cls("initial_source_connection_id", data=data)


@dataclass
class QuicInitialSpec:
    """The QUIC Initial packet shape around the ClientHello.

    A spec with ``quic`` set is emitted over UDP as a QUIC Initial flight rather
    than as TLS records over TCP. The ClientHello itself still comes from
    ``ciphers``/``extensions`` (or a preset), with the transport parameters in
    the ``quic_transport_parameters`` extension.
    """

    version: int = QUIC_V1
    dcid_len: int = 8
    scid_len: int = 0
    token: str | None = None  # hex
    udp_datagram_min_size: int = 1200
    packet_number: int = 0
    packet_number_len: int = 1
    randomize_transport_parameters: bool = False
    suppress_transport_parameters: list[int] = field(default_factory=list)

    def to_engine(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": int(self.version),
            "dcid_len": int(self.dcid_len),
            "scid_len": int(self.scid_len),
            "udp_datagram_min_size": int(self.udp_datagram_min_size),
            "packet_number": int(self.packet_number),
            "packet_number_len": int(self.packet_number_len),
        }
        if self.token is not None:
            out["token"] = self.token
        if self.randomize_transport_parameters:
            out["randomize_transport_parameters"] = True
        if self.suppress_transport_parameters:
            out["suppress_transport_parameters"] = [
                int(p) for p in self.suppress_transport_parameters
            ]
        return out


def _copy_extension(e: Extension) -> Extension:
    """Deep-copy an Extension, keeping transport parameters as dataclasses.

    ``dataclasses.asdict`` would flatten nested ``TransportParameter`` objects
    into dicts, so they are lifted back out and rebuilt.
    """
    data = asdict(e)
    params = data.pop("transport_parameters", [])
    return Extension(**data, transport_parameters=[TransportParameter(**p) for p in params])


@dataclass
class Extension:
    """One ClientHello extension request.

    ``kind`` names a typed extension the engine understands, or ``"generic"``
    to inject an arbitrary extension type with raw bytes.
    """

    kind: str
    id: int | None = None
    data: str | None = None  # hex, for generic
    values: list[int] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    modes: list[int] = field(default_factory=list)
    points: list[int] = field(default_factory=list)
    server_name: str | None = None
    algorithms: list[int] = field(default_factory=list)
    # QUIC transport parameters (kind "quic_transport_parameters").
    transport_parameters: list[TransportParameter] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.kind not in _KNOWN_KINDS:
            raise SpecError(f"unknown extension kind: {self.kind!r}")
        if self.kind == "generic" and self.id is None:
            raise SpecError("generic extension requires an id")
        self.transport_parameters = [
            p if isinstance(p, TransportParameter) else TransportParameter(**p)
            for p in self.transport_parameters
        ]
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
        if self.values and self.kind != "padding":
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
        if self.kind == "padding" and self.values:
            out["padding_len"] = self.values[0]
        if self.transport_parameters:
            out["transport_parameters"] = [p.to_engine() for p in self.transport_parameters]
        return out

    # Convenience constructors -------------------------------------------------
    @classmethod
    def sni(cls, host: str) -> Extension:
        return cls("sni", server_name=host)

    @classmethod
    def alpn(cls, *protocols: str) -> Extension:
        return cls("alpn", strings=list(protocols))

    @classmethod
    def supported_versions(cls, *versions: int) -> Extension:
        return cls("supported_versions", values=list(versions))

    @classmethod
    def supported_curves(cls, *groups: int | str) -> Extension:
        return cls("supported_curves", values=cast("list[int]", list(groups)))

    @classmethod
    def ec_point_formats(cls, *points: int) -> Extension:
        return cls("ec_point_formats", points=list(points))

    @classmethod
    def signature_algorithms(cls, *algs: int | str) -> Extension:
        return cls("signature_algorithms", values=cast("list[int]", list(algs)))

    @classmethod
    def key_share(cls, *groups: int | str) -> Extension:
        return cls("key_share", values=cast("list[int]", list(groups)))

    @classmethod
    def psk_key_exchange_modes(cls, *modes: int) -> Extension:
        return cls("psk_key_exchange_modes", modes=list(modes))

    @classmethod
    def generic(cls, ext_id: int, data: str = "") -> Extension:
        return cls("generic", id=ext_id, data=data)

    @classmethod
    def padding(cls, length: int | None = None) -> Extension:
        """Padding extension (0x0015). ``length`` fixes the byte count; None
        uses uTLS's Boring-style length heuristic."""
        return cls("padding", values=[] if length is None else [int(length)])

    @classmethod
    def record_size_limit(cls, limit: int = 0) -> Extension:
        """record_size_limit extension (0x001C)."""
        return cls("record_size_limit", values=[int(limit)])

    @classmethod
    def pre_shared_key(cls) -> Extension:
        """Empty pre_shared_key (0x0029) placeholder for TLS 1.3 resumption.

        uTLS fills the identities/binders from the shared session cache; place
        it last in the extension list. Requires ``FingerprintSpec.session_cache``.
        """
        return cls("pre_shared_key")

    @classmethod
    def application_settings(cls, *protocols: str) -> Extension:
        """ALPS application_settings extension (0x4469)."""
        return cls("application_settings", strings=list(protocols))

    @classmethod
    def quic_transport_parameters(cls, *params: TransportParameter) -> Extension:
        """QUIC transport parameters (ext 0x0039), in wire order.

        Required in a QUIC ClientHello. Order is itself a fingerprinting signal
        (real clients differ), so the list is emitted verbatim.
        """
        return cls("quic_transport_parameters", transport_parameters=list(params))

    @classmethod
    def grease(cls, value: int | None = None) -> Extension:
        """A GREASE extension slot. ``value`` selects a specific GREASE code
        point (one of the 16 reserved values); None emits uTLS's random GREASE.
        """
        if value is None:
            return cls("grease")
        return cls("generic", id=int(value), data="")


@dataclass
class FingerprintSpec:
    """A complete ClientHello specification."""

    ciphers: list[int] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    vers_min: int = TLS12
    vers_max: int = TLS13
    server_name: str | None = None
    # None => use the library default (secure: True). See set_default_verify().
    verify: bool | None = None
    # None => use the library default (unsafe). See set_safe_mode().
    safe: bool | None = None
    # Permit anonymous (ADH) cipher suites, which provide no server
    # authentication. Off by default.
    anonymous: bool = False
    # TLS 1.2 PSK credentials (RFC 4279). ``psk`` is hex-encoded. Both must be
    # set to use the PSK/ECDHE-PSK/DHE-PSK/RSA-PSK cipher suites.
    psk_identity: str | None = None
    psk: str | None = None
    # TLS 1.2 SRP credentials (RFC 5054).
    srp_username: str | None = None
    srp_password: str | None = None
    root_ca: str | None = None
    timeout_ms: int = 30000

    # Certificate suite (verification, trust, pinning, mTLS).
    check_hostname: bool | None = None  # None => True
    system_roots: bool | None = None  # None => True
    ca_dir: str | None = None  # directory of PEM certs
    cadata: str | None = None  # inline PEM bundle
    client_cert: str | None = None  # mTLS cert PEM file
    client_key: str | None = None  # mTLS key PEM file
    client_cert_pem: str | None = None  # mTLS cert PEM text
    client_key_pem: str | None = None  # mTLS key PEM text
    pinned_sha256: list | None = None  # base64 sha256 of leaf DER or SPKI

    # ClientHello legacy compression methods. None leaves uTLS's default
    # (null compression); [] sends an explicit empty list; [0] is the classic
    # "null" method.
    compression: list | None = None
    # Enable TLS resumption through the shared engine session cache (capacity).
    # None/0 disables resumption.
    session_cache: int | None = None

    # Built-in uTLS preset (used instead of ciphers/extensions when set).
    preset: str | None = None
    preset_no_sni: bool = False
    # None = leave the preset's ALPN untouched; [] = remove ALPN; list = set it.
    preset_alpn: list | None = None

    # A uTLS ClientHelloSpec JSON document (see README "Custom presets"). When
    # set it fully describes the ClientHello and takes precedence over
    # ``preset`` and ``ciphers``/``extensions``.
    chlo_json: str | None = None

    # HTTP/2 fingerprint controls (applied by TLSSession.h2_request / the
    # HTTP/2 transport). ``h2_settings`` is an ordered list of [id, value].
    h2_settings: list | None = None
    h2_window_update: int = 0
    h2_pseudo_header_order: list | None = None

    # QUIC / HTTP-3 (see docs/route-c-plan.md). When ``quic`` is set the spec is
    # emitted as a QUIC Initial flight over UDP instead of TLS records over TCP.
    quic: QuicInitialSpec | None = None
    # A built-in uQUIC preset name (e.g. "QUICChrome_146_IPv4"), used instead of
    # ciphers/extensions when set.
    quic_id: str | None = None
    # Reserved for the deferred 0-RTT work; not yet honoured by the engine.
    quic_early_data: bool = False
    # Enable RFC 9297 HTTP/3 datagrams (RFC 9221 QUIC datagrams). Off by default:
    # a datagram-enabled client requires the peer to support QUIC datagrams.
    quic_datagrams: bool = False

    def __post_init__(self) -> None:
        if self.verify is None:
            self.verify = DEFAULT_VERIFY

    def to_engine(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ciphers": list(self.ciphers),
            "vers_min": self.vers_min,
            "vers_max": self.vers_max,
            "server_name": self.server_name or "",
            "verify": self.verify,
            "anonymous": self.anonymous,
            "psk_identity": self.psk_identity or "",
            "psk": self.psk or "",
            "srp_username": self.srp_username or "",
            "srp_password": self.srp_password or "",
            "root_ca": self.root_ca or "",
            "timeout_ms": self.timeout_ms,
            "extensions": [e.to_engine() for e in self.extensions],
        }
        if self.preset is not None:
            out["preset"] = self.preset
        # The preset_no_sni / preset_alpn overrides also apply to QUIC presets
        # (quic_id), where there is no `preset`.
        if self.preset is not None or self.quic_id is not None:
            out["preset_no_sni"] = self.preset_no_sni
            if self.preset_alpn is not None:
                if len(self.preset_alpn) == 0:
                    out["preset_alpn_remove"] = True
                else:
                    out["preset_alpn"] = list(self.preset_alpn)
        if self.chlo_json is not None:
            out["chlo_json"] = self.chlo_json
        # Certificate suite options (only when set, to keep the JSON small).
        if self.check_hostname is not None:
            out["check_hostname"] = self.check_hostname
        if self.system_roots is not None:
            out["system_roots"] = self.system_roots
        for name in (
            "ca_dir",
            "cadata",
            "client_cert",
            "client_key",
            "client_cert_pem",
            "client_key_pem",
        ):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.pinned_sha256:
            out["pinned_sha256"] = list(self.pinned_sha256)
        if self.compression is not None:
            out["compression"] = list(self.compression)
        if self.session_cache:
            out["session_cache"] = int(self.session_cache)
        if self.quic is not None:
            out["transport"] = "quic"
            out["quic"] = self.quic.to_engine()
        if self.quic_id is not None:
            out["transport"] = "quic"
            out["quic_id"] = self.quic_id
        if self.quic_early_data:
            out["quic_early_data"] = True
        if self.quic_datagrams:
            out["quic_datagrams"] = True
        return out

    def find(self, kind: str) -> Extension | None:
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

    def copy(self) -> FingerprintSpec:
        return FingerprintSpec(
            ciphers=list(self.ciphers),
            extensions=[_copy_extension(e) for e in self.extensions],
            vers_min=self.vers_min,
            vers_max=self.vers_max,
            server_name=self.server_name,
            verify=self.verify,
            safe=self.safe,
            anonymous=self.anonymous,
            psk_identity=self.psk_identity,
            psk=self.psk,
            srp_username=self.srp_username,
            srp_password=self.srp_password,
            root_ca=self.root_ca,
            timeout_ms=self.timeout_ms,
            check_hostname=self.check_hostname,
            system_roots=self.system_roots,
            ca_dir=self.ca_dir,
            cadata=self.cadata,
            client_cert=self.client_cert,
            client_key=self.client_key,
            client_cert_pem=self.client_cert_pem,
            client_key_pem=self.client_key_pem,
            pinned_sha256=None if self.pinned_sha256 is None else list(self.pinned_sha256),
            compression=None if self.compression is None else list(self.compression),
            session_cache=self.session_cache,
            preset=self.preset,
            preset_no_sni=self.preset_no_sni,
            preset_alpn=None if self.preset_alpn is None else list(self.preset_alpn),
            chlo_json=self.chlo_json,
            h2_settings=None if self.h2_settings is None else [list(s) for s in self.h2_settings],
            h2_window_update=self.h2_window_update,
            h2_pseudo_header_order=(
                None if self.h2_pseudo_header_order is None else list(self.h2_pseudo_header_order)
            ),
            quic=(
                None
                if self.quic is None
                else replace(
                    self.quic,
                    suppress_transport_parameters=list(self.quic.suppress_transport_parameters),
                )
            ),
            quic_id=self.quic_id,
            quic_early_data=self.quic_early_data,
            quic_datagrams=self.quic_datagrams,
        )
