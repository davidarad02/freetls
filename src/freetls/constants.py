"""Named constants for the IANA TLS value universe.

These are real, importable ``IntEnum`` classes built from the committed IANA
tables, so you can write readable specs instead of raw hex:

    from freetls import Cipher, SignatureScheme, NamedGroup

    modes.specific(ciphers=[Cipher.TLS_AES_128_GCM_SHA256, Cipher.TLS_AES_256_GCM_SHA384])
    Extension.signature_algorithms(SignatureScheme.RSA_PSS_RSAE_SHA256)
    Extension.supported_curves(NamedGroup.X25519, NamedGroup.SECP256R1)

Every member is also just an ``int`` (so ``0x1301`` and
``Cipher.TLS_AES_128_GCM_SHA256`` are interchangeable), and lookups work by name
string or value: ``Cipher["TLS_AES_128_GCM_SHA256"]``, ``Cipher(0x1301)``.
"""
from __future__ import annotations

import re
from enum import IntEnum

from .fingerprint import tables

__all__ = [
    "Cipher",
    "ExtensionType",
    "SignatureScheme",
    "NamedGroup",
    "cipher_id",
    "extension_id",
    "sigalg_id",
    "group_id",
]


def _ident(text: str, *, upper: bool = True) -> str:
    """Turn an IANA display name into a valid Python identifier."""
    text = text.split("(")[0].strip()  # drop parentheticals like "(renamed from ...)"
    text = re.sub(r"[^0-9A-Za-z]+", "_", text).strip("_")
    if upper:
        text = text.upper()
    if text and text[0].isdigit():
        text = "_" + text
    return text


def _build(enum_name: str, entries, *, upper: bool = True, aliases=None) -> IntEnum:
    members: dict[str, int] = {}
    for e in entries:
        value = int(e["value"])
        name = _ident(e["name"], upper=upper)
        if not name:
            name = f"VALUE_{value:04X}"
        if name in members:
            name = f"{name}_{value:04X}"
        members[name] = value
    for alias, value in (aliases or {}).items():
        members.setdefault(alias, int(value))
    return IntEnum(enum_name, members, module=__name__)


#: Cipher suites, e.g. ``Cipher.TLS_AES_128_GCM_SHA256`` (== 0x1301).
Cipher = _build("Cipher", tables.CIPHERS)

#: Extension types, e.g. ``ExtensionType.SERVER_NAME`` and the short aliases
#: ``ExtensionType.SNI`` and ``ExtensionType.ALPN``.
ExtensionType = _build(
    "ExtensionType",
    tables.EXTENSIONS,
    aliases={"SNI": 0x0000, "ALPN": 0x0010},
)

#: Signature schemes, e.g. ``SignatureScheme.RSA_PSS_RSAE_SHA256`` (== 0x0804).
SignatureScheme = _build("SignatureScheme", tables.SIGALGS)

#: Named groups / supported curves, e.g. ``NamedGroup.X25519`` (== 0x001d).
NamedGroup = _build("NamedGroup", tables.GROUPS)


def cipher_id(value) -> int:
    """Resolve an int, enum member, or (case-insensitive) name to a cipher ID."""
    return tables.as_cipher(value)


def extension_id(value) -> int:
    """Resolve an int, enum member, or (case-insensitive) name to an extension ID."""
    return tables.as_extension(value)


def sigalg_id(value) -> int:
    """Resolve an int, enum member, or name to a signature-scheme ID."""
    return tables.as_sigalg(value)


def group_id(value) -> int:
    """Resolve an int, enum member, or name to a named-group ID."""
    return tables.as_group(value)
