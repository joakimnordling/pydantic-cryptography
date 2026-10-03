"""The kinds of keys supported: RSA, EC, Ed25519, Ed448, X25519 and X448."""

from typing import Any, Literal, NamedTuple, TypeAlias

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

SupportedPrivateKey: TypeAlias = (
    RSAPrivateKey
    | EllipticCurvePrivateKey
    | Ed25519PrivateKey
    | Ed448PrivateKey
    | X25519PrivateKey
    | X448PrivateKey
)
SupportedPublicKey: TypeAlias = (
    RSAPublicKey
    | EllipticCurvePublicKey
    | Ed25519PublicKey
    | Ed448PublicKey
    | X25519PublicKey
    | X448PublicKey
)

# The names of the kinds of keys; a test checks that they match KEY_KINDS.
KindName: TypeAlias = Literal["RSA", "EC", "Ed25519", "Ed448", "X25519", "X448"]


class KeyKind(NamedTuple):
    """A kind of key, with its private and public key classes."""

    name: KindName  # for the OKP keys (RFC 8037), also the JWK "crv"
    private: type[SupportedPrivateKey]
    public: type[SupportedPublicKey]


KEY_KINDS = (
    KeyKind("RSA", RSAPrivateKey, RSAPublicKey),
    KeyKind("EC", EllipticCurvePrivateKey, EllipticCurvePublicKey),
    KeyKind("Ed25519", Ed25519PrivateKey, Ed25519PublicKey),
    KeyKind("Ed448", Ed448PrivateKey, Ed448PublicKey),
    KeyKind("X25519", X25519PrivateKey, X25519PublicKey),
    KeyKind("X448", X448PrivateKey, X448PublicKey),
)


def kind_of(key: SupportedPrivateKey | SupportedPublicKey) -> KeyKind:
    """The kind of the key."""
    return next(kind for kind in KEY_KINDS if isinstance(key, (kind.private, kind.public)))


def kinds_matching(classes: tuple[type[Any], ...]) -> list[KeyKind]:
    """The kinds of keys whose private or public key class is one of the classes (or a subclass)."""
    return [
        kind
        for kind in KEY_KINDS
        if issubclass(kind.private, classes) or issubclass(kind.public, classes)
    ]


def kind_by_name(name: KindName) -> KeyKind:
    """The kind of key with the name, e.g. "RSA"."""
    for kind in KEY_KINDS:
        if kind.name == name:
            return kind
    names = ", ".join(repr(kind.name) for kind in KEY_KINDS)
    raise ValueError(f"unknown kind of key {name!r}, expected one of {names}")
