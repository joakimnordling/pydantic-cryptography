"""JWK (RFC 7517) representations of `cryptography` keys, and their thumbprints (RFC 7638)."""

import json
from base64 import urlsafe_b64encode
from hashlib import sha256
from typing import TYPE_CHECKING, Annotated, Literal, NamedTuple, Self, TypeAlias

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurve,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from ._kinds import KindName, SupportedPublicKey, kind_of

if TYPE_CHECKING:  # (_keys imports this module)
    from ._keys import PrivateKey, PublicKey

# The JWA algorithms ("alg") that the supported keys can be used with, from the IANA JOSE registry
# (a test checks that they match the tables below). Left out: RSA1_5 (insecure) and the symmetric
# ones.
AlgName: TypeAlias = Literal[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "Ed25519",
    "Ed448",
    "EdDSA",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "HPKE-0",
    "HPKE-1",
    "HPKE-2",
    "HPKE-3",
    "HPKE-4",
    "HPKE-5",
    "HPKE-6",
    "HPKE-7",
    "HPKE-0-KE",
    "HPKE-1-KE",
    "HPKE-2-KE",
    "HPKE-3-KE",
    "HPKE-5-KE",
    "HPKE-7-KE",
]

_ECDH: tuple[AlgName, ...] = (
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
)

# The algorithms of each kind of key other than EC; the first one is the default.
ALGS: dict[KindName, tuple[AlgName, ...]] = {
    "RSA": (
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA-OAEP-384",
        "RSA-OAEP-512",
    ),
    # EdDSA is deprecated by RFC 9864, but PyJWT (as of 2.15) only knows EdDSA, not Ed25519 and
    # Ed448: https://github.com/jpadilla/pyjwt/issues/1190
    "Ed25519": (
        "Ed25519",
        "EdDSA",
    ),
    "Ed448": (
        "Ed448",
        "EdDSA",
    ),
    "X25519": (
        *_ECDH,
        "HPKE-3",
        "HPKE-4",
        "HPKE-3-KE",
    ),
    "X448": (
        *_ECDH,
        "HPKE-5",
        "HPKE-6",
        "HPKE-5-KE",
    ),
}


# The JWK "crv" of the EC curves (the IANA JOSE registry has no others), and the JWK "use"
ECCurveName: TypeAlias = Literal["P-256", "P-384", "P-521", "secp256k1"]
Use: TypeAlias = Literal["sig", "enc"]


class ECCurve(NamedTuple):
    """An EC curve with a JWK representation."""

    crv: ECCurveName
    algs: tuple[AlgName, ...]  # the first one is the default


# By cryptography's curve name. Other curves have no JWK representation (the keys refuse them).
EC_CURVES = {
    "secp256r1": ECCurve(
        crv="P-256",
        algs=(
            "ES256",
            *_ECDH,
            "HPKE-0",
            "HPKE-7",
            "HPKE-0-KE",
            "HPKE-7-KE",
        ),
    ),
    "secp384r1": ECCurve(
        crv="P-384",
        algs=(
            "ES384",
            *_ECDH,
            "HPKE-1",
            "HPKE-1-KE",
        ),
    ),
    "secp521r1": ECCurve(
        crv="P-521",
        algs=(
            "ES512",
            *_ECDH,
            "HPKE-2",
            "HPKE-2-KE",
        ),
    ),
    "secp256k1": ECCurve(
        crv="secp256k1",
        algs=("ES256K",),
    ),
}

# The algorithms that encrypt (the JWK "use" is "enc"); the others sign ("sig").
_ENCRYPTION_ALG_PREFIXES = (
    "RSA-OAEP",
    "ECDH-ES",
    "HPKE-",
)


def b64url(data: bytes) -> str:
    """Base64url encoding without padding (RFC 7515 section 2)."""
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _uint(value: int, length: int | None = None) -> str:
    """
    An unsigned integer as base64url, big-endian.

    Without `length`, in as few octets as possible (RFC 7518 section 2, for the RSA members);
    otherwise padded to `length` octets (for the EC members, whose length is set by the curve).
    """
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return b64url(value.to_bytes(length, "big"))


def _ec_size(curve: EllipticCurve) -> int:
    return (curve.key_size + 7) // 8


def public_members(key: SupportedPublicKey) -> dict[str, str]:
    """
    The JWK members of the public key: "kty" and the key's parameters, nothing else.

    These are exactly the members the thumbprint is computed from (RFC 7638 section 3.2).
    """
    if isinstance(key, RSAPublicKey):
        numbers = key.public_numbers()
        return {
            "kty": "RSA",
            "n": _uint(numbers.n),
            "e": _uint(numbers.e),
        }
    if isinstance(key, EllipticCurvePublicKey):
        crv = EC_CURVES[key.curve.name].crv
        size = _ec_size(key.curve)
        ec_numbers = key.public_numbers()
        return {
            "kty": "EC",
            "crv": crv,
            "x": _uint(ec_numbers.x, size),
            "y": _uint(ec_numbers.y, size),
        }
    return {
        "kty": "OKP",
        "crv": kind_of(key).name,
        "x": b64url(key.public_bytes_raw()),
    }


def thumbprint(key: SupportedPublicKey) -> str:
    """The SHA-256 JWK thumbprint of the key (RFC 7638), base64url encoded."""
    canonical = json.dumps(public_members(key), sort_keys=True, separators=(",", ":"))
    return b64url(sha256(canonical.encode("utf-8")).digest())


def algs(key: SupportedPublicKey) -> tuple[AlgName, ...]:
    """The JWA algorithms the key can be used with; the first one is the default."""
    if isinstance(key, EllipticCurvePublicKey):
        return EC_CURVES[key.curve.name].algs
    return ALGS[kind_of(key).name]


def kind_algs(kind: KindName) -> frozenset[AlgName]:
    """The algorithms a kind of key can be used with; for EC, with any of the curves."""
    if kind == "EC":
        return frozenset(alg for curve in EC_CURVES.values() for alg in curve.algs)
    return frozenset(ALGS[kind])


def use(alg: AlgName) -> Use:
    """The JWK "use" of a key used with the algorithm: "enc" or "sig"."""
    return "enc" if alg.startswith(_ENCRYPTION_ALG_PREFIXES) else "sig"


# The algorithms of each JWK key type; a test checks that they match the tables above.
RSAAlgName: TypeAlias = Literal[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA-OAEP-384",
    "RSA-OAEP-512",
]
ECAlgName: TypeAlias = Literal[
    "ES256",
    "ES384",
    "ES512",
    "ES256K",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "HPKE-0",
    "HPKE-1",
    "HPKE-2",
    "HPKE-7",
    "HPKE-0-KE",
    "HPKE-1-KE",
    "HPKE-2-KE",
    "HPKE-7-KE",
]
OKPAlgName: TypeAlias = Literal[
    "Ed25519",
    "Ed448",
    "EdDSA",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "HPKE-3",
    "HPKE-4",
    "HPKE-5",
    "HPKE-6",
    "HPKE-3-KE",
    "HPKE-5-KE",
]


_Kid: TypeAlias = Annotated[
    str, Field(description="The key ID: the key's SHA-256 JWK thumbprint (RFC 7638)")
]


class _PublicJWK(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RSAPublicJWK(_PublicJWK):
    """The JWK of an RSA public key."""

    kty: Literal["RSA"]
    kid: _Kid
    use: Use
    alg: RSAAlgName
    n: str
    e: str


class ECPublicJWK(_PublicJWK):
    """The JWK of an EC public key."""

    kty: Literal["EC"]
    kid: _Kid
    use: Use
    alg: ECAlgName
    crv: ECCurveName
    x: str
    y: str


class OKPPublicJWK(_PublicJWK):
    """The JWK of an Ed25519, Ed448, X25519 or X448 public key (RFC 8037)."""

    kty: Literal["OKP"]
    kid: _Kid
    use: Use
    alg: OKPAlgName
    crv: Literal["Ed25519", "Ed448", "X25519", "X448"]
    x: str


PublicJWK: TypeAlias = Annotated[
    RSAPublicJWK | ECPublicJWK | OKPPublicJWK, Field(discriminator="kty")
]


class JWKS(BaseModel):
    """A JWK Set (RFC 7517 section 5) of public keys, e.g. for a `jwks.json` endpoint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    keys: list[PublicJWK]

    @classmethod
    def from_keys(cls, *keys: "PrivateKey | PublicKey | None") -> Self:
        """
        The JWK Set of the public keys of the keys.

        None is skipped, so that an optional setting (like the previous key during a key rotation)
        can be passed as is, and so are repeats. The same key with two different algorithms is
        refused.
        """
        by_kid: dict[str, PublicJWK] = {}
        for key in keys:
            if key is None:
                continue
            if by_kid.setdefault(key.kid, key.public_jwk) != key.public_jwk:
                raise ValueError(f"two different JWKs with the kid {key.kid!r}")
        return cls(keys=list(by_kid.values()))


PUBLIC_JWK_ADAPTER: TypeAdapter[PublicJWK] = TypeAdapter(PublicJWK)
