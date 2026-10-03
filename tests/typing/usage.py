"""
Type-checking tests for code that uses the package; this file is checked, never run.

Every line marked `# type: ignore` must produce an error: the checkers are configured to report
unused ignore comments, so a planted error that stops being detected fails the check.
"""

from typing import Annotated, Literal, assert_type

from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import BaseModel

from pydantic_cryptography import (
    JWKS,
    Alg,
    AlgName,
    KindName,
    PrivateKey,
    PublicJWK,
    PublicKey,
    RSAPublicJWK,
)

AnyPrivateKey = (
    RSAPrivateKey
    | EllipticCurvePrivateKey
    | Ed25519PrivateKey
    | Ed448PrivateKey
    | X25519PrivateKey
    | X448PrivateKey
)

DEV_KEY = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"


class Settings(BaseModel):
    signing_key: PrivateKey[RSAPrivateKey] = PrivateKey.load(DEV_KEY, "RSA")
    any_key: PrivateKey
    ec_or_rsa: PrivateKey[RSAPrivateKey | EllipticCurvePrivateKey]
    partner_key: PublicKey[Ed25519PublicKey] | None = None
    wrong_default: PrivateKey[RSAPrivateKey] = PrivateKey.load(DEV_KEY, "EC")  # type: ignore
    rs512_key: Annotated[PrivateKey[RSAPrivateKey], Alg("RS512")]
    eddsa_key: Annotated[PublicKey[Ed25519PublicKey], Alg("EdDSA")] | None = None


def use(settings: Settings) -> None:
    key = settings.signing_key
    assert_type(settings.rs512_key, PrivateKey[RSAPrivateKey])
    assert_type(key.key, RSAPrivateKey)
    assert_type(key.public_key(), PublicKey[RSAPublicKey])
    assert_type(key.public_key().key, RSAPublicKey)
    assert_type(key.kid, str)
    assert_type(key.alg, AlgName)
    assert_type(key.kty, Literal["RSA", "EC", "OKP"])
    assert_type(key.public_jwk, PublicJWK)
    if isinstance(key.public_jwk, RSAPublicJWK):
        assert_type(key.public_jwk.n, str)
    n = key.public_jwk.n  # type: ignore  # only an RSA JWK has n
    assert_type(key.private_pem, str)
    assert_type(key.public_pem, str)

    assert_type(settings.any_key.key, AnyPrivateKey)
    assert_type(settings.ec_or_rsa.key, RSAPrivateKey | EllipticCurvePrivateKey)
    if settings.partner_key is not None:
        assert_type(settings.partner_key.key, Ed25519PublicKey)

    assert_type(JWKS.from_keys(key, settings.partner_key), JWKS)
    JWKS.from_keys(key.public_jwk)  # type: ignore  # only keys

    # a key of a narrower kind is a key of a wider one
    wider: PrivateKey = key
    narrower: PrivateKey[Ed25519PrivateKey] = key  # type: ignore
    print(wider, narrower)


def construct() -> None:
    assert_type(PrivateKey(Ed25519PrivateKey.generate()), PrivateKey[Ed25519PrivateKey])
    assert_type(PrivateKey(Ed25519PrivateKey.generate()).public_key(), PublicKey[Ed25519PublicKey])
    assert_type(PrivateKey.load(DEV_KEY), PrivateKey)
    assert_type(PrivateKey.load(DEV_KEY, "EC"), PrivateKey[EllipticCurvePrivateKey])
    assert_type(PublicKey.load(DEV_KEY, "EC").key, EllipticCurvePublicKey)
    PrivateKey.load(DEV_KEY, "DSA")  # type: ignore
    assert_type(PrivateKey.load(DEV_KEY, "RSA", alg="PS256"), PrivateKey[RSAPrivateKey])
    assert_type(PublicKey.load(DEV_KEY, alg="ECDH-ES"), PublicKey)
    PrivateKey.load(DEV_KEY, "RSA", alg="PS1024")  # type: ignore
    Alg("RS1024")  # type: ignore
    PrivateKey.load(DEV_KEY, "RSA", "RS512")  # type: ignore  # alg is keyword-only
    assert_type(PrivateKey(Ed25519PrivateKey.generate(), "EdDSA"), PrivateKey[Ed25519PrivateKey])
    PublicKey(Ed25519PrivateKey.generate())  # type: ignore


def unsupported(key: DSAPrivateKey) -> None:
    PrivateKey(key)  # type: ignore


class Invalid(BaseModel):
    dsa: PrivateKey[DSAPrivateKey]  # type: ignore
    wrong_side: PublicKey[RSAPrivateKey]  # type: ignore


def from_config(kind: KindName, alg: AlgName, text: str) -> None:
    """A kind and an algorithm known only at runtime, e.g. from your own config."""
    assert_type(PrivateKey.load(DEV_KEY, kind, alg=alg), PrivateKey)
    assert_type(PublicKey.load(DEV_KEY, kind), PublicKey)
    PrivateKey.load(DEV_KEY, alg=text)  # type: ignore  # a str isn't an AlgName
