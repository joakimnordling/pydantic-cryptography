"""JWKs, thumbprints (kid) and JWK Sets, checked against the RFC examples and against joserfc."""

import json
from base64 import urlsafe_b64decode

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from joserfc import jwt
from joserfc.jwk import ECKey, JWKRegistry, OKPKey, RSAKey

from pydantic_cryptography import (
    JWKS,
    ECPublicJWK,
    OKPPublicJWK,
    PrivateKey,
    PublicKey,
    RSAPublicJWK,
)
from tests.helpers import TEST_KEYS, private_key, private_pem

DEFAULTS = {  # test key: (kty, use, alg)
    "rsa": ("RSA", "sig", "RS256"),
    "p256": ("EC", "sig", "ES256"),
    "p384": ("EC", "sig", "ES384"),
    "p521": ("EC", "sig", "ES512"),
    "secp256k1": ("EC", "sig", "ES256K"),
    "ed25519": ("OKP", "sig", "Ed25519"),
    "ed448": ("OKP", "sig", "Ed448"),
    "x25519": ("OKP", "enc", "ECDH-ES"),
    "x448": ("OKP", "enc", "ECDH-ES"),
}


def b64url_decode_int(value: str) -> int:
    return int.from_bytes(urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def test_rfc7638_example() -> None:
    """The example in RFC 7638 section 3.1."""
    n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
        "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY"
        "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f"
        "M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    )
    key = PublicKey(RSAPublicNumbers(e=65537, n=b64url_decode_int(n)).public_key())
    assert key.kid == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    assert key.public_jwk == RSAPublicJWK(
        kty="RSA",
        kid="NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
        use="sig",
        alg="RS256",
        n=n,
        e="AQAB",
    )
    assert key.public_jwk.model_dump() == {
        "kty": "RSA",
        "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
        "use": "sig",
        "alg": "RS256",
        "n": n,
        "e": "AQAB",
    }


def without_kid_use_and_alg(jwk: dict[str, str]) -> dict[str, str]:
    """The JWK as in the RFC examples and from joserfc, which don't add these optional members."""
    return {name: value for name, value in jwk.items() if name not in {"kid", "use", "alg"}}


def test_rfc8037_example() -> None:
    """The Ed25519 examples in RFC 8037 appendix A."""
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    key = PrivateKey(Ed25519PrivateKey.from_private_bytes(seed))
    assert key.kid == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    assert without_kid_use_and_alg(key.public_jwk.model_dump()) == {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }


@pytest.mark.parametrize("name", TEST_KEYS)
def test_same_as_joserfc(name: str) -> None:
    key = PrivateKey.load(private_pem(name))
    key_classes: dict[str, type[RSAKey | ECKey | OKPKey]] = {
        "RSA": RSAKey,
        "EC": ECKey,
        "OKP": OKPKey,
    }
    reference = key_classes[key.kty].import_key(private_pem(name))
    assert key.kid == reference.thumbprint()
    public = reference.as_dict(private=False)
    assert without_kid_use_and_alg(key.public_jwk.model_dump()) == public
    assert without_kid_use_and_alg(key.public_key().public_jwk.model_dump()) == public


@pytest.mark.parametrize("name", [name for name in TEST_KEYS if DEFAULTS[name][1] == "sig"])
def test_default_alg_signs_with_joserfc(name: str) -> None:
    """The default alg is a real JOSE algorithm: sign with it, and verify with the published JWK."""
    key = PrivateKey(private_key(name))
    private = JWKRegistry.import_key(key.private_pem, key.kty)
    token = jwt.encode({"alg": key.alg}, {"sub": "x"}, private, algorithms=[key.alg])
    public = JWKRegistry.import_key(JWKS.from_keys(key).keys[0].model_dump())
    assert jwt.decode(token, public, algorithms=[key.alg]).claims == {"sub": "x"}


@pytest.mark.parametrize("name", TEST_KEYS)
def test_defaults(name: str) -> None:
    key = PrivateKey(private_key(name))
    kty, use, alg = DEFAULTS[name]
    assert (key.kty, key.alg) == (kty, alg)
    assert key.public_jwk == key.public_key().public_jwk
    jwk = key.public_jwk
    assert (jwk.kty, jwk.kid, jwk.use, jwk.alg) == (kty, key.kid, use, alg)
    assert "d" not in key.public_jwk.model_dump()


def test_member_order() -> None:
    key = PrivateKey(private_key("rsa"))
    assert list(key.public_jwk.model_dump()) == ["kty", "kid", "use", "alg", "n", "e"]


def test_ec_members_have_the_curve_size() -> None:
    """EC coordinates are always as long as the curve needs, even with leading zeros."""
    # the private value 1 gives the curve's generator point, whose x starts with a zero octet
    key = PrivateKey(ec.derive_private_key(1, ec.SECP521R1()))
    jwk = key.public_jwk
    assert isinstance(jwk, ECPublicJWK)
    assert jwk.x.startswith("AM")  # base64url of 0x00 0xc6, the first two octets
    assert len(jwk.x) == len(jwk.y) == 88  # 66 octets


def test_jwks() -> None:
    new = PrivateKey(private_key("rsa"))
    old = PublicKey(private_key("p256").public_key())
    ed = PrivateKey(private_key("ed25519"))
    published = JWKS.from_keys(new, None, old, ed)
    assert published == JWKS(keys=[new.public_jwk, old.public_jwk, ed.public_jwk])
    assert [type(jwk) for jwk in published.keys] == [RSAPublicJWK, ECPublicJWK, OKPPublicJWK]
    assert JWKS.from_keys() == JWKS(keys=[])


def test_jwks_skips_repeats() -> None:
    """E.g. during a key rotation, when the previous key is the current one."""
    key = PrivateKey(private_key("rsa"))
    assert JWKS.from_keys(key, key.public_key(), key).keys == [key.public_jwk]


def test_jwks_json() -> None:
    key = PrivateKey(private_key("ed25519"))
    assert json.loads(JWKS.from_keys(key).model_dump_json()) == {
        "keys": [key.public_jwk.model_dump()]
    }
