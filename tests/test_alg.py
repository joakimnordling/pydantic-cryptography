"""The algorithm a key is used with: Alg(...) on a field, and alg to load() and the constructors."""

import copy
import pickle
import re
from typing import Annotated, Any, Generic, TypeVar, get_args

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x25519
from joserfc import jwt
from joserfc.jwk import JWKRegistry
from pydantic import BaseModel, ValidationError

from pydantic_cryptography import JWKS, Alg, KindName, PrivateKey, PublicKey, _jwk
from tests.helpers import (
    PRIVATE_FORMATS,
    PUBLIC_FORMATS,
    assert_not_shown,
    private_key,
    private_pem,
    public_pem,
)


class Keys(BaseModel):
    rs512: Annotated[PrivateKey[rsa.RSAPrivateKey], Alg("RS512")]
    oaep: Annotated[PublicKey[rsa.RSAPublicKey], Alg("RSA-OAEP-256")]
    eddsa: Annotated[PrivateKey[ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey], Alg("EdDSA")]
    es384: Annotated[PrivateKey[ec.EllipticCurvePrivateKey], Alg("ES384")]
    ecdh: Annotated[
        PrivateKey[ec.EllipticCurvePrivateKey | x25519.X25519PrivateKey], Alg("ECDH-ES+A128KW")
    ]


def valid_keys(**changes: Any) -> dict[str, Any]:
    return {
        "rs512": private_pem("rsa"),
        "oaep": public_pem("rsa"),
        "eddsa": private_pem("ed448"),
        "es384": private_pem("p384"),
        "ecdh": private_pem("x25519"),
        **changes,
    }


def test_alg_on_a_field() -> None:
    keys = Keys.model_validate(valid_keys())
    for key, alg, use in (
        (keys.rs512, "RS512", "sig"),
        (keys.oaep, "RSA-OAEP-256", "enc"),
        (keys.eddsa, "EdDSA", "sig"),
        (keys.es384, "ES384", "sig"),
        (keys.ecdh, "ECDH-ES+A128KW", "enc"),
    ):
        assert key.alg == alg
        assert (key.public_jwk.alg, key.public_jwk.use) == (alg, use)
    assert keys.rs512.public_key().alg == "RS512"
    assert repr(keys.rs512) == "PrivateKey(RSA 2048, alg=RS512)"
    # the key itself, and so the kid, is the same as without the algorithm
    assert keys.rs512.kid == PrivateKey(private_key("rsa")).kid


def test_alg_is_checked_against_the_curve() -> None:
    """For EC keys, when a key is loaded; the error doesn't show the key."""
    pem = private_pem("p256")
    with pytest.raises(ValidationError) as info:
        Keys.model_validate(valid_keys(es384=pem))
    assert [(error["loc"], error["msg"]) for error in info.value.errors()] == [
        (
            ("es384",),
            "Value error, ES384 isn't an algorithm for EC P-256 keys, expected one of ES256, "
            "ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-0, HPKE-7, "
            "HPKE-0-KE, HPKE-7-KE",
        )
    ]
    assert_not_shown(info.value, pem)


def test_the_fields_alg_wins() -> None:
    plain = PrivateKey(private_key("rsa"))
    rs384 = PrivateKey(private_key("rsa"), alg="RS384")
    rs512 = PrivateKey(private_key("rsa"), alg="RS512")
    for given in (plain, rs384, rs512):
        assert Keys.model_validate(valid_keys(rs512=given)).rs512 == rs512
    assert Keys.model_validate(valid_keys(rs512=rs512)).rs512 is rs512  # already right: as is
    public = PublicKey(private_key("rsa").public_key())
    assert Keys.model_validate(valid_keys(oaep=public)).oaep.alg == "RSA-OAEP-256"


@pytest.mark.parametrize(
    ("annotation", "error"),
    [
        pytest.param(
            Annotated[PrivateKey, Alg("RS512")],
            "Alg(name='RS512') doesn't fit EC, Ed25519, Ed448, X25519 or X448 keys, which the "
            "field allows",
            id="any-kind",
        ),
        pytest.param(
            Annotated[PublicKey[rsa.RSAPublicKey | ec.EllipticCurvePublicKey], Alg("RS512")],
            "Alg(name='RS512') doesn't fit EC keys, which the field allows",
            id="union",
        ),
        pytest.param(
            Annotated[
                PrivateKey[ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey], Alg("Ed25519")
            ],
            "Alg(name='Ed25519') doesn't fit Ed448 keys, which the field allows",
            id="ed25519-and-ed448",
        ),
        pytest.param(
            Annotated[int, Alg("RS512")],
            "Alg(name='RS512') only applies to a PrivateKey or PublicKey type",
            id="not-a-key",
        ),
        pytest.param(
            Annotated[
                PrivateKey[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] | None, Alg("RS512")
            ],
            "Alg(name='RS512') doesn't fit EC keys, which the field allows",
            id="optional",
        ),
        pytest.param(
            Annotated[list[PrivateKey[rsa.RSAPrivateKey]], Alg("RS512")],
            "Alg(name='RS512') only applies to a PrivateKey or PublicKey type",
            id="list",
        ),
    ],
)
def test_alg_must_fit_the_field(annotation: Any, error: str) -> None:
    """Checked when the model is defined, so that validation never fails on it."""
    with pytest.raises(TypeError, match=r"^" + re.escape(error)):

        class Model(BaseModel):
            key: annotation


def test_alg_on_an_optional_field() -> None:
    class Optional(BaseModel):
        inside: Annotated[PrivateKey[rsa.RSAPrivateKey] | None, Alg("PS256")] = None
        outside: Annotated[PrivateKey[rsa.RSAPrivateKey], Alg("PS256")] | None = None

    keys = Optional.model_validate({"inside": private_pem("rsa"), "outside": private_pem("rsa")})
    assert keys.inside is not None
    assert keys.inside.alg == "PS256"
    assert keys.inside == keys.outside
    assert Optional().inside is None
    properties = Optional.model_json_schema()["properties"]
    assert properties["inside"] == {**properties["outside"], "title": "Inside"}
    assert properties["inside"]["anyOf"][1] == {"type": "null"}


RSAKeyT = TypeVar("RSAKeyT", bound=rsa.RSAPrivateKey)


class GenericKeys(BaseModel, Generic[RSAKeyT]):
    key: Annotated[PrivateKey[RSAKeyT], Alg("PS256")]


def test_alg_in_a_generic_model() -> None:
    """Unparametrized, the field's type stays a generic alias (see _parametrize)."""
    for model in (GenericKeys, GenericKeys[rsa.RSAPrivateKey]):
        assert model.model_validate({"key": private_pem("rsa")}).key.alg == "PS256"
        with pytest.raises(ValidationError, match="expected an RSA private key, got an EC"):
            model.model_validate({"key": private_pem("p256")})


def test_unknown_alg() -> None:
    with pytest.raises(ValueError, match=r"^unknown algorithm 'RS1024'$"):
        Alg("RS1024")  # type: ignore[arg-type]


def test_json_schema() -> None:
    properties = Keys.model_json_schema()["properties"]
    assert properties["rs512"] == {
        "title": "Rs512",
        "type": "string",
        "format": "password",
        "writeOnly": True,
        "description": f"An RSA private key{PRIVATE_FORMATS}",
    }
    assert properties["oaep"] == {
        "title": "Oaep",
        "type": "string",
        "description": f"An RSA public key{PUBLIC_FORMATS}",
    }


def test_constructor_and_load() -> None:
    key = private_key("rsa")
    assert PrivateKey(key, alg="PS256").alg == "PS256"
    assert PrivateKey.load(private_pem("rsa"), "RSA", alg="PS384").alg == "PS384"
    assert PrivateKey.load(private_pem("rsa"), alg="RS512").alg == "RS512"
    assert PublicKey(key.public_key(), "RSA-OAEP").alg == "RSA-OAEP"
    assert PublicKey.load(public_pem("p256"), "EC", alg="ECDH-ES").public_jwk.use == "enc"
    # the default, given explicitly, is the same as none
    assert PrivateKey(key, alg="RS256") == PrivateKey(key)
    assert repr(PrivateKey(key, alg="RS256")) == "PrivateKey(RSA 2048)"


def test_alg_must_fit_the_key() -> None:
    with pytest.raises(
        ValueError, match=r"^ES256 isn't an algorithm for RSA 2048 keys, expected one"
    ):
        PrivateKey(private_key("rsa"), alg="ES256")
    with pytest.raises(ValueError, match=r"^ES256K isn't an algorithm for EC P-256 keys"):
        PublicKey.load(public_pem("p256"), alg="ES256K")
    with pytest.raises(ValueError, match=r"^expected an RSA private key, got an EC private key$"):
        PrivateKey.load(private_pem("p256"), "RSA", alg="RS512")  # the kind is checked first


def test_equality_hash_and_pickle() -> None:
    key = private_key("rsa")
    rs512 = PrivateKey(key, alg="RS512")
    assert rs512 != PrivateKey(key)
    assert hash(rs512) == hash(PrivateKey(key))
    public = rs512.public_key()
    assert public != PublicKey(key.public_key())
    for wrapped in (rs512, public):
        assert pickle.loads(pickle.dumps(wrapped)) == wrapped
        assert copy.deepcopy(wrapped) is wrapped


def test_jwks_refuses_one_key_with_two_algs() -> None:
    key = private_key("rsa")
    with pytest.raises(ValueError, match=r"^two different JWKs with the kid "):
        JWKS.from_keys(PrivateKey(key, alg="RS256"), PrivateKey(key, alg="PS256"))


def test_alg_names() -> None:
    """The Literal lists every algorithm of the tables, once."""
    in_tables = [alg for algs in _jwk.ALGS.values() for alg in algs]
    in_tables += [alg for curve in _jwk.EC_CURVES.values() for alg in curve.algs]
    assert set(get_args(_jwk.AlgName)) == set(in_tables)
    assert len(get_args(_jwk.AlgName)) == len(set(get_args(_jwk.AlgName)))


def test_jwk_alg_names() -> None:
    """The algorithms in each JWK model are those of its kinds of keys."""
    okp_kinds: list[KindName] = ["Ed25519", "Ed448", "X25519", "X448"]
    assert set(get_args(_jwk.RSAAlgName)) == _jwk.kind_algs("RSA")
    assert set(get_args(_jwk.ECAlgName)) == _jwk.kind_algs("EC")
    assert set(get_args(_jwk.OKPAlgName)) == {alg for k in okp_kinds for alg in _jwk.kind_algs(k)}


@pytest.mark.parametrize(
    ("name", "alg"),
    [
        ("rsa", "RS384"),
        ("rsa", "RS512"),
        ("rsa", "PS256"),
        ("rsa", "PS384"),
        ("rsa", "PS512"),
        ("ed25519", "Ed25519"),
        ("ed448", "Ed448"),
    ],
)
def test_signs_with_joserfc(name: str, alg: Any) -> None:
    """Sign with the key's alg, and verify with the published JWK."""
    key = PrivateKey(private_key(name), alg=alg)
    private = JWKRegistry.import_key(key.private_pem, key.kty)
    token = jwt.encode({"alg": key.alg}, {"sub": "x"}, private, [alg])
    public = JWKRegistry.import_key(JWKS.from_keys(key).keys[0].model_dump())
    assert jwt.decode(token, public, algorithms=[alg]).claims == {"sub": "x"}


@pytest.mark.parametrize(
    ("name", "alg"), [("rsa", "RS512"), ("ed25519", "EdDSA"), ("ed448", "EdDSA")]
)
def test_signs_with_pyjwt(name: str, alg: Any) -> None:
    """E.g. EdDSA, for PyJWT, which (as of 2.15) doesn't know Ed25519 and Ed448."""
    key = PrivateKey(private_key(name), alg=alg)
    pem = key.private_pem
    token = pyjwt.encode({"sub": "x"}, pem, algorithm=key.alg, headers={"kid": key.kid})
    published = pyjwt.PyJWKSet.from_dict(JWKS.from_keys(key).model_dump())
    assert pyjwt.decode(token, published[key.kid], algorithms=[key.alg]) == {"sub": "x"}
