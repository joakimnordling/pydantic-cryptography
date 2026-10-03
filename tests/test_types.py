"""The key types in Pydantic models, and as objects."""

import copy
import json
import pickle
from typing import Any, Generic, TypeVar, get_args

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import PrivateFormat
from pydantic import BaseModel, TypeAdapter, ValidationError

from pydantic_cryptography import JWKS, PrivateKey, PublicKey, _kinds
from tests.helpers import (
    PRIVATE_FORMATS,
    PUBLIC_FORMATS,
    TEST_KEYS,
    assert_not_shown,
    private_key,
    private_pem,
    public_pem,
)

DESCRIPTIONS = {
    "rsa": "RSA 2048",
    "p256": "EC P-256",
    "p384": "EC P-384",
    "p521": "EC P-521",
    "secp256k1": "EC secp256k1",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
}


class Keys(BaseModel):
    private: PrivateKey
    public: PublicKey


def keys(name: str) -> Keys:
    return Keys.model_validate(
        {
            "private": private_pem(name),
            "public": public_pem(name),
        }
    )


@pytest.mark.parametrize("name", TEST_KEYS)
def test_repr_hides_the_key(name: str) -> None:
    model = keys(name)
    assert repr(model.private) == str(model.private) == f"PrivateKey({DESCRIPTIONS[name]})"
    assert repr(model.public) == f"PublicKey({DESCRIPTIONS[name]})"
    assert repr(model) == (
        f"Keys(private=PrivateKey({DESCRIPTIONS[name]}), public=PublicKey({DESCRIPTIONS[name]}))"
    )


@pytest.mark.parametrize("name", TEST_KEYS)
def test_key_objects(name: str) -> None:
    model = keys(name)
    assert model.private.key.public_key() == private_key(name).public_key()
    assert model.public.key == private_key(name).public_key()
    assert model.private.public_key() == model.public
    assert model.private.public_pem == model.public.public_pem == public_pem(name)


@pytest.mark.parametrize("name", TEST_KEYS)
def test_private_pem(name: str) -> None:
    secret = keys(name).private.private_pem
    assert secret == private_pem(name, PrivateFormat.PKCS8)
    assert PrivateKey.load(secret) == keys(name).private


def test_accepts_key_objects_and_instances() -> None:
    key = private_key("ed25519")
    wrapped = PrivateKey(key)
    public = PublicKey(key.public_key())
    from_objects = Keys.model_validate(
        {
            "private": key,
            "public": key.public_key(),
        }
    )
    assert from_objects == Keys(private=wrapped, public=public)
    model = Keys(private=wrapped, public=public)
    assert model.private is wrapped  # used as is, not copied
    assert model.public is public


P256 = private_key("p256")


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        pytest.param(
            "private", 12, "expected a PEM encoded private key as str, got int", id="private-int"
        ),
        pytest.param(
            "public", 12, "expected a PEM encoded public key as str, got int", id="public-int"
        ),
        pytest.param(
            "private",
            PublicKey(P256.public_key()),
            "expected a private key, got a public key",
            id="private-PublicKey",
        ),
        pytest.param(
            "private",
            P256.public_key(),
            "expected a private key, got a public key",
            id="private-public-key-object",
        ),
        pytest.param(
            "public",
            PrivateKey(P256),
            "expected a public key, got a private key",
            id="public-PrivateKey",
        ),
        pytest.param(
            "public",
            P256,
            "expected a public key, got a private key",
            id="public-private-key-object",
        ),
    ],
)
def test_wrong_input(field: str, value: object, error: str) -> None:
    valid = {"private": P256, "public": P256.public_key()}
    with pytest.raises(ValidationError, match=f"Value error, {error} "):
        Keys.model_validate({**valid, field: value})


class Restricted(BaseModel):
    rsa: PrivateKey[RSAPrivateKey] | None = None
    rsa_or_ec: PrivateKey[RSAPrivateKey | EllipticCurvePrivateKey] | None = None
    ed25519_public: PublicKey[Ed25519PublicKey] | None = None


def test_type_argument_limits_the_kinds() -> None:
    assert Restricted.model_validate({"rsa": private_pem("rsa")}).rsa == PrivateKey(
        private_key("rsa")
    )
    assert Restricted.model_validate({"rsa_or_ec": private_pem("rsa")}).rsa_or_ec is not None
    assert Restricted.model_validate({"rsa_or_ec": private_pem("p384")}).rsa_or_ec is not None
    public = Restricted.model_validate({"ed25519_public": public_pem("ed25519")})
    assert public.ed25519_public is not None
    for field, value, error in (
        ("rsa", private_pem("p256"), "expected an RSA private key, got an EC private key"),
        ("rsa", private_key("ed448"), "expected an RSA private key, got an Ed448 private key"),
        (
            "rsa_or_ec",
            PrivateKey(private_key("x25519")),
            "expected an RSA or EC private key, got an X25519 private key",
        ),
        (
            "ed25519_public",
            public_pem("rsa"),
            "expected an Ed25519 public key, got an RSA public key",
        ),
    ):
        with pytest.raises(ValidationError, match=f"Value error, {error} "):
            Restricted.model_validate({field: value})


def test_unrestricted_accepts_every_supported_kind() -> None:
    for name in TEST_KEYS:
        keys(name)


def test_invalid_type_argument() -> None:
    message = "isn't supported: the type argument must be one of RSA"
    with pytest.raises(TypeError, match=message):
        PrivateKey[RSAPublicKey]  # type: ignore[type-var]
    with pytest.raises(TypeError, match=message):
        PrivateKey[int]  # type: ignore[type-var]
    with pytest.raises(TypeError, match=message):
        PublicKey[RSAPrivateKey]  # type: ignore[type-var]


def test_any_type_argument() -> None:
    adapter = TypeAdapter(PrivateKey[Any])
    assert adapter.validate_python(private_pem("x448")) == PrivateKey(private_key("x448"))


KeyT = TypeVar("KeyT", bound=RSAPrivateKey | Ed25519PrivateKey)


class Generic_(BaseModel, Generic[KeyT]):
    key: PrivateKey[KeyT]


UnboundT = TypeVar("UnboundT")


class Unbound(BaseModel, Generic[UnboundT]):
    key: PrivateKey[UnboundT]  # type: ignore[type-var]


def test_generic_model() -> None:
    # not parametrized: the TypeVar's bound
    assert Generic_.model_validate({"key": private_pem("rsa")}).key == PrivateKey(
        private_key("rsa")
    )
    with pytest.raises(
        ValidationError, match="expected an RSA or Ed25519 private key, got an Ed448"
    ):
        Generic_.model_validate({"key": private_pem("ed448")})
    assert Unbound.model_validate({"key": private_pem("ed448")}).key == PrivateKey(
        private_key("ed448")
    )
    # parametrized
    assert Generic_[Ed25519PrivateKey].model_validate({"key": private_pem("ed25519")}).key
    with pytest.raises(ValidationError, match="expected an Ed25519 private key, got an RSA"):
        Generic_[Ed25519PrivateKey].model_validate({"key": private_pem("rsa")})


def test_serialization() -> None:
    model = keys("ed25519")
    assert model.model_dump() == {
        "private": model.private,
        "public": model.public,
    }
    assert json.loads(model.model_dump_json()) == {
        "private": "**********",
        "public": public_pem("ed25519"),
    }
    # the public key survives a JSON round trip; the private key, like a SecretStr, doesn't
    assert PublicKey.load(json.loads(model.model_dump_json())["public"]) == model.public


ALL_KINDS = "RSA, EC, Ed25519, Ed448, X25519 or X448"


def test_json_schema() -> None:
    assert Keys.model_json_schema()["properties"] == {
        "private": {
            "title": "Private",
            "type": "string",
            "format": "password",
            "writeOnly": True,
            "description": f"A private key ({ALL_KINDS}){PRIVATE_FORMATS}",
        },
        "public": {
            "title": "Public",
            "type": "string",
            "description": f"A public key ({ALL_KINDS}){PUBLIC_FORMATS}",
        },
    }


def test_json_schema_of_restricted() -> None:
    assert Restricted.model_json_schema()["properties"]["rsa"] == {
        "anyOf": [
            {
                "type": "string",
                "format": "password",
                "writeOnly": True,
                "description": f"An RSA private key{PRIVATE_FORMATS}",
            },
            {"type": "null"},
        ],
        "default": None,
        "title": "Rsa",
    }
    properties = Restricted.model_json_schema()["properties"]
    assert (
        properties["rsa_or_ec"]["anyOf"][0]["description"]
        == f"An RSA or EC private key{PRIVATE_FORMATS}"
    )
    assert properties["ed25519_public"]["anyOf"][0] == {
        "type": "string",
        "description": f"An Ed25519 public key{PUBLIC_FORMATS}",
    }


def test_serialization_of_restricted() -> None:
    model = Restricted.model_validate(
        {
            "rsa": private_pem("rsa"),
            "ed25519_public": public_pem("ed25519"),
        }
    )
    assert json.loads(model.model_dump_json()) == {
        "rsa": "**********",
        "rsa_or_ec": None,
        "ed25519_public": public_pem("ed25519"),
    }


class Collections(BaseModel):
    private_keys: list[PrivateKey[RSAPrivateKey]] = []
    public_keys: dict[str, PublicKey] = {}


def test_collections() -> None:
    model = Collections.model_validate(
        {
            "private_keys": [private_pem("rsa"), private_key("rsa")],
            "public_keys": {"partner": public_pem("ed25519")},
        }
    )
    assert model.private_keys == [PrivateKey(private_key("rsa"))] * 2
    assert model.public_keys == {"partner": PublicKey(private_key("ed25519").public_key())}
    assert repr(model) == (
        "Collections(private_keys=[PrivateKey(RSA 2048), PrivateKey(RSA 2048)], "
        "public_keys={'partner': PublicKey(Ed25519)})"
    )
    assert json.loads(model.model_dump_json()) == {
        "private_keys": ["**********", "**********"],
        "public_keys": {"partner": public_pem("ed25519")},
    }
    assert JWKS.from_keys(*model.private_keys).keys == [model.private_keys[0].public_jwk]


def test_collection_errors() -> None:
    """Each item is checked, and the errors point at it, without showing it."""
    with pytest.raises(ValidationError) as info:
        Collections.model_validate(
            {
                "private_keys": [private_pem("rsa"), private_pem("p256")],
                "public_keys": {"partner": private_pem("ed25519")},
            }
        )
    assert [(error["loc"], error["msg"]) for error in info.value.errors()] == [
        (("private_keys", 1), "Value error, expected an RSA private key, got an EC private key"),
        (("public_keys", "partner"), "Value error, expected a public key, got a private key"),
    ]
    for pem in (private_pem("p256"), private_pem("ed25519")):
        assert_not_shown(info.value, pem)


def test_equality_and_hash() -> None:
    a, b = keys("p256"), keys("p256")
    assert a.private == b.private
    assert a.public == b.public
    assert hash(a.private) == hash(b.private) == hash(a.public)
    other = keys("p384")
    assert a.private != other.private
    assert a.public != other.public
    assert a.private != a.public
    assert a.public != a.private
    assert a.private != private_pem("p256")
    assert len({a.private, b.private, other.private}) == 2


@pytest.mark.parametrize("name", TEST_KEYS)
def test_copy_and_pickle(name: str) -> None:
    model = keys(name)
    for key in (model.private, model.public):
        assert copy.copy(key) is key
        assert copy.deepcopy(key) is key
        assert pickle.loads(pickle.dumps(key)) == key
    assert model.model_copy(deep=True) == model
    assert pickle.loads(pickle.dumps(model)) == model


def test_kind_names_match_the_supported_kinds() -> None:
    """The Literal that types `load(kind=...)` lists every supported kind, in the same order."""
    assert get_args(_kinds.KindName) == tuple(kind.name for kind in _kinds.KEY_KINDS)
