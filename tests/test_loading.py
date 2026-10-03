"""Loading keys from text: the formats, load() and its kind, settings clean-up, and the errors."""

import json
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, ValidationError

from pydantic_cryptography import KindName, PrivateKey, PublicKey
from tests.helpers import (
    ENCRYPTED_OPENSSH_KEY,
    SSH_KEYS,
    TEST_KEYS,
    TRADITIONAL_KEYS,
    assert_not_shown,
    private_key,
    private_pem,
    public_pem,
)


class Model(BaseModel):
    private: PrivateKey | None = None
    public: PublicKey | None = None


@pytest.mark.parametrize("name", TEST_KEYS)
def test_pkcs8(name: str) -> None:
    assert PrivateKey.load(private_pem(name)) == PrivateKey(private_key(name))


@pytest.mark.parametrize("name", TRADITIONAL_KEYS)
def test_traditional(name: str) -> None:
    pem = private_pem(name, PrivateFormat.TraditionalOpenSSL)
    assert pem.startswith(("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"))
    assert PrivateKey.load(pem) == PrivateKey(private_key(name))


@pytest.mark.parametrize("name", SSH_KEYS)
def test_openssh_private(name: str) -> None:
    pem = private_pem(name, PrivateFormat.OpenSSH)
    assert pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert PrivateKey.load(pem) == PrivateKey(private_key(name))


@pytest.mark.parametrize("name", TEST_KEYS)
def test_public_pem(name: str) -> None:
    assert PublicKey.load(public_pem(name)) == PrivateKey(private_key(name)).public_key()


def test_public_pkcs1() -> None:
    public = private_key("rsa").public_key()
    pem = public.public_bytes(Encoding.PEM, PublicFormat.PKCS1).decode()
    assert pem.startswith("-----BEGIN RSA PUBLIC KEY-----")
    assert PublicKey.load(pem, "RSA") == PublicKey(public)


@pytest.mark.parametrize("name", SSH_KEYS)
def test_openssh_public(name: str) -> None:
    public = private_key(name).public_key()
    line = public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    expected = PublicKey(public)
    assert PublicKey.load(line) == expected
    assert PublicKey.load(f"{line} someone@example.com\n") == expected  # with a comment


def test_bytes() -> None:
    assert PrivateKey.load(private_pem("ed25519").encode()) == PrivateKey(private_key("ed25519"))
    assert PublicKey.load(public_pem("ed25519").encode()) == PublicKey(
        private_key("ed25519").public_key()
    )


def test_load() -> None:
    assert isinstance(PrivateKey.load(private_pem("rsa")).key, rsa.RSAPrivateKey)
    assert isinstance(PublicKey.load(public_pem("p256")).key, ec.EllipticCurvePublicKey)


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("rsa", "RSA"),
        ("p256", "EC"),
        ("ed25519", "Ed25519"),
        ("ed448", "Ed448"),
        ("x25519", "X25519"),
        ("x448", "X448"),
    ],
)
def test_load_kind(name: str, kind: KindName) -> None:
    assert PrivateKey.load(private_pem(name), kind) == PrivateKey(private_key(name))
    assert PublicKey.load(public_pem(name), kind) == PublicKey(private_key(name).public_key())
    other: KindName = "EC" if kind == "RSA" else "RSA"
    with pytest.raises(ValueError, match=f"^expected an {other} private key, got an {kind} priv"):
        PrivateKey.load(private_pem(name), other)
    with pytest.raises(ValueError, match=f"^expected an {other} public key, got an {kind} publ"):
        PublicKey.load(public_pem(name), other)


def test_load_unknown_kind() -> None:
    with pytest.raises(
        ValueError, match=r"^unknown kind of key 'DSA', expected one of 'RSA', 'EC'"
    ):
        PrivateKey.load(private_pem("rsa"), "DSA")  # type: ignore[call-overload]


@pytest.mark.parametrize(
    "transform",
    [
        pytest.param(lambda pem: f"\n    {pem.replace(chr(10), chr(10) + '    ')}", id="indented"),
        pytest.param(lambda pem: pem.replace("\n", "\\n"), id="literal-backslash-n"),
        pytest.param(lambda pem: pem.replace("\n", "\\r\\n"), id="literal-backslash-r-n"),
        pytest.param(lambda pem: pem.replace("\n", "\r\n"), id="crlf"),
        pytest.param(lambda pem: f"  \n\n{pem}\n\n  ", id="surrounding-whitespace"),
        pytest.param(lambda pem: pem.rstrip("\n"), id="no-final-newline"),
    ],
)
def test_settings_value_cleanup(transform: Callable[[str], str]) -> None:
    expected = PrivateKey(private_key("rsa"))
    pem = private_pem("rsa", PrivateFormat.TraditionalOpenSSL)
    assert PrivateKey.load(transform(pem)) == expected
    assert Model.model_validate({"private": transform(pem)}).private == expected
    public = Model.model_validate({"public": transform(public_pem("rsa"))}).public
    assert public == expected.public_key()


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "expected a PEM encoded private key, starting with '-----BEGIN '"),
        ("not a key", "expected a PEM encoded private key, starting with '-----BEGIN '"),
        (b"\xff\xfe", "the key isn't PEM text: it contains non-ASCII bytes"),
        (
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "invalid or unsupported private key: it couldn't be loaded",
        ),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
            "invalid or unsupported private key: it couldn't be loaded",
        ),
        (ENCRYPTED_OPENSSH_KEY, "encrypted private keys aren't supported"),
    ],
)
def test_private_errors(value: str | bytes, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        PrivateKey.load(value)


@pytest.mark.parametrize("fmt", [PrivateFormat.PKCS8, PrivateFormat.TraditionalOpenSSL])
def test_encrypted_pem(fmt: PrivateFormat) -> None:
    pem = private_key("p256").private_bytes(Encoding.PEM, fmt, BestAvailableEncryption(b"secret"))
    with pytest.raises(ValueError, match=r"^encrypted private keys aren't supported$"):
        PrivateKey.load(pem)


def test_public_key_as_private() -> None:
    ssh_line = (
        private_key("ed25519").public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    )
    for value in (public_pem("rsa"), ssh_line):
        with pytest.raises(ValueError, match=r"^expected a private key, got a public key$"):
            PrivateKey.load(value)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "expected a PEM encoded public key, starting with '-----BEGIN ', or an OpenSSH"),
        ("ssh-ed25519 AAAA", "invalid or unsupported public key: it couldn't be loaded"),
        (
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
            "invalid or unsupported public key: it couldn't be loaded",
        ),
    ],
)
def test_public_errors(value: str, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}"):
        PublicKey.load(value)


def test_private_key_as_public() -> None:
    for value in (private_pem("rsa"), private_pem("ed25519", PrivateFormat.OpenSSH)):
        with pytest.raises(ValueError, match=r"^expected a public key, got a private key$"):
            PublicKey.load(value)


def test_unsupported_kinds_of_keys() -> None:
    key = dsa.generate_private_key(key_size=1024)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(ValueError, match=r"^unsupported type of private key: DSAPrivateKey$"):
        PrivateKey.load(pem)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match=r"^unsupported type of public key: DSAPublicKey$"):
        PublicKey.load(pem)
    with pytest.raises(TypeError, match=r"^unsupported type of private key: DSAPrivateKey$"):
        PrivateKey(key)  # type: ignore[type-var]
    with pytest.raises(TypeError, match=r"^unsupported type of public key: DSAPublicKey$"):
        PublicKey(key.public_key())  # type: ignore[type-var]


def test_small_rsa_keys() -> None:
    """RFC 7518 requires at least 2048 bits for RSA keys."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    message = r"^RSA keys must be at least 2048 bits, got 1024$"
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(ValueError, match=message):
        PrivateKey.load(pem)
    with pytest.raises(ValueError, match=message):
        PrivateKey(key)
    with pytest.raises(ValueError, match=message):
        PublicKey.load(key.public_key().public_bytes(Encoding.PEM, PublicFormat.PKCS1))
    with pytest.raises(ValueError, match=message):
        PublicKey(key.public_key())
    with pytest.raises(ValidationError, match=message[1:-1]):
        Model(private=pem)  # type: ignore[arg-type]


@pytest.mark.parametrize("curve", [ec.BrainpoolP256R1(), ec.SECP192R1()])
def test_ec_curves_without_jwk(curve: ec.EllipticCurve) -> None:
    """They'd have no JWK, algorithm or key ID."""
    key = ec.generate_private_key(curve)
    message = rf"^unsupported EC curve {curve.name}, expected P-256, P-384, P-521 or secp256k1$"
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with pytest.raises(ValueError, match=message):
        PrivateKey.load(pem)
    with pytest.raises(ValueError, match=message):
        PrivateKey(key)
    with pytest.raises(ValueError, match=message):
        PublicKey.load(
            key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
    with pytest.raises(ValueError, match=message):
        PublicKey(key.public_key())
    with pytest.raises(ValidationError, match=message[1:-1]):
        Model(private=pem)  # type: ignore[arg-type]


def from_python(model: type[BaseModel], data: dict[str, str]) -> None:
    model.model_validate(data)


def from_json(model: type[BaseModel], data: dict[str, str]) -> None:
    model.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("validate", [from_python, from_json])
def test_errors_never_show_the_input(
    validate: Callable[[type[BaseModel], dict[str, str]], None],
) -> None:
    """A key given where it doesn't fit must not end up in the error, and so in logs."""
    pem = private_pem("rsa")
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    brainpool = ec.generate_private_key(ec.BrainpoolP256R1())

    class Ed25519Only(BaseModel):
        key: PrivateKey[Ed25519PrivateKey]

    cases: list[tuple[type[BaseModel], str, str]] = [
        (Ed25519Only, "key", pem),  # of the wrong kind
        (Model, "public", pem),  # in a public key field
        (Model, "private", pem[:-40]),  # broken
        (Model, "private", pem_of(small)),  # too small
        (Model, "private", pem_of(brainpool)),  # on a curve without a JWK
    ]
    for model, field, value in cases:
        with pytest.raises(ValidationError) as info:
            validate(model, {field: value})
        assert "**********" in str(info.value)
        assert_not_shown(info.value, value)


def pem_of(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
