"""Test keys of every supported kind, and their encodings."""

from functools import cache
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import ValidationError

from pydantic_cryptography._kinds import SupportedPrivateKey

# A test key of every supported kind, and of every EC curve with a JWK representation, by name
TEST_KEYS = ["rsa", "p256", "p384", "p521", "secp256k1", "ed25519", "ed448", "x25519", "x448"]

# The test keys that the OpenSSH formats can hold
SSH_KEYS = ["rsa", "p256", "p384", "p521", "ed25519"]

# The test keys with a "traditional" PEM format: PKCS#1 for RSA, SEC 1 for EC
TRADITIONAL_KEYS = ["rsa", "p256", "p384", "p521", "secp256k1"]

# How the JSON schema of a key field describes the formats it accepts, after the kinds of keys
PRIVATE_FORMATS = ": PEM (PKCS#8, PKCS#1 or SEC 1) or OpenSSH"
PUBLIC_FORMATS = ": PEM (SubjectPublicKeyInfo or PKCS#1) or an OpenSSH public key line"

# An ssh-keygen generated Ed25519 key, encrypted with the password "testpassword"
ENCRYPTED_OPENSSH_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDZdcanua
HxLxqO7k/QisrLAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJha7WvKLU9eWOD9
r5f+81XrqGK9R8n28v2wYR+0P5gMAAAAkEwYx1QLpj4ATbZQ5raSH1ISB7dC21FvNDRiDy
PgI/p0Kx2kAamPoM+kxuu7HGx4jpEYLdYqWHkuDaEjIxWlxqjoueGQAABavvH7vz5HBlDx
X1esI3EcGgJzqNMqCVXTfPovX5+Y0oQgC+4CFsl4TNi6v8ACVBi1lnrD33gC3YXNM7iioa
X9z8+DUVAI+2bK5w==
-----END OPENSSH PRIVATE KEY-----
"""


@cache
def private_key(name: str) -> SupportedPrivateKey:
    """The test key with the name, e.g. "p256"; the same one for the whole test run."""
    curves: dict[str, ec.EllipticCurve] = {
        "p256": ec.SECP256R1(),
        "p384": ec.SECP384R1(),
        "p521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }
    if name == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if name in curves:
        return ec.generate_private_key(curves[name])
    generators: dict[str, Any] = {
        "ed25519": ed25519.Ed25519PrivateKey,
        "ed448": ed448.Ed448PrivateKey,
        "x25519": x25519.X25519PrivateKey,
        "x448": x448.X448PrivateKey,
    }
    key: SupportedPrivateKey = generators[name].generate()
    return key


def private_pem(name: str, fmt: PrivateFormat = PrivateFormat.PKCS8) -> str:
    return private_key(name).private_bytes(Encoding.PEM, fmt, NoEncryption()).decode()


def public_pem(name: str) -> str:
    public = private_key(name).public_key()
    return public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def assert_not_shown(error: BaseException, pem: str | bytes) -> None:
    """
    The error doesn't show the key: none of the base64 lines of its PEM.

    Checked in every form the error can end up in a log: str() and repr(), and for a Pydantic
    error also .json() and .errors(); and the same for the error it was raised from.
    """
    texts: list[str] = []
    for exc in (error, error.__cause__):
        if exc is not None:
            texts += [str(exc), repr(exc)]
        if isinstance(exc, ValidationError):
            texts += [exc.json(), repr(exc.errors())]
    text = pem.decode() if isinstance(pem, bytes) else pem
    lines = [line for line in text.splitlines()[1:-1] if len(line) >= 16]  # not a short last line
    assert lines
    for line in lines:
        assert all(line not in shown for shown in texts), f"the error shows {line!r}"
