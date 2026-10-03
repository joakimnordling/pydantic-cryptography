"""With pydantic-settings: keys from environment variables, .env files, secrets and defaults."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import PrivateFormat
from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict, SettingsError

from pydantic_cryptography import JWKS, PrivateKey, PublicKey
from tests.helpers import assert_not_shown, private_key, private_pem, public_pem

RSA_PEM = private_pem("rsa", PrivateFormat.TraditionalOpenSSL)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TEST_")

    signing_key: PrivateKey[RSAPrivateKey]
    previous_signing_key: PrivateKey[RSAPrivateKey] | None = None
    partner_key: PublicKey | None = None


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(RSA_PEM, id="multi-line"),
        pytest.param(RSA_PEM.replace("\n", "\\n"), id="one-line"),
    ],
)
def test_environment_variable(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("TEST_SIGNING_KEY", value)
    monkeypatch.setenv("TEST_PARTNER_KEY", public_pem("ed25519"))
    settings = Settings()  # type: ignore[call-arg]
    assert settings.signing_key == PrivateKey(private_key("rsa"))
    assert settings.previous_signing_key is None
    assert settings.partner_key == PublicKey(private_key("ed25519").public_key())
    assert JWKS.from_keys(settings.signing_key, settings.previous_signing_key).keys == [
        settings.signing_key.public_jwk
    ]


def test_dotenv_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(f'TEST_SIGNING_KEY="{RSA_PEM}"\n')
    settings = Settings(_env_file=env)  # type: ignore[call-arg]
    assert settings.signing_key == PrivateKey(private_key("rsa"))


def test_secrets_dir(tmp_path: Path) -> None:
    """E.g. Docker or Kubernetes secrets mounted as files."""
    (tmp_path / "TEST_SIGNING_KEY").write_text(RSA_PEM)
    settings = Settings(_secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.signing_key == PrivateKey(private_key("rsa"))


def test_wrong_key_in_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_SIGNING_KEY", private_pem("ed25519"))
    with pytest.raises(ValidationError) as info:
        Settings()  # type: ignore[call-arg]
    assert "expected an RSA private key, got an Ed25519 private key" in str(info.value)
    assert_not_shown(info.value, private_pem("ed25519"))


def test_defaults() -> None:
    """A default is validated too (BaseSettings sets validate_default), however it's indented."""
    indented = "\n        ".join(RSA_PEM.splitlines())

    class WithDefaults(BaseSettings):
        # e.g. a development key; with the kind, type checkers know it's an RSA key
        signing_key: PrivateKey[RSAPrivateKey] = PrivateKey.load(f"\n    {indented}\n", "RSA")
        # as a string it works too, but type checkers don't accept it
        other_key: PrivateKey[RSAPrivateKey] = f"\n    {indented}\n"  # type: ignore[assignment]
        # or a new key on each start
        session_key: PrivateKey[Ed25519PrivateKey] = PrivateKey(Ed25519PrivateKey.generate())

    settings = WithDefaults()
    assert settings.signing_key == settings.other_key == PrivateKey(private_key("rsa"))
    assert isinstance(settings.session_key.key, Ed25519PrivateKey)


class KeyRotation(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TEST_")

    signing_keys: list[PrivateKey[RSAPrivateKey]] = Field(min_length=1)


def test_list_in_environment_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A list is given as a JSON array, as for any list in pydantic-settings."""
    monkeypatch.setenv("TEST_SIGNING_KEYS", json.dumps([RSA_PEM, private_pem("rsa")]))
    settings = KeyRotation()  # type: ignore[call-arg]
    assert settings.signing_keys == [PrivateKey(private_key("rsa"))] * 2


def test_list_in_dotenv_file(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    # single quotes: the JSON, with its \n escapes, is taken as is
    env.write_text(f"TEST_SIGNING_KEYS='{json.dumps([RSA_PEM])}'\n")
    settings = KeyRotation(_env_file=env)  # type: ignore[call-arg]
    assert settings.signing_keys == [PrivateKey(private_key("rsa"))]


def test_wrong_key_in_list(monkeypatch: pytest.MonkeyPatch) -> None:
    ed25519_pem = private_pem("ed25519")
    monkeypatch.setenv("TEST_SIGNING_KEYS", json.dumps([RSA_PEM, ed25519_pem]))
    with pytest.raises(ValidationError) as info:
        KeyRotation()  # type: ignore[call-arg]
    assert [(error["loc"], error["msg"]) for error in info.value.errors()] == [
        (
            ("signing_keys", 1),
            "Value error, expected an RSA private key, got an Ed25519 private key",
        )
    ]
    assert_not_shown(info.value, ed25519_pem)


def test_list_not_given_as_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """pydantic-settings refuses it; without the key in the error."""
    monkeypatch.setenv("TEST_SIGNING_KEYS", RSA_PEM)
    with pytest.raises(SettingsError) as info:
        KeyRotation()  # type: ignore[call-arg]
    assert_not_shown(info.value, RSA_PEM)
