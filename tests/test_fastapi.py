"""A JWKS endpoint with FastAPI: the response, and its OpenAPI schema."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from pydantic_cryptography import JWKS, PrivateKey, PublicKey
from tests.helpers import private_key


def test_jwks_endpoint() -> None:
    keys = (
        PrivateKey(private_key("rsa")),
        PublicKey(private_key("p256").public_key()),
        PrivateKey(private_key("ed25519")),
    )
    app = FastAPI()

    @app.get("/.well-known/jwks.json")
    def get_jwks() -> JWKS:
        return JWKS.from_keys(*keys)

    client = TestClient(app)
    assert client.get("/.well-known/jwks.json").json() == {
        "keys": [key.public_jwk.model_dump() for key in keys]
    }

    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    assert schemas["JWKS"]["properties"]["keys"]["items"]["discriminator"] == {
        "propertyName": "kty",
        "mapping": {
            "RSA": "#/components/schemas/RSAPublicJWK",
            "EC": "#/components/schemas/ECPublicJWK",
            "OKP": "#/components/schemas/OKPPublicJWK",
        },
    }
    rsa = schemas["RSAPublicJWK"]
    assert rsa["required"] == ["kty", "kid", "use", "alg", "n", "e"]
    assert rsa["properties"]["alg"]["enum"][:3] == ["RS256", "RS384", "RS512"]
    assert schemas["OKPPublicJWK"]["properties"]["crv"]["enum"] == [
        "Ed25519",
        "Ed448",
        "X25519",
        "X448",
    ]
