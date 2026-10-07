# pydantic-cryptography

[![PyPI](https://img.shields.io/pypi/v/pydantic-cryptography)](https://pypi.org/project/pydantic-cryptography/)
[![Python versions](https://img.shields.io/pypi/pyversions/pydantic-cryptography)](https://pypi.org/project/pydantic-cryptography/)
[![CI](https://github.com/joakimnordling/pydantic-cryptography/actions/workflows/ci.yml/badge.svg)](https://github.com/joakimnordling/pydantic-cryptography/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/pypi/l/pydantic-cryptography)](https://github.com/joakimnordling/pydantic-cryptography/blob/main/LICENSE)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/joakimnordling/pydantic-cryptography/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Pydantic types for cryptographic keys.

Use private and public RSA, EC (elliptic curve), Ed25519, Ed448, X25519 and X448 keys in your
settings: validated when the settings load, and ready to use, e.g. to sign and verify. Want to
publish a JWKS (JSON Web Key Set) of your keys for OpenID Connect and OAuth clients?
`JWKS.from_keys()` builds it for you, with a JWK (JSON Web Key: `kty`, `kid`, `n`, `e`, …) for
each key.

```python
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic_settings import BaseSettings

from pydantic_cryptography import PrivateKey, PublicKey


class Settings(BaseSettings):
    signing_key: PrivateKey[rsa.RSAPrivateKey]
    partner_key: PublicKey[ec.EllipticCurvePublicKey]
```

Fully typed: mypy, pyright and ty know that `settings.signing_key.key` is an `rsa.RSAPrivateKey`.

## Why

Keys are usually kept as secrets and given to the application as environment variables or `.env`
files, e.g. to sign tokens, to verify a partner's signatures, or to publish in a `jwks.json` for an
OpenID Connect or OAuth setup. A `SecretStr` setting works, but you still have to load the key
before you can use it, and keep the loaded key for reuse: loading an RSA key might take tens of
milliseconds, as it's checked on the way. And a broken key, or one of the wrong kind, only shows up
when it's first used.

These types load and check each key once, when the settings load, and the loaded key is right there
in the settings, ready to use. A mistake is reported with the field's name, and the key is kept out
of reprs, JSON and error messages, so it doesn't end up in your logs by accident. For a
`jwks.json`, the JWK members and the key ID (`kid`) are computed for you.

## Installation

```bash
pip install pydantic-cryptography
# or
uv add pydantic-cryptography
```

Requires Python 3.11+, Pydantic 2.7+ and cryptography 50.0.2+. The types work in any Pydantic model;
[pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) isn't required,
but it's where they're most useful.

## Quick start

Create a key and give it to the application as an environment variable:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing-key.pem
export SIGNING_KEY="$(cat signing-key.pem)"
```

The examples in this README continue from each other, like one script. For them, we create the key
in Python:

```python
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
os.environ["SIGNING_KEY"] = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
```

Declare it in the settings. The type argument limits the kinds of keys accepted; here only RSA:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic_settings import BaseSettings

from pydantic_cryptography import PrivateKey


class Settings(BaseSettings):
    signing_key: PrivateKey[rsa.RSAPrivateKey]
    previous_signing_key: PrivateKey[rsa.RSAPrivateKey] | None = None  # during a key rotation


settings = Settings()
```

Sign with the key, e.g. a JWT with [PyJWT](https://pyjwt.readthedocs.io/):

<!-- readme-test: needs jwt -->
```python
import jwt

key = settings.signing_key
token = jwt.encode({"sub": "someone"}, key.key, algorithm=key.alg, headers={"kid": key.kid})

# and to verify it
claims = jwt.decode(
    token,
    key.public_key().key,
    algorithms=[key.alg],  # the key's own algorithm, never the one in the token
)
assert claims == {"sub": "someone"}
```

And publish the public key as a JWKS, e.g. at the `jwks_uri` of your OpenID configuration. With
FastAPI, return it from an endpoint, and its OpenAPI schema shows the members of each kind of key:

<!-- readme-test: needs fastapi -->
```python
from fastapi import FastAPI

from pydantic_cryptography import JWKS

app = FastAPI()


@app.get("/.well-known/jwks.json")
def get_jwks() -> JWKS:
    return JWKS.from_keys(settings.signing_key, settings.previous_signing_key)
```

`JWKS` is a Pydantic model, so without FastAPI, `.model_dump_json()` gives the JSON, and
`.model_dump()` a dict:

```python
from pydantic_cryptography import JWKS

jwks = JWKS.from_keys(settings.signing_key, settings.previous_signing_key)
assert jwks.keys == [settings.signing_key.public_jwk]
json_text = jwks.model_dump_json()
# {"keys":[{"kty":"RSA","kid":"...","use":"sig","alg":"RS256","n":"...","e":"AQAB"}]}
```

## The types

### `PrivateKey`

A private key. As a field, it accepts:

- PEM: PKCS#8 (`-----BEGIN PRIVATE KEY-----`), PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) or
  SEC 1 (`-----BEGIN EC PRIVATE KEY-----`);
- OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), as from `ssh-keygen`;
- a `cryptography` private key object, or a `PrivateKey`.

Encrypted (password-protected) keys aren't supported.

The value is cleaned up the way settings values tend to need: the indentation of each line is
removed (a key in a triple-quoted string in a class body just works), and a key squeezed onto one
line with literal `\n`s (as some deployment tools require) gets its line breaks back.

Like Pydantic's `SecretStr`, it keeps the key out of sight: its `repr` shows only the kind of key
(`PrivateKey(RSA 2048)`), and it's serialized to JSON as `"**********"`. Validation errors don't
show the input either, so a private key put in the wrong field doesn't end up in your logs. As with
`SecretStr`, the JSON of a model with a private key can't be loaded again, as the key isn't in it.

| Attribute | What it is |
| --- | --- |
| `key` | The `cryptography` key object, e.g. `rsa.RSAPrivateKey`, to sign or decrypt with. |
| `public_key()` | The public key, as a `PublicKey`. |
| `alg` | The JWA algorithm the key is used with (see [Algorithms](#algorithms)). |
| `kid` | The key ID: the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) SHA-256 JWK thumbprint of the key. |
| `kty` | The JWK key type: `"RSA"`, `"EC"` or `"OKP"`. |
| `public_jwk` | The public key as a JWK (see [JWKs](#jwks)). |
| `public_pem` | The public key as PEM (`-----BEGIN PUBLIC KEY-----`). |
| `private_pem` | The private key as PEM (PKCS#8, `-----BEGIN PRIVATE KEY-----`). |
| `PrivateKey(key, alg=None)` | A `PrivateKey` of a `cryptography` key object. |
| `PrivateKey.load(data, kind=None, *, alg=None)` | Loads a key from PEM or OpenSSH text (`str` or `bytes`) outside a model, e.g. `PrivateKey.load(pem, "RSA")`. The `kind` is `"RSA"`, `"EC"`, `"Ed25519"`, `"Ed448"`, `"X25519"` or `"X448"`. |

**Pass the key object to other libraries**, e.g. `settings.signing_key.key`, rather than the PEM.
PyJWT, python-jose, joserfc and jwcrypto all accept it, and loading a PEM again checks the key
again, which might take tens of milliseconds for an RSA key.

### `PublicKey`

A public key, e.g. a partner's, to verify their signatures with. As a field, it accepts PEM
(`-----BEGIN PUBLIC KEY-----` or `-----BEGIN RSA PUBLIC KEY-----`), an OpenSSH public key line
(`ssh-ed25519 AAAA... comment`), or a `cryptography` public key object. It's serialized to JSON as
PEM. It has the same attributes as `PrivateKey` (`PublicKey(key, alg=None)`, `PublicKey.load(...)`,
`key`, `alg`, `kid`, ...), except `public_key()` and `private_pem`.

### Limiting the kinds of keys

Without a type argument, any supported kind of key is accepted. With one, only the kinds named, and
type checkers know which `key` you get:

```python
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, x448, x25519
from pydantic import BaseModel

from pydantic_cryptography import PrivateKey, PublicKey


class Keys(BaseModel):
    any_key: PrivateKey | None = None  # any of the kinds below
    rsa_key: PrivateKey[rsa.RSAPrivateKey] | None = None
    ec_key: PrivateKey[ec.EllipticCurvePrivateKey] | None = None
    ed25519_key: PrivateKey[ed25519.Ed25519PrivateKey] | None = None
    ed448_key: PrivateKey[ed448.Ed448PrivateKey] | None = None
    x25519_key: PrivateKey[x25519.X25519PrivateKey] | None = None
    x448_key: PrivateKey[x448.X448PrivateKey] | None = None
    rsa_or_ec_key: PrivateKey[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey] | None = None
    partner_key: PublicKey[ed25519.Ed25519PublicKey] | None = None
```

The public key classes are in the same modules, with `Public` in place of `Private`, e.g.
`ec.EllipticCurvePublicKey`.

A key of another kind is refused with an error such as `expected an RSA or EC private key, got an
Ed25519 private key`.

### Algorithms

A key's `.alg` is the JWA algorithm it's used with, e.g. to sign with `algorithm=key.alg`. Its JWK
says the same. The algorithms a key can be used with depend on its kind (and for EC keys, the
curve):

| Key | Default `alg` | Others |
| --- | --- | --- |
| RSA | RS256 | RS384, RS512, PS256, PS384, PS512, RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512 |
| EC P-256 | ES256 | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-0, HPKE-7, HPKE-0-KE, HPKE-7-KE |
| EC P-384 | ES384 | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-1, HPKE-1-KE |
| EC P-521 | ES512 | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-2, HPKE-2-KE |
| EC secp256k1 | ES256K | |
| Ed25519 | Ed25519 | EdDSA |
| Ed448 | Ed448 | EdDSA |
| X25519 | ECDH-ES | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-3, HPKE-4, HPKE-3-KE |
| X448 | ECDH-ES | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, HPKE-5, HPKE-6, HPKE-5-KE |

The RSA-OAEP, ECDH-ES and HPKE algorithms encrypt (the JWK's `use` is `enc`); the others sign.

Keys on other EC curves, e.g. brainpoolP256r1, are refused: JWKs have no representation for them,
so they'd have no algorithm or key ID either.

**An algorithm other than the default**, e.g. RS512 or RSA-PSS for an RSA key, is set with `Alg(...)` in the field's
annotation:

```python
from typing import Annotated

from pydantic_cryptography import Alg


class PSSSettings(BaseSettings):
    signing_key: Annotated[PrivateKey[rsa.RSAPrivateKey], Alg("PS256")]


pss_key = PSSSettings().signing_key
assert pss_key.alg == pss_key.public_jwk.alg == "PS256"
```

The algorithm must fit every kind of key the field allows: `Alg("PS256")` on a plain `PrivateKey`
raises a `TypeError` when the class is defined. For EC keys, it's also checked against the curve
when a key is loaded, e.g. ES384 needs a P-384 key. It works on an optional field too:
`Annotated[PrivateKey[rsa.RSAPrivateKey] | None, Alg("PS256")]`. Outside a model, `load()` and the
constructor take it as well: `PrivateKey.load(pem, "RSA", alg="PS256")`.

For Ed25519 and Ed448 keys, the defaults are the fully-specified algorithms of
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), which deprecates the older `EdDSA`. Not every
library knows them yet: PyJWT doesn't as of 2.15 ([issue](https://github.com/jpadilla/pyjwt/issues/1190),
[pull request](https://github.com/jpadilla/pyjwt/pull/1199)), and it can't use a JWK that has them.
Until your verifiers do, use `Alg("EdDSA")`, and sign with `algorithm=key.alg` as usual. With
PyJWT:

<!-- readme-test: needs jwt -->
```python
from typing import Annotated

import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519

from pydantic_cryptography import JWKS, Alg

os.environ["ED25519_SIGNING_KEY"] = PrivateKey(ed25519.Ed25519PrivateKey.generate()).private_pem


class EdDSASettings(BaseSettings):
    ed25519_signing_key: Annotated[PrivateKey[ed25519.Ed25519PrivateKey], Alg("EdDSA")]


ed_key = EdDSASettings().ed25519_signing_key
assert ed_key.alg == ed_key.public_jwk.alg == "EdDSA"
token = jwt.encode(
    {"sub": "someone"}, ed_key.key, algorithm=ed_key.alg, headers={"kid": ed_key.kid}
)

# a verifier using your JWKS, e.g. with PyJWT's PyJWKClient, finds the key by its kid
jwk_set = jwt.PyJWKSet.from_dict(JWKS.from_keys(ed_key).model_dump())
claims = jwt.decode(token, jwk_set[ed_key.kid], algorithms=["EdDSA"])
assert claims == {"sub": "someone"}
```

The names of the kinds of keys (`"RSA"`, `"EC"`, ...) and of the algorithms (`"RS256"`, ...) are
typed as `KindName` and `AlgName`, which you can import too, e.g. for a value from your own config.

## JWKs

`.public_jwk` is a Pydantic model of the key's JWK: an `RSAPublicJWK` (with `n` and `e`), an
`ECPublicJWK` (`crv`, `x` and `y`) or an `OKPPublicJWK` (`crv` and `x`), each also with `kty`, the
key ID as `kid`, and `use` and `alg`. `use` follows from `alg`: `enc` for the algorithms that
encrypt, `sig` for the others. `isinstance` tells the kinds apart:

```python
from pydantic_cryptography import RSAPublicJWK

jwk = settings.signing_key.public_jwk
assert isinstance(jwk, RSAPublicJWK)
assert (jwk.kty, jwk.use, jwk.alg, jwk.e) == ("RSA", "sig", "RS256", "AQAB")
```

`JWKS.from_keys()` takes any number of keys (`PrivateKey` or `PublicKey`). `None` is skipped, so you
can pass an optional setting directly:

```python
assert JWKS.from_keys(pss_key, settings.previous_signing_key).keys == [pss_key.public_jwk]
```

A key that's already in the set is left out. The same key with two different algorithms raises an
error, as a verifier couldn't tell which one to use.

Both are Pydantic models: `.model_dump_json()` gives the JSON, and `.model_dump()` a dict.

## Settings tips

**Multi-line values.** Environment variables can hold line breaks, and so can double-quoted values
in a `.env` file. Where that's awkward, write the key on one line with `\n` in place of the line
breaks. Kubernetes and Docker secrets mounted as files work with pydantic-settings' `secrets_dir`.

**Several keys**, e.g. for a key rotation, go in a list. As for any list in pydantic-settings, the
environment variable is then a JSON array, where the line breaks of a key are written as `\n`:
`SIGNING_KEYS='["-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"]'`.

```python
import json

from pydantic import Field

os.environ["SIGNING_KEYS"] = json.dumps([settings.signing_key.private_pem])


class RotatingSettings(BaseSettings):
    # The first key signs, and all of them are published. To rotate, add the new key last, so it's
    # published before anything is signed with it; then move it first; and remove the old key once
    # nothing signed with it is in use any more.
    signing_keys: list[PrivateKey[rsa.RSAPrivateKey]] = Field(min_length=1)


rotating = RotatingSettings()
signing_key = rotating.signing_keys[0]
assert JWKS.from_keys(*rotating.signing_keys).keys == [signing_key.public_jwk]
```

A mistake in one of the keys is reported with its position, e.g. `signing_keys.1`.

**A default key**, e.g. for development, can be given as text. `PrivateKey.load()` with the kind
keeps type checkers happy, as they don't accept a string for the field. Keep such defaults out of
the production settings: there, a missing environment variable would mean signing with a key that's
in your repository.

```python
DEVELOPMENT_KEY = settings.signing_key.private_pem  # yours would be a literal PEM string


class DevelopmentSettings(BaseSettings):
    signing_key: PrivateKey[rsa.RSAPrivateKey] = PrivateKey.load(DEVELOPMENT_KEY, "RSA")
```

**A new key on each start**, when nothing needs to survive a restart. Each process gets its own
key, so with several workers or instances, one can't verify what another signed:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519


class EphemeralSettings(BaseSettings):
    session_key: PrivateKey[ed25519.Ed25519PrivateKey] = PrivateKey(
        ed25519.Ed25519PrivateKey.generate()
    )
```

## Limitations

- Encrypted (password-protected) private keys aren't supported. Decrypt one with `cryptography`
  (`load_pem_private_key(data, password)`) and pass the key object.
- DSA keys, and other kinds not listed above, are refused.
- RSA keys must be at least 2048 bits, as RFC 7518 requires for all the RSA algorithms.
- EC keys must be on the curves P-256, P-384, P-521 or secp256k1, the ones JWKs know.
- JWKs are output only: keys aren't loaded from JWKs, and there's no JWK of a private key.
- X.509 certificates aren't accepted: a `PublicKey` takes the key itself. Take it out of a
  certificate with `cryptography` (`load_pem_x509_certificate(data).public_key()`) and pass the key
  object.
- PyJWT (as of 2.15) supports Ed25519 and Ed448 keys, but only with the older `alg` `EdDSA`, not
  `Ed25519` / `Ed448`, the defaults here: signing with them fails, and `PyJWKClient` skips JWKs
  that have them. Set `Alg("EdDSA")` on the field until it does; see [Algorithms](#algorithms).

## License

[MIT](LICENSE)
