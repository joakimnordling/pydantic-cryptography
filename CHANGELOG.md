# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions
may contain breaking changes.

## [Unreleased]

## [0.1.0] - 2026-10-03

### Added

- `PrivateKey` and `PublicKey` Pydantic types for RSA, EC (P-256, P-384, P-521, secp256k1),
  Ed25519, Ed448, X25519 and X448 keys, loaded from PEM or OpenSSH text. A type argument, as in
  `PrivateKey[RSAPrivateKey]`, limits the kinds of keys accepted. RSA keys must be at least 2048
  bits (RFC 7518), and EC keys on one of the curves that JWKs know.
- Settings-friendly loading: indented keys (e.g. in a triple-quoted default) and keys on one line
  with literal `\n`s are accepted. Works with pydantic-settings.
- Private keys stay hidden: in their `repr`, when serialized to JSON, and in validation errors.
- Key fields describe themselves in their JSON schema, and so in OpenAPI: the kinds of keys and the
  formats they accept, e.g. "An RSA private key: PEM (PKCS#8, PKCS#1 or SEC 1) or OpenSSH".
- JWKs and JWK Sets as Pydantic models: `public_jwk` is an `RSAPublicJWK`, `ECPublicJWK` or
  `OKPPublicJWK`, and `JWKS.from_keys()` gives a `JWKS`, e.g. to return from a FastAPI endpoint,
  with its OpenAPI schema. Key IDs (`kid`) are the RFC 7638 thumbprint. Checked against the RFC
  examples and against joserfc. The default `alg` of Ed25519 and Ed448 keys is `Ed25519` or
  `Ed448` (RFC 9864), not the deprecated `EdDSA`.
- `Alg(...)`, to set the algorithm a key field's keys are used with, e.g.
  `Annotated[PrivateKey[RSAPrivateKey], Alg("RS512")]`; the key's `alg`, `use` and JWK follow it.
  It's checked against the kinds of keys the field allows when the class is defined, and against
  the EC curve when a key is loaded. It works on an optional field too, e.g.
  `Annotated[PrivateKey[RSAPrivateKey] | None, Alg("RS512")]`. `load()` and the constructors take
  an `alg` too.
- `PrivateKey.load()` and `PublicKey.load()`, with an optional kind (`"RSA"`, `"EC"`, ...) that
  type checkers understand.
- Type-checker support: mypy, pyright and ty.

[Unreleased]: https://github.com/joakimnordling/pydantic-cryptography/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/joakimnordling/pydantic-cryptography/releases/tag/v0.1.0
