"""
The `PrivateKey` and `PublicKey` Pydantic types.

How a key field works:

- `PrivateKey[RSAPrivateKey]` is `Annotated[PrivateKey, _AllowedTypes(...)]` at runtime
  (`_parametrize`), as pydantic-settings would take a generic class for a complex value and parse
  its environment variable as JSON. Type checkers see a generic class. A plain `PrivateKey`
  allows every supported kind of key.
- Its core schema (`_KeyBase._core_schema`) is a chain. First `RedactedInput` wraps the input, so
  that Pydantic shows `**********` instead of it in errors. Then `_KeyBase._validate` loads the
  key (`_load_private` or `_load_public` for text), and checks that it's fit for use
  (`_check_key`), of an allowed kind (`_check_allowed`) and that the algorithm fits it.
- The schema's metadata (under `_SCHEMA_KEY`) has the class and the allowed key classes.
  `Alg(...)` finds them there, checks when the class is defined that the algorithm fits every
  allowed kind, and builds the schema again with the algorithm.
- `_KeyBase` has what the two classes share. `PrivateKey` and `PublicKey` add the `key` typed with
  their type variable, the overloads for type checkers, and what differs (parsing, DER, JSON).

The algorithms and JWKs are in `_jwk`, and the kinds of keys in `_kinds`.
"""

import hmac
import types
import typing
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import cached_property, partial
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    ClassVar,
    Generic,
    Literal,
    Self,
    TypeAlias,
    Union,
    cast,
    get_args,
    get_origin,
    overload,
)

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_private_key,
    load_ssh_public_key,
)
from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema
from typing_extensions import TypeVar

from . import _jwk, _kinds
from ._jwk import AlgName, PublicJWK
from ._kinds import KindName, SupportedPrivateKey, SupportedPublicKey

__all__ = ["Alg", "PrivateKey", "PublicKey"]

PrivateKeyT = TypeVar(
    "PrivateKeyT", bound=SupportedPrivateKey, default=SupportedPrivateKey, covariant=True
)
PublicKeyT = TypeVar(
    "PublicKeyT", bound=SupportedPublicKey, default=SupportedPublicKey, covariant=True
)

_PRIVATE_KEY_TYPES = tuple(kind.private for kind in _kinds.KEY_KINDS)
_PUBLIC_KEY_TYPES = tuple(kind.public for kind in _kinds.KEY_KINDS)

_MASK = "**********"


class RedactedInput:
    """
    The input of a key field, as Pydantic sees it after the first validation step.

    Pydantic includes the input in validation errors, which end up in logs. For a private key put
    in the wrong field, or of the wrong type, that would be the key itself; so the key is validated
    from this wrapper, which Pydantic shows as `**********`.
    """

    __slots__ = ("value",)

    def __init__(self, value: object) -> None:
        self.value = value

    def __repr__(self) -> str:
        return repr(_MASK)


def _normalize(data: str | bytes) -> bytes:
    """
    Clean up PEM (or OpenSSH) text as it typically comes from settings and environment variables.

    Strips the indentation of each line (a triple-quoted default in a class body), and turns
    literal `\\n` into line breaks when the value has none (a key squeezed onto one line).
    """
    if isinstance(data, bytes):
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("the key isn't PEM text: it contains non-ASCII bytes") from None
    data = data.strip()
    if "\n" not in data and "\\n" in data:
        data = data.replace("\\r\\n", "\n").replace("\\n", "\n")
    return "".join(f"{line.strip()}\n" for line in data.splitlines()).encode("ascii")


# How an OpenSSH public key line starts, e.g. "ssh-ed25519 AAAA..." or "ecdsa-sha2-nistp256 ..."
_SSH_PUBLIC_KEY_PREFIXES = (b"ssh-", b"ecdsa-")


def _load_private(data: str | bytes) -> SupportedPrivateKey:
    text = _normalize(data)
    if b"PUBLIC KEY-----" in text or text.startswith(_SSH_PUBLIC_KEY_PREFIXES):
        raise ValueError("expected a private key, got a public key")
    if not text.startswith(b"-----BEGIN "):
        raise ValueError("expected a PEM encoded private key, starting with '-----BEGIN '")
    key: PrivateKeyTypes
    try:
        if text.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = load_ssh_private_key(text, password=None)
        else:
            key = load_pem_private_key(text, password=None)
    except TypeError as exc:
        # cryptography raises TypeError for an encrypted key when no password is given
        raise ValueError("encrypted private keys aren't supported") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("invalid or unsupported private key: it couldn't be loaded") from exc
    if not isinstance(key, _PRIVATE_KEY_TYPES):
        raise ValueError(f"unsupported type of private key: {type(key).__name__}")
    return key


def _load_public(data: str | bytes) -> SupportedPublicKey:
    text = _normalize(data)
    if b"PRIVATE KEY-----" in text:
        raise ValueError("expected a public key, got a private key")
    is_ssh = text.startswith(_SSH_PUBLIC_KEY_PREFIXES)
    if not is_ssh and not text.startswith(b"-----BEGIN "):
        raise ValueError(
            "expected a PEM encoded public key, starting with '-----BEGIN ', or an OpenSSH public "
            "key line"
        )
    key: PublicKeyTypes
    try:
        key = load_ssh_public_key(text) if is_ssh else load_pem_public_key(text)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("invalid or unsupported public key: it couldn't be loaded") from exc
    if not isinstance(key, _PUBLIC_KEY_TYPES):
        raise ValueError(f"unsupported type of public key: {type(key).__name__}")
    return key


def _allowed_types(source: Any, supported: tuple[type[Any], ...]) -> tuple[type[Any], ...]:
    """The key classes that a field annotated with `source` (`PrivateKey[...]`) accepts."""
    args = get_args(source)
    if not args:
        return supported
    arg = args[0]
    if isinstance(arg, typing.TypeVar):  # in a generic model that isn't parametrized
        arg = arg.__bound__
    if arg is None or arg is Any:
        return supported
    members = get_args(arg) if get_origin(arg) in (Union, types.UnionType) else (arg,)
    for member in members:
        if not (isinstance(member, type) and issubclass(member, supported)):
            names = ", ".join(t.__name__ for t in supported)
            raise TypeError(f"{source} isn't supported: the type argument must be one of {names}")
    return tuple(members)


def _or(names: Sequence[str]) -> str:
    """The names as text: "RSA", "RSA or EC", "RSA, EC or Ed25519"."""
    *others, last = names
    return f"{', '.join(others)} or {last}" if others else last


def _check_allowed(key: "_KeyBase", allowed: tuple[type[Any], ...], what: str) -> None:
    if isinstance(key._any_key, allowed):
        return
    expected = _or([kind.name for kind in _kinds.kinds_matching(allowed)])
    actual = _kinds.kind_of(key._any_key).name
    raise ValueError(f"expected an {expected} {what}, got an {actual} {what}")


@dataclass(frozen=True)
class _AllowedTypes:
    """
    Pydantic metadata that limits a key field to some kinds of keys.

    `PrivateKey[RSAPrivateKey]` is `Annotated[PrivateKey, _AllowedTypes(...)]` at runtime (see
    `_parametrize`), while type checkers see a generic class.
    """

    cls: "type[PrivateKey[Any] | PublicKey[Any]]"
    allowed: tuple[type[Any], ...]

    # The schema is the class's, but with the limit. Not an after validator on the class's schema:
    # Pydantic would include the original input in its errors, and that may be a private key.
    def __get_pydantic_core_schema__(
        self, source: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return self.cls._core_schema(self.allowed)

    def __get_pydantic_json_schema__(
        self, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return self.cls.__get_pydantic_json_schema__(schema, handler)


# The key in a key field's core schema metadata that `Alg` finds the field's class and allowed key
# classes under
_SCHEMA_KEY = "pydantic_cryptography"

_KeyField: TypeAlias = "tuple[type[PrivateKey[Any] | PublicKey[Any]], tuple[type[Any], ...]]"


def _key_field(schema: CoreSchema) -> "_KeyField | None":
    """The class and allowed key classes of a key field's core schema; None for other schemas."""
    return cast("_KeyField | None", (schema.get("metadata") or {}).get(_SCHEMA_KEY))


def _unwrap_nullable(schema: CoreSchema) -> tuple[CoreSchema, bool]:
    """The schema of the type in an optional type's (`X | None`) schema, and whether it was one."""
    if schema["type"] == "nullable":
        return schema["schema"], True
    return schema, False


@dataclass(frozen=True)
class Alg:
    """
    Pydantic metadata: the JWA algorithm that the keys of a field are used with.

    E.g. `Annotated[PrivateKey[RSAPrivateKey], Alg("RS512")]`. The key's `alg` and JWK follow it,
    and so does the JWK's "use": "enc" for the encryption algorithms, otherwise "sig". It must fit
    every kind of key the field allows; for EC keys, it's checked against the curve when a key is
    loaded. An optional key field takes it too: `Annotated[PrivateKey[RSAPrivateKey] | None,
    Alg("RS512")]`.
    """

    name: AlgName

    def __post_init__(self) -> None:
        if self.name not in get_args(AlgName):
            raise ValueError(f"unknown algorithm {self.name!r}")

    def __get_pydantic_core_schema__(
        self, source: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        schema, nullable = _unwrap_nullable(handler(source))
        field = _key_field(schema)
        if field is None:
            raise TypeError(
                f"{self!r} only applies to a PrivateKey or PublicKey type, e.g. "
                "Annotated[PrivateKey[rsa.RSAPrivateKey], Alg('RS512')]"
            )
        cls, allowed = field
        unfit = [
            kind.name
            for kind in _kinds.kinds_matching(allowed)
            if self.name not in _jwk.kind_algs(kind.name)
        ]
        if unfit:
            raise TypeError(f"{self!r} doesn't fit {_or(unfit)} keys, which the field allows")
        result: CoreSchema = cls._core_schema(allowed, self.name)
        return core_schema.nullable_schema(result) if nullable else result

    def __get_pydantic_json_schema__(
        self, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        inner, nullable = _unwrap_nullable(schema)  # the schema from __get_pydantic_core_schema__
        cls, _ = cast(_KeyField, _key_field(inner))
        result: JsonSchemaValue = cls.__get_pydantic_json_schema__(inner, handler)
        return {"anyOf": [result, {"type": "null"}]} if nullable else result


def _parametrize(cls: "type[PrivateKey[Any] | PublicKey[Any]]", alias: Any) -> Any:
    """
    What `PrivateKey[...]` or `PublicKey[...]` is at runtime.

    Not the usual generic alias, as pydantic-settings takes a field of a generic class (other than
    a model) for a complex value, and tries to parse its environment variable as JSON. With a type
    variable in a generic class, it stays one, so that Pydantic can replace it.
    """
    if alias.__parameters__:
        return alias
    annotated: Any = Annotated  # built at runtime; type checkers don't take a variable in it
    return annotated[cls, _AllowedTypes(cls, _allowed_types(alias, cls._SUPPORTED))]


def _describe(key: SupportedPrivateKey | SupportedPublicKey) -> str:
    """A short description of the key that doesn't reveal it, e.g. "RSA 2048" or "EC P-256"."""
    name = _kinds.kind_of(key).name
    if isinstance(key, RSAPrivateKey | RSAPublicKey):
        return f"{name} {key.key_size}"
    if isinstance(key, EllipticCurvePrivateKey | EllipticCurvePublicKey):
        return f"{name} {_jwk.EC_CURVES[key.curve.name].crv}"
    return name


# RFC 7518 requires RSA keys of at least 2048 bits for all its RSA algorithms (sections 3.3, 3.5
# and 4.2-4.3).
_MIN_RSA_KEY_SIZE = 2048


def _check_key(key: SupportedPrivateKey | SupportedPublicKey) -> None:
    """
    Refuse a key of a supported kind that isn't fit for use.

    That's an RSA key that's too small, or an EC key on a curve without a JWK representation (e.g.
    brainpoolP256r1), which would have no algorithm or key ID either.
    """
    if isinstance(key, RSAPrivateKey | RSAPublicKey) and key.key_size < _MIN_RSA_KEY_SIZE:
        raise ValueError(f"RSA keys must be at least {_MIN_RSA_KEY_SIZE} bits, got {key.key_size}")
    if (
        isinstance(key, EllipticCurvePrivateKey | EllipticCurvePublicKey)
        and key.curve.name not in _jwk.EC_CURVES
    ):
        crvs = _or([curve.crv for curve in _jwk.EC_CURVES.values()])
        raise ValueError(f"unsupported EC curve {key.curve.name}, expected {crvs}")


class _KeyBase:
    """What `PrivateKey` and `PublicKey` share."""

    _SUPPORTED: ClassVar[tuple[type[SupportedPrivateKey | SupportedPublicKey], ...]]  # key classes
    _WHAT: ClassVar[str]  # "private key" or "public key", for messages
    _OTHER: ClassVar[str]  # and the other one

    # The algorithm, if it isn't the default one
    _alg: AlgName | None

    def __init__(self, key: SupportedPrivateKey | SupportedPublicKey, alg: AlgName | None) -> None:
        # (the subclass has kept the key, typed with its type variable)
        if not isinstance(key, self._SUPPORTED):
            raise TypeError(f"unsupported type of {self._WHAT}: {type(key).__name__}")
        _check_key(key)
        self._set_alg(alg)

    if not TYPE_CHECKING:  # pragma: no branch (see _parametrize)

        def __class_getitem__(cls, params):
            return _parametrize(cls, super().__class_getitem__(params))

    @property
    def _any_key(self) -> SupportedPrivateKey | SupportedPublicKey:
        # the key as the union of the supported types; type checkers can't call methods through
        # the TypeVar bound to it
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    def _public(self) -> SupportedPublicKey:
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    def _der(self) -> bytes:
        """The key, DER encoded; it's what pickles and equality use."""
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    @classmethod
    def _from_der(cls, der: bytes, alg: AlgName | None) -> "_KeyBase":
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    @staticmethod
    def _parse(data: str | bytes) -> SupportedPrivateKey | SupportedPublicKey:
        """The key in PEM or OpenSSH text."""
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    @staticmethod
    def _kind_class(kind: _kinds.KeyKind) -> type[Any]:
        """The private or the public key class of the kind."""
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    def _json(self) -> str:
        """The key serialized to JSON."""
        raise NotImplementedError  # pragma: no cover (both subclasses implement it)

    @classmethod
    def _load(cls, data: str | bytes, kind: KindName | None, alg: AlgName | None) -> Self:
        """What `load()` does."""
        key = cls(cls._parse(data), None)
        if kind is not None:
            _check_allowed(key, (cls._kind_class(_kinds.kind_by_name(kind)),), cls._WHAT)
        return cls(key._any_key, alg) if alg else key

    def _set_alg(self, alg: AlgName | None) -> None:
        self._alg = None
        if alg is None:
            return
        algs = _jwk.algs(self._public())
        if alg not in algs:
            raise ValueError(
                f"{alg} isn't an algorithm for {_describe(self._public())} keys, expected one "
                f"of {', '.join(algs)}"
            )
        if alg != algs[0]:
            self._alg = alg

    def __repr__(self) -> str:
        alg = f", alg={self._alg}" if self._alg else ""
        return f"{type(self).__name__}({_describe(self._public())}{alg})"

    @cached_property
    def _public_members(self) -> dict[str, str]:
        return _jwk.public_members(self._public())

    @property
    def kty(self) -> Literal["RSA", "EC", "OKP"]:
        """The JWK key type: "RSA", "EC" or "OKP"."""
        return self.public_jwk.kty

    @property
    def alg(self) -> AlgName:
        """
        The JWA algorithm the key is used with.

        The one given with `Alg(...)` on the field, or to `load()` or the constructor. Otherwise
        the default for the key: RS256 for RSA; ES256, ES384, ES512 or ES256K for EC, depending
        on the curve; Ed25519 or Ed448 for those keys (RFC 9864, which deprecates EdDSA); and
        ECDH-ES for X25519 and X448.
        """
        return self._alg or _jwk.algs(self._public())[0]

    @cached_property
    def kid(self) -> str:
        """The key ID: the key's SHA-256 JWK thumbprint (RFC 7638)."""
        return _jwk.thumbprint(self._public())

    @cached_property
    def public_jwk(self) -> PublicJWK:
        """The public key as a JWK (a Pydantic model; `.model_dump()` gives a dict)."""
        members = self._public_members
        jwk = {
            "kty": members["kty"],
            "kid": self.kid,
            "use": _jwk.use(self.alg),
            "alg": self.alg,
            **members,
        }
        return _jwk.PUBLIC_JWK_ADAPTER.validate_python(jwk)

    @cached_property
    def public_pem(self) -> str:
        """The public key, PEM encoded (SubjectPublicKeyInfo, "-----BEGIN PUBLIC KEY-----")."""
        pem = self._public().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return pem.decode("ascii")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        # in constant time: for a private key, the DER is the key itself
        return self._alg == other._alg and hmac.compare_digest(self._der(), other._der())

    def __hash__(self) -> int:
        return hash(self.public_pem)

    # The key objects can't be copied or pickled; the wrapper is immutable, so a copy can be itself,
    # and it pickles as its DER encoding and algorithm.
    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> Self:
        return self

    def __reduce__(
        self,
    ) -> tuple[Callable[[bytes, AlgName | None], "_KeyBase"], tuple[bytes, AlgName | None]]:
        return self._from_der, (self._der(), self._alg)

    @classmethod
    def __get_pydantic_core_schema__(cls, source: Any, handler: GetCoreSchemaHandler) -> CoreSchema:
        return cls._core_schema(_allowed_types(source, cls._SUPPORTED))

    @classmethod
    def _core_schema(cls, allowed: tuple[type[Any], ...], alg: AlgName | None = None) -> CoreSchema:
        return core_schema.chain_schema(
            [
                core_schema.no_info_plain_validator_function(RedactedInput),
                core_schema.no_info_plain_validator_function(partial(cls._validate, allowed, alg)),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                cls._json, when_used="json"
            ),
            metadata={_SCHEMA_KEY: (cls, allowed)},
        )

    @classmethod
    def _describe_field(cls, schema: CoreSchema) -> str:
        """The keys a field accepts, for its JSON schema, e.g. "An RSA or EC private key"."""
        _, allowed = cast(_KeyField, _key_field(schema))  # the schema from _core_schema()
        kinds = [kind.name for kind in _kinds.kinds_matching(allowed)]
        if len(kinds) == len(_kinds.KEY_KINDS):
            return f"A {cls._WHAT} ({_or(kinds)})"
        return f"An {_or(kinds)} {cls._WHAT}"

    @classmethod
    def _validate(
        cls, allowed: tuple[type[Any], ...], alg: AlgName | None, value: RedactedInput
    ) -> Self:
        raw = value.value
        if isinstance(raw, cls):
            result = raw
        elif isinstance(raw, cls._SUPPORTED):
            result = cls(raw, None)
        elif isinstance(raw, str | bytes):
            result = cls(cls._parse(raw), None)
        elif isinstance(raw, (_KeyBase, *_PRIVATE_KEY_TYPES, *_PUBLIC_KEY_TYPES)):
            raise ValueError(f"expected a {cls._WHAT}, got a {cls._OTHER}")
        else:
            raise ValueError(f"expected a PEM encoded {cls._WHAT} as str, got {type(raw).__name__}")
        _check_allowed(result, allowed, cls._WHAT)
        if alg is not None and result.alg != alg:
            result = cls(result._any_key, alg)
        return result


class PrivateKey(_KeyBase, Generic[PrivateKeyT]):
    """
    A private key: RSA, EC, Ed25519, Ed448, X25519 or X448.

    As a Pydantic field, it's loaded from PEM (PKCS#8, PKCS#1 or SEC 1) or OpenSSH text. The type
    argument limits the kinds of keys accepted: `PrivateKey[RSAPrivateKey]` accepts only RSA
    keys, `PrivateKey[RSAPrivateKey | EllipticCurvePrivateKey]` RSA and EC keys, and a plain
    `PrivateKey` any of them. `Alg(...)` sets the algorithm the keys are used with, e.g.
    `Annotated[PrivateKey[RSAPrivateKey], Alg("RS512")]`.

    Like Pydantic's `SecretStr`, it doesn't reveal the key in its `repr`, or when serialized to
    JSON; `private_pem` gives the PEM.
    """

    _SUPPORTED = _PRIVATE_KEY_TYPES
    _WHAT = "private key"
    _OTHER = "public key"

    def __init__(self, key: PrivateKeyT, alg: AlgName | None = None) -> None:
        self._key: PrivateKeyT = key
        super().__init__(key, alg)

    # With `kind`, type checkers know the kind of key; `PrivateKey.load(pem, RSAPrivateKey)` would
    # be nicer, but mypy doesn't accept the abstract key classes where a class is expected.
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: None = None, *, alg: AlgName | None = None
    ) -> "PrivateKey": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["RSA"], *, alg: AlgName | None = None
    ) -> "PrivateKey[RSAPrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["EC"], *, alg: AlgName | None = None
    ) -> "PrivateKey[EllipticCurvePrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["Ed25519"], *, alg: AlgName | None = None
    ) -> "PrivateKey[Ed25519PrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["Ed448"], *, alg: AlgName | None = None
    ) -> "PrivateKey[Ed448PrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["X25519"], *, alg: AlgName | None = None
    ) -> "PrivateKey[X25519PrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["X448"], *, alg: AlgName | None = None
    ) -> "PrivateKey[X448PrivateKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: KindName | None = None, *, alg: AlgName | None = None
    ) -> "PrivateKey": ...  # a kind known only at runtime
    @classmethod
    def load(
        cls, data: str | bytes, kind: KindName | None = None, *, alg: AlgName | None = None
    ) -> "PrivateKey[Any]":
        """
        Load a private key from PEM or OpenSSH text, as a Pydantic field does.

        With `kind` ("RSA", "EC", "Ed25519", "Ed448", "X25519" or "X448"), only that kind of key is
        accepted, e.g. for a settings default: `KEY: PrivateKey[RSAPrivateKey] = PrivateKey.load(
        DEVELOPMENT_KEY, "RSA")`. With `alg`, the key is used with that algorithm, as with
        `Alg(...)` on a field.
        """
        return cls._load(data, kind, alg)

    @property
    def key(self) -> PrivateKeyT:
        """The `cryptography` private key object, e.g. to sign with."""
        return self._key

    @property
    def _any_key(self) -> SupportedPrivateKey:
        return self._key

    def _public(self) -> SupportedPublicKey:
        return self._any_key.public_key()

    # The public key matching each kind of private key, for type checkers.
    @overload
    def public_key(self: "PrivateKey[RSAPrivateKey]") -> "PublicKey[RSAPublicKey]": ...
    @overload
    def public_key(
        self: "PrivateKey[EllipticCurvePrivateKey]",
    ) -> "PublicKey[EllipticCurvePublicKey]": ...
    @overload
    def public_key(self: "PrivateKey[Ed25519PrivateKey]") -> "PublicKey[Ed25519PublicKey]": ...
    @overload
    def public_key(self: "PrivateKey[Ed448PrivateKey]") -> "PublicKey[Ed448PublicKey]": ...
    @overload
    def public_key(self: "PrivateKey[X25519PrivateKey]") -> "PublicKey[X25519PublicKey]": ...
    @overload
    def public_key(self: "PrivateKey[X448PrivateKey]") -> "PublicKey[X448PublicKey]": ...
    @overload
    def public_key(self) -> "PublicKey": ...
    def public_key(self) -> "PublicKey[Any]":
        """The public key, as a `PublicKey`."""
        return PublicKey(self._public(), self._alg)

    @property
    def private_pem(self) -> str:
        """The private key, PEM encoded (PKCS#8, "-----BEGIN PRIVATE KEY-----")."""
        return self._private_bytes(Encoding.PEM).decode("ascii")

    def _private_bytes(self, encoding: Encoding) -> bytes:
        return self._any_key.private_bytes(encoding, PrivateFormat.PKCS8, NoEncryption())

    def _der(self) -> bytes:
        return self._private_bytes(Encoding.DER)

    @classmethod
    def _from_der(cls, der: bytes, alg: AlgName | None) -> "PrivateKey":
        # the pickled key was of a supported type, so it loads as one again
        return PrivateKey(cast(SupportedPrivateKey, load_der_private_key(der, password=None)), alg)

    @staticmethod
    def _parse(data: str | bytes) -> SupportedPrivateKey:
        return _load_private(data)

    @staticmethod
    def _kind_class(kind: _kinds.KeyKind) -> type[Any]:
        return kind.private

    def _json(self) -> str:
        return _MASK

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return {
            "type": "string",
            "format": "password",
            "writeOnly": True,
            "description": (
                f"{cls._describe_field(schema)}: PEM (PKCS#8, PKCS#1 or SEC 1) or OpenSSH"
            ),
        }


class PublicKey(_KeyBase, Generic[PublicKeyT]):
    """
    A public key: RSA, EC, Ed25519, Ed448, X25519 or X448.

    As a Pydantic field, it's loaded from PEM (SubjectPublicKeyInfo or PKCS#1) or an OpenSSH public
    key line ("ssh-ed25519 AAAA..."), and serialized to JSON as PEM. The type argument limits the
    kinds of keys accepted, and `Alg(...)` sets the algorithm, as for `PrivateKey`.
    """

    _SUPPORTED = _PUBLIC_KEY_TYPES
    _WHAT = "public key"
    _OTHER = "private key"

    def __init__(self, key: PublicKeyT, alg: AlgName | None = None) -> None:
        self._key: PublicKeyT = key
        super().__init__(key, alg)

    # With `kind`, type checkers know the kind of key; `load(pem, RSAPrivateKey)` would be
    # nicer, but mypy doesn't accept the abstract key classes where a class is expected.
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: None = None, *, alg: AlgName | None = None
    ) -> "PublicKey": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["RSA"], *, alg: AlgName | None = None
    ) -> "PublicKey[RSAPublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["EC"], *, alg: AlgName | None = None
    ) -> "PublicKey[EllipticCurvePublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["Ed25519"], *, alg: AlgName | None = None
    ) -> "PublicKey[Ed25519PublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["Ed448"], *, alg: AlgName | None = None
    ) -> "PublicKey[Ed448PublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["X25519"], *, alg: AlgName | None = None
    ) -> "PublicKey[X25519PublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: Literal["X448"], *, alg: AlgName | None = None
    ) -> "PublicKey[X448PublicKey]": ...
    @overload
    @classmethod
    def load(
        cls, data: str | bytes, kind: KindName | None = None, *, alg: AlgName | None = None
    ) -> "PublicKey": ...  # a kind known only at runtime
    @classmethod
    def load(
        cls, data: str | bytes, kind: KindName | None = None, *, alg: AlgName | None = None
    ) -> "PublicKey[Any]":
        """
        Load a public key from PEM or OpenSSH text, as a Pydantic field does.

        With `kind` ("RSA", "EC", "Ed25519", "Ed448", "X25519" or "X448"), only that kind of key is
        accepted. With `alg`, the key is used with that algorithm, as with `Alg(...)` on a field.
        """
        return cls._load(data, kind, alg)

    @property
    def key(self) -> PublicKeyT:
        """The `cryptography` public key object, e.g. to verify signatures with."""
        return self._key

    @property
    def _any_key(self) -> SupportedPublicKey:
        return self._key

    def _public(self) -> SupportedPublicKey:
        return self._any_key

    def _der(self) -> bytes:
        return self._any_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @classmethod
    def _from_der(cls, der: bytes, alg: AlgName | None) -> "PublicKey":
        # the pickled key was of a supported type, so it loads as one again
        return PublicKey(cast(SupportedPublicKey, load_der_public_key(der)), alg)

    @staticmethod
    def _parse(data: str | bytes) -> SupportedPublicKey:
        return _load_public(data)

    @staticmethod
    def _kind_class(kind: _kinds.KeyKind) -> type[Any]:
        return kind.public

    def _json(self) -> str:
        return self.public_pem

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return {
            "type": "string",
            "description": (
                f"{cls._describe_field(schema)}: PEM (SubjectPublicKeyInfo or PKCS#1) or an "
                "OpenSSH public key line"
            ),
        }
