"""Passwords (scrypt), RS256 signing keys, JWKS, token issue/verify, and the RBAC permission map."""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.errors import Forbidden, Unauthorized

# ---------- RBAC: the single source of truth for what each role may do ----------
_VIEWER = {"boards:read", "boards:follow_up", "setup:run", "metrics:read", "jobs:read"}
PERMISSIONS: dict[str, frozenset[str]] = {
    "VIEWER": frozenset(_VIEWER),
    "EDITOR": frozenset(_VIEWER | {"metrics:write"}),
    "ADMIN": frozenset(_VIEWER | {"metrics:write", "users:read", "users:write"}),
}
ROLES = tuple(PERMISSIONS)

# ---------- passwords ----------
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))  # equalises timing for unknown emails


# ---------- signing keys ----------
@lru_cache
def private_key() -> rsa.RSAPrivateKey:
    s = get_settings()
    if s.jwt_private_key_b64:
        pem = base64.b64decode(s.jwt_private_key_b64)
    else:  # local development: generate once and keep it on disk so restarts don't invalidate sessions
        path = Path(s.key_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        pem = path.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


def jwks() -> dict:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key().public_key(), as_dict=True)
    return {"keys": [jwk | {"kid": get_settings().jwt_key_id, "use": "sig", "alg": "RS256"}]}


# ---------- tokens ----------
@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    email: str

    @property
    def permissions(self) -> frozenset[str]:
        return PERMISSIONS.get(self.role, frozenset())


def issue_access_token(user_id: str, role: str, email: str) -> tuple[str, int]:
    s = get_settings()
    now = datetime.now(UTC)
    ttl = s.access_token_minutes * 60
    claims = {"sub": user_id, "email": email, "role": role, "perms": sorted(PERMISSIONS[role]),
              "iss": s.jwt_issuer, "aud": s.jwt_audience, "iat": now, "exp": now + timedelta(seconds=ttl),
              "typ": "access"}
    return jwt.encode(claims, private_key(), algorithm="RS256", headers={"kid": s.jwt_key_id}), ttl


def new_refresh_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_access_token(token: str) -> Principal:
    s = get_settings()
    try:
        claims = jwt.decode(token, private_key().public_key(), algorithms=["RS256"], issuer=s.jwt_issuer,
                            audience=s.jwt_audience)
    except jwt.ExpiredSignatureError as exc:
        raise Unauthorized("Access token expired") from exc
    except jwt.PyJWTError as exc:
        raise Unauthorized("Invalid token") from exc
    if claims.get("typ") != "access" or claims.get("role") not in PERMISSIONS:
        raise Unauthorized("Invalid token")
    return Principal(claims["sub"], claims["role"], claims.get("email", ""))


bearer = HTTPBearer(auto_error=False)


async def current_principal(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if creds is None:
        raise Unauthorized("Missing bearer token")
    return decode_access_token(creds.credentials)


def require(*permissions: str):  # noqa: ANN201
    async def check(me: Principal = Depends(current_principal)) -> Principal:
        missing = [p for p in permissions if p not in me.permissions]
        if missing:
            raise Forbidden("You don't have permission to do this", details={"missing": missing, "role": me.role})
        return me

    return check
