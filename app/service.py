"""Accounts: sign-up, sign-in, refresh-token rotation, sign-out, admin management, bootstrap admin."""

import logging
import math
from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import throttle
from app.config import get_settings
from app.db import RefreshToken, User, as_utc, new_id, utcnow
from app.errors import AppError, Conflict, Forbidden, NotFound, Unauthorized
from app.security import (
    DUMMY_HASH,
    PERMISSIONS,
    hash_password,
    hash_refresh_token,
    issue_access_token,
    new_refresh_token,
    verify_password,
)

log = logging.getLogger(__name__)


class TooManyAttempts(AppError):
    status_code = 429
    code = "TOO_MANY_ATTEMPTS"


def _norm(email: str) -> str:
    return email.strip().lower()


async def issue_tokens(session: AsyncSession, user: User, family_id: str | None = None) -> dict[str, Any]:
    access, ttl = issue_access_token(user.id, user.role_cd, user.email)
    refresh, digest = new_refresh_token()
    session.add(RefreshToken(user_id=user.id, family_id=family_id or new_id(), token_hash=digest,
                             expires_at=utcnow() + timedelta(days=get_settings().refresh_token_days)))
    await session.commit()
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer", "expires_in": ttl,
            "user": user_view(user)}


def user_view(u: User) -> dict[str, Any]:
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "role": u.role_cd,
            "is_active": u.is_active, "last_login_at": u.last_login_at, "created_at": u.created_at,
            "permissions": sorted(PERMISSIONS.get(u.role_cd, ()))}


async def register(session: AsyncSession, *, email: str, password: str, display_name: str) -> dict[str, Any]:
    s = get_settings()
    if not s.allow_signup:
        raise Forbidden("Self sign-up is disabled; ask an administrator for an account")
    user = User(email=_norm(email), display_name=display_name.strip(), password_hash=hash_password(password),
                role_cd=s.signup_role, is_active=True, last_login_at=utcnow())
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise Conflict("An account with this email already exists") from exc
    log.info("user registered", extra={"ctx": {"user_id": user.id, "role": user.role_cd}})
    return await issue_tokens(session, user)


async def login(session: AsyncSession, *, email: str, password: str, client_ip: str) -> dict[str, Any]:
    email = _norm(email)
    await _check_rate_limit(email, client_ip)
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    ok = verify_password(password, user.password_hash if user else DUMMY_HASH)  # constant work either way
    if not user or not ok:
        await _record_failure(email, client_ip)
        raise Unauthorized("Email or password is incorrect")
    if not user.is_active:
        raise Forbidden("This account is deactivated")
    await _clear_failures(email, client_ip)
    user.last_login_at = utcnow()
    return await issue_tokens(session, user)


async def refresh(session: AsyncSession, token: str) -> dict[str, Any]:
    """Rotate: the presented token is revoked and a new one issued in the same family. Presenting an
    already-revoked token means it was stolen or replayed, so the whole family is revoked."""
    row = (await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(token)))).scalar_one_or_none()
    if row is None:
        raise Unauthorized("Invalid refresh token")
    if row.revoked_at is not None:
        await session.execute(update(RefreshToken).where(RefreshToken.family_id == row.family_id,
                                                         RefreshToken.revoked_at.is_(None))
                              .values(revoked_at=utcnow()))
        await session.commit()
        log.warning("refresh token reuse detected; family revoked", extra={"ctx": {"user_id": row.user_id}})
        raise Unauthorized("Refresh token was already used; please sign in again")
    if as_utc(row.expires_at) <= utcnow():
        raise Unauthorized("Session expired; please sign in again")
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise Unauthorized("Account unavailable")
    row.revoked_at = utcnow()
    return await issue_tokens(session, user, family_id=row.family_id)


async def logout(session: AsyncSession, token: str) -> None:
    row = (await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(token)))).scalar_one_or_none()
    if row is not None:
        await session.execute(update(RefreshToken).where(RefreshToken.family_id == row.family_id,
                                                         RefreshToken.revoked_at.is_(None))
                              .values(revoked_at=utcnow()))
        await session.commit()


async def get(session: AsyncSession, user_id: str) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise NotFound("User not found")
    return user


async def search(session: AsyncSession, *, q: str | None, role: str | None, page: int, size: int) -> dict[str, Any]:
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(User.email.like(like), func.lower(User.display_name).like(like)))
    if role:
        stmt = stmt.where(User.role_cd == role)
    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    stmt = stmt.order_by(User.created_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await session.execute(stmt)).scalars()
    return {"items": [user_view(u) for u in rows], "total": total, "page": page, "size": size,
            "pages": max(1, math.ceil(total / size))}


async def update_user(session: AsyncSession, actor_id: str, user_id: str, *, role: str | None,
                      is_active: bool | None) -> User:
    user = await get(session, user_id)
    losing_admin = user.role_cd == "ADMIN" and ((role and role != "ADMIN") or is_active is False)
    if losing_admin:
        admins = (await session.execute(select(func.count()).select_from(User).where(
            User.role_cd == "ADMIN", User.is_active.is_(True)))).scalar_one()
        if admins <= 1:
            raise Conflict("At least one active administrator must remain")
    if user_id == actor_id and is_active is False:
        raise Conflict("You can't deactivate your own account")
    if role:
        user.role_cd = role
    if is_active is not None:
        user.is_active = is_active
    if role or is_active is False:  # role/state change takes effect at the next refresh: end current sessions
        await session.execute(update(RefreshToken).where(RefreshToken.user_id == user.id,
                                                         RefreshToken.revoked_at.is_(None))
                              .values(revoked_at=utcnow()))
    await session.commit()
    await session.refresh(user)
    return user


async def ensure_bootstrap_admin(session: AsyncSession) -> None:
    """Create the configured admin if there is no admin yet (first start of a fresh database)."""
    s = get_settings()
    has_admin = (await session.execute(select(func.count()).select_from(User).where(User.role_cd == "ADMIN"))
                 ).scalar_one()
    if has_admin:
        return
    session.add(User(email=_norm(s.bootstrap_admin_email), display_name="Administrator",
                     password_hash=hash_password(s.bootstrap_admin_password), role_cd="ADMIN", is_active=True))
    try:
        await session.commit()
        log.info("bootstrap admin created", extra={"ctx": {"email": s.bootstrap_admin_email}})
    except IntegrityError:  # another worker created it, or the email exists as a non-admin
        await session.rollback()


# ---------- login throttling ----------
def _keys(email: str, ip: str) -> list[str]:
    return [f"login:fail:email:{email}", f"login:fail:ip:{ip}"]


async def _check_rate_limit(email: str, ip: str) -> None:
    if any(c >= get_settings().login_max_attempts for c in await throttle.counts(_keys(email, ip))):
        raise TooManyAttempts("Too many failed sign-in attempts. Try again in a few minutes.")


async def _record_failure(email: str, ip: str) -> None:
    await throttle.increment(_keys(email, ip), get_settings().login_window_seconds)


async def _clear_failures(email: str, ip: str) -> None:
    await throttle.clear(_keys(email, ip))
