"""Identity HTTP API: auth, users (admin), RBAC catalogue, JWKS/OpenID discovery, health."""

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import service
from app.config import get_settings
from app.db import get_session
from app.security import PERMISSIONS, ROLES, Principal, current_principal, jwks, require

router = APIRouter()
Role = Literal["ADMIN", "EDITOR", "VIEWER"]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128, description="At least 10 characters")
    display_name: str = Field(min_length=1, max_length=120)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=200)


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool
    permissions: list[str]
    last_login_at: datetime | None = None
    created_at: datetime | None = None


class SessionOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserOut


class UserPage(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    size: int
    pages: int


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


# ---------- auth ----------
@router.post("/api/v1/auth/register", response_model=SessionOut, status_code=status.HTTP_201_CREATED, tags=["auth"])
async def register(body: RegisterIn, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await service.register(session, email=body.email, password=body.password, display_name=body.display_name)


@router.post("/api/v1/auth/login", response_model=SessionOut, tags=["auth"])
async def login(body: LoginIn, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    ip = forwarded or (request.client.host if request.client else "unknown")
    return await service.login(session, email=body.email, password=body.password, client_ip=ip)


@router.post("/api/v1/auth/refresh", response_model=SessionOut, tags=["auth"])
async def refresh(body: RefreshIn, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await service.refresh(session, body.refresh_token)


@router.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
async def logout(body: RefreshIn, session: AsyncSession = Depends(get_session)) -> Response:
    await service.logout(session, body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/api/v1/auth/me", response_model=UserOut, tags=["auth"])
async def me(principal: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)):  # noqa: ANN201
    return service.user_view(await service.get(session, principal.user_id))


@router.get("/api/v1/auth/roles", tags=["auth"])
async def roles() -> dict[str, list[str]]:
    """Role -> permissions. Public so UIs and services can render and reason about access."""
    return {r: sorted(p) for r, p in PERMISSIONS.items()}


# ---------- users (admin) ----------
@router.get("/api/v1/users", response_model=UserPage, tags=["users"])
async def list_users(
    q: str | None = Query(None, max_length=100), role: Role | None = None,
    page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100),
    _: Principal = Depends(require("users:read")), session: AsyncSession = Depends(get_session),
) -> dict:
    return await service.search(session, q=q, role=role, page=page, size=size)


@router.patch("/api/v1/users/{user_id}", response_model=UserOut, tags=["users"])
async def update_user(
    user_id: str, body: UserUpdate, me: Principal = Depends(require("users:write")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return service.user_view(await service.update_user(session, me.user_id, user_id, role=body.role,
                                                       is_active=body.is_active))


# ---------- discovery for resource servers and gateways ----------
@router.get("/.well-known/jwks.json", tags=["discovery"])
async def jwks_endpoint() -> JSONResponse:
    return JSONResponse(jwks(), headers={"Cache-Control": "public, max-age=300"})


@router.get("/.well-known/openid-configuration", tags=["discovery"])
async def openid_configuration(request: Request) -> dict[str, Any]:
    base = str(request.base_url).rstrip("/")
    return {"issuer": get_settings().jwt_issuer, "jwks_uri": f"{base}/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["RS256"], "roles_supported": list(ROLES)}


# ---------- health ----------
@router.get("/healthz", tags=["health"])
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz", tags=["health"])
async def readyz(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    try:
        await session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        return JSONResponse({"status": "degraded", "database": "down"}, status_code=503)
    return JSONResponse({"status": "ok", "database": "up"})
