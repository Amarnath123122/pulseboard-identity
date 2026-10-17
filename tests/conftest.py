import os
import tempfile
from collections.abc import AsyncIterator

_tmp = tempfile.mkdtemp()
os.environ.update({
    "ID_ENVIRONMENT": "test",
    "ID_DATABASE_URL": f"sqlite+aiosqlite:///{_tmp}/identity.db",
    "ID_KEY_FILE": f"{_tmp}/key.pem",
    "ID_LOG_JSON": "false",
})

import httpx  # noqa: E402
import pytest  # noqa: E402

from app import service, throttle  # noqa: E402
from app.db import Base, db  # noqa: E402
from app.main import app  # noqa: E402

ADMIN = {"email": "admin@example.com", "password": "Admin-Pulseboard-2026"}


@pytest.fixture(autouse=True)
async def database() -> AsyncIterator[None]:
    db.init(os.environ["ID_DATABASE_URL"])
    async with db.engine.begin() as conn:  # type: ignore[union-attr]
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    throttle.reset()
    async with db.session() as s:
        await service.ensure_bootstrap_admin(s)
    yield
    await db.dispose()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def sign_in(client: httpx.AsyncClient, name: str) -> dict[str, str]:
    creds = {"email": f"{name.lower()}@example.com", "password": "Correct-Horse-9"}
    r = await client.post("/api/v1/auth/register", json=creds | {"display_name": name})
    if r.status_code == 409:
        r = await client.post("/api/v1/auth/login", json=creds)
    assert r.status_code in (200, 201), r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def sign_in_admin(client: httpx.AsyncClient) -> dict[str, str]:
    r = await client.post("/api/v1/auth/login", json=ADMIN)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
