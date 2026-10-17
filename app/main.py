import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app import service
from app.config import get_settings
from app.db import Base, db
from app.errors import register_error_handlers
from app.logging import configure_logging, request_id_ctx
from app.routes import router
from app.security import private_key

log = logging.getLogger("identity")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    if db.engine is None:
        db.init(s.database_url)
    if s.db_auto_create:
        async with db.engine.begin() as conn:  # type: ignore[union-attr]
            await conn.run_sync(Base.metadata.create_all)
    private_key()  # fail fast on a bad key
    async with db.session() as session:
        await service.ensure_bootstrap_admin(session)
    log.info("identity started", extra={"ctx": {"env": s.environment}})
    yield
    await db.dispose()


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="Pulseboard Identity", version="1.0.0", lifespan=lifespan,
                  docs_url=None if s.is_production else "/docs", redoc_url=None)
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=True,
                           allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
                           allow_headers=["Authorization", "Content-Type", "X-Request-ID"])

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # noqa: ANN001, ANN202
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        token = request_id_ctx.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        response.headers.update({"X-Request-ID": rid, "X-Content-Type-Options": "nosniff",
                                 "Cache-Control": response.headers.get("Cache-Control", "no-store")})
        log.info("request", extra={"ctx": {"method": request.method, "path": request.url.path,
                                           "status": response.status_code,
                                           "ms": round((time.perf_counter() - start) * 1000, 1)}})
        return response

    register_error_handlers(app)
    app.include_router(router)
    return app


app = create_app()
