from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_ADMIN_PASSWORD = "Admin-Pulseboard-2026"


class Settings(BaseSettings):
    """Identity service settings; every field can be overridden with an ID_-prefixed environment variable."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="ID_", extra="ignore")

    app_name: str = "pulseboard-identity"
    environment: str = "local"
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "sqlite+aiosqlite:///./identity.db"
    db_auto_create: bool = True

    cors_origins: list[str] = []  # empty behind a gateway (same origin); set for direct browser access

    # RS256 signing. Base64 of a PEM private key; if empty, a key is generated into key_file on first start.
    jwt_private_key_b64: str = ""
    key_file: str = ".keys/jwt-private.pem"
    jwt_key_id: str = "pulseboard-1"
    jwt_issuer: str = "pulseboard-identity"
    jwt_audience: str = "pulseboard"
    access_token_minutes: int = 15
    refresh_token_days: int = 7

    allow_signup: bool = True
    signup_role: Literal["ADMIN", "EDITOR", "VIEWER"] = "VIEWER"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = _DEFAULT_ADMIN_PASSWORD

    # Login throttling (per email and per client IP). Uses Redis when configured, else process memory.
    redis_url: str | None = None
    login_max_attempts: int = 5
    login_window_seconds: int = 900

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.is_production and (self.bootstrap_admin_password == _DEFAULT_ADMIN_PASSWORD or not self.jwt_private_key_b64):
            raise ValueError("ID_BOOTSTRAP_ADMIN_PASSWORD and ID_JWT_PRIVATE_KEY_B64 must be set in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
