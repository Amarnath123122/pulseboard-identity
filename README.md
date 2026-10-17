# pulseboard-identity

The identity microservice for Pulseboard. It owns user accounts, sessions and role-based access control (RBAC). Other services never store passwords and never share a secret: they verify this service's RS256 tokens using its published public keys (JWKS).

## Endpoints
| Method | Path | Access |
|---|---|---|
| POST | `/api/v1/auth/register` | public (if `ID_ALLOW_SIGNUP`); new users get `ID_SIGNUP_ROLE` (VIEWER) |
| POST | `/api/v1/auth/login` | public; returns a 15-minute access token and a 7-day refresh token; locks out after 5 failures per email or IP |
| POST | `/api/v1/auth/refresh` | refresh token; **rotates** it, and reusing an old one revokes the whole session family |
| POST | `/api/v1/auth/logout` | refresh token; revokes the session family |
| GET | `/api/v1/auth/me` | signed in |
| GET | `/api/v1/auth/roles` | public; role → permissions |
| GET / PATCH | `/api/v1/users`, `/api/v1/users/{id}` | `users:read` / `users:write` (ADMIN); keeps at least one active admin |
| GET | `/.well-known/jwks.json`, `/.well-known/openid-configuration` | public; used by the API and the gateway |
| GET | `/healthz`, `/readyz` | ops |

## Roles
| Role | Permissions |
|---|---|
| VIEWER | `boards:read`, `boards:follow_up`, `setup:run`, `metrics:read`, `jobs:read` |
| EDITOR | VIEWER + `metrics:write` |
| ADMIN | EDITOR + `users:read`, `users:write` |

Tokens carry `sub`, `email`, `role` and `perms`, with `iss=pulseboard-identity` and `aud=pulseboard`.
- **Role changes:** a change of role or a deactivation revokes the user's refresh tokens, so it takes effect within one access-token lifetime.
- **First admin:** a bootstrap admin (`ID_BOOTSTRAP_ADMIN_EMAIL` / `ID_BOOTSTRAP_ADMIN_PASSWORD`) is created when no admin exists.

## Run
```powershell
python -m venv .venv; .\.venv\Scripts\python -m pip install -e ".[dev]"
copy .env.example .env
.\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8100
.\.venv\Scripts\python -m pytest -q
```
Locally, a signing key is generated into `.keys/` on first start. In production, set `ID_JWT_PRIVATE_KEY_B64` (from Key Vault). The service refuses to start without it, or with the default admin password.

The full system (gateway, API, web, databases) runs from the `pulseboard-platform` repo.
