# pulseboard-identity

The identity microservice: accounts, sign-in, RS256 tokens with public keys (JWKS), rotating refresh tokens, roles and permissions (Viewer / Editor / Admin).

**Everything about Pulseboard (architecture, how to run, deploy, test, troubleshoot and the evidence it works) is in one guide:**

➡️ **[pulseboard-platform/README.md](https://github.com/Amarnath123122/pulseboard-platform#readme)**

## Quick start for this repo
```
python -m venv .venv && .venv/Scripts/python -m pip install -e .[dev]
.venv/Scripts/python -m pytest -q                              # 7 tests
.venv/Scripts/python -m uvicorn app.main:app --reload --port 8100
```
