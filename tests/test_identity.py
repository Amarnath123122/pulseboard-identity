import jwt

from tests.conftest import sign_in, sign_in_admin

PW = "Correct-Horse-9"


async def test_health_and_discovery(client):
    assert (await client.get("/readyz")).json()["database"] == "up"
    keys = (await client.get("/.well-known/jwks.json")).json()["keys"]
    assert keys[0]["kty"] == "RSA" and keys[0]["alg"] == "RS256" and keys[0]["kid"]
    oidc = (await client.get("/.well-known/openid-configuration")).json()
    assert oidc["jwks_uri"].endswith("/.well-known/jwks.json")


async def test_access_token_verifies_with_published_jwks(client):
    reg = (await client.post("/api/v1/auth/register",
                             json={"email": "a@example.com", "password": PW, "display_name": "A"})).json()
    jwk = (await client.get("/.well-known/jwks.json")).json()["keys"][0]
    key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(reg["access_token"], key, algorithms=["RS256"], audience="pulseboard",
                        issuer="pulseboard-identity")
    assert claims["role"] == "VIEWER" and "metrics:write" not in claims["perms"] and claims["sub"]


async def test_register_login_refresh_rotation_logout(client):
    creds = {"email": "Ana@Example.com", "password": PW, "display_name": "Ana"}
    reg = await client.post("/api/v1/auth/register", json=creds)
    assert reg.status_code == 201 and reg.json()["user"]["email"] == "ana@example.com"
    assert (await client.post("/api/v1/auth/register", json=creds)).status_code == 409
    weak = await client.post("/api/v1/auth/register", json=creds | {"email": "b@example.com", "password": "short"})
    assert weak.status_code == 422

    login = (await client.post("/api/v1/auth/login", json={"email": "ana@example.com", "password": PW})).json()
    me = (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login['access_token']}"})).json()
    assert me["role"] == "VIEWER"

    rotated = (await client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})).json()
    assert rotated["refresh_token"] != login["refresh_token"]
    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": login["refresh_token"]})
    sibling = await client.post("/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    assert replay.status_code == 401 and sibling.status_code == 401  # reuse revokes the family

    fresh = (await client.post("/api/v1/auth/login", json={"email": "ana@example.com", "password": PW})).json()
    assert (await client.post("/api/v1/auth/logout", json={"refresh_token": fresh["refresh_token"]})).status_code == 204
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": fresh["refresh_token"]})
    assert after.status_code == 401


async def test_wrong_password_and_lockout(client):
    await sign_in(client, "lock")
    unknown = await client.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "x"})
    assert unknown.status_code == 401 and "incorrect" in unknown.json()["error"]["message"]
    bad = {"email": "lock@example.com", "password": "wrong-password"}
    for _ in range(4):
        assert (await client.post("/api/v1/auth/login", json=bad)).status_code == 401
    assert (await client.post("/api/v1/auth/login", json=bad)).status_code == 429


async def test_admin_manages_roles_and_access(client):
    viewer = await sign_in(client, "viewer1")
    admin = await sign_in_admin(client)
    assert (await client.get("/api/v1/users", headers=viewer)).status_code == 403
    uid = (await client.get("/api/v1/users", params={"q": "viewer1"}, headers=admin)).json()["items"][0]["id"]
    assert (await client.patch(f"/api/v1/users/{uid}", json={"role": "EDITOR"}, headers=admin)).json()["role"] == "EDITOR"
    editor = (await client.post("/api/v1/auth/login",
                                json={"email": "viewer1@example.com", "password": PW})).json()
    assert "metrics:write" in editor["user"]["permissions"]
    assert (await client.patch(f"/api/v1/users/{uid}", json={"is_active": False}, headers=admin)).status_code == 200
    denied = await client.post("/api/v1/auth/login", json={"email": "viewer1@example.com", "password": PW})
    assert denied.status_code == 403


async def test_last_admin_protected_and_tampered_token(client):
    admin = await sign_in_admin(client)
    me = (await client.get("/api/v1/auth/me", headers=admin)).json()
    assert (await client.patch(f"/api/v1/users/{me['id']}", json={"role": "VIEWER"}, headers=admin)).status_code == 409
    token = admin["Authorization"].split()[1]
    bad = {"Authorization": "Bearer " + token[:-4] + "AAAA"}
    assert (await client.get("/api/v1/auth/me", headers=bad)).status_code == 401


async def test_roles_catalogue_is_public(client):
    roles = (await client.get("/api/v1/auth/roles")).json()
    assert set(roles) == {"ADMIN", "EDITOR", "VIEWER"} and "users:write" in roles["ADMIN"]
