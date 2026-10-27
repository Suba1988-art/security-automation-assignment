import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


def create_test_scan(token):
    return client.post("/scans", json={
        "title": "Shared report test",
        "description": "Test report details",
        "severity": "high",
        "affected_component": "test-service",
    }, headers=auth_headers(token)).json()["id"]


def test_share_link_returns_scan_and_expires_after_24_hours():
    token = register_and_login()
    scan_id = create_test_scan(token)
    share_response = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert share_response.status_code == 200
    share_url = share_response.json()["share_url"]
    share_token = share_url.rsplit("/", 1)[-1]
    public_response = client.get(f"/share/{share_token}")
    assert public_response.status_code == 200
    assert public_response.json()["id"] == scan_id
    assert public_response.headers["cache-control"] == "no-store"


def test_password_protected_share_requires_correct_password():
    token = register_and_login()
    scan_id = create_test_scan(token)
    share_response = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "correct horse battery"},
        headers=auth_headers(token),
    )
    share_token = share_response.json()["share_url"].rsplit("/", 1)[-1]
    assert client.get(f"/share/{share_token}").status_code == 401
    assert client.get(f"/share/{share_token}?password=wrong").status_code == 401
    assert client.get(f"/share/{share_token}?password=correct%20horse%20battery").status_code == 200


def test_cannot_share_another_users_scan():
    owner_token = register_and_login("owner", "owner@example.com")
    scan_id = create_test_scan(owner_token)
    other_token = register_and_login("other", "other@example.com")
    response = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(other_token))
    assert response.status_code == 404


def test_expired_share_link_is_rejected():
    from datetime import datetime, timedelta
    import hashlib
    import models

    token = register_and_login()
    scan_id = create_test_scan(token)
    raw_token = "expired-test-token"
    db = TestingSessionLocal()
    try:
        db.add(models.SharedReportToken(
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            scan_id=scan_id,
            expires_at=datetime.utcnow() - timedelta(seconds=1),
        ))
        db.commit()
    finally:
        db.close()
    assert client.get(f"/share/{raw_token}").status_code == 404


def test_get_scan_does_not_expose_another_users_scan():
    owner_token = register_and_login("owner2", "owner2@example.com")
    scan_id = create_test_scan(owner_token)
    other_token = register_and_login("other2", "other2@example.com")
    response = client.get(f"/scans/{scan_id}", headers=auth_headers(other_token))
    assert response.status_code == 404


def test_search_only_returns_current_users_scans():
    first_token = register_and_login("search_owner", "search_owner@example.com")
    second_token = register_and_login("search_other", "search_other@example.com")
    client.post("/scans", json={
        "title": "Private marker finding",
        "severity": "high",
        "affected_component": "private-service",
    }, headers=auth_headers(first_token))
    response = client.get("/scans/search?q=Private", headers=auth_headers(second_token))
    assert response.status_code == 200
    assert response.json()["count"] == 0
