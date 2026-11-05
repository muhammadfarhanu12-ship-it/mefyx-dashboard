"""API key lifecycle: create -> plan limit -> hash -> authenticate -> revoke.

Regression coverage for: FREE users could never obtain a usable key because the key list silently
auto-created a "Workspace Primary" key whose secret was discarded (it consumed the single FREE slot and was
re-created after every revoke), and for keys that looked created but were never persisted.
"""
from __future__ import annotations

import hashlib
from typing import Any

import pytest
from fastapi import HTTPException

from app.main import app
from app.middleware import auth_middleware
from app.services import dashboard_service

FREE_USER = {
    "_id": "user-free-1",
    "id": "user-free-1",
    "email": "free@example.com",
    "name": "Free User",
    "tier": "FREE",
    "role": "user",
    "is_active": True,
    "is_verified": True,
    "is_admin": False,
}


@pytest.fixture
def free_client(client):
    """The shared `client` fixture, authenticated as a FREE-tier user with a clean key store."""
    original = app.dependency_overrides.get(auth_middleware.get_current_user)

    async def free_user():
        return dict(FREE_USER)

    app.dependency_overrides[auth_middleware.get_current_user] = free_user
    saved = list(dashboard_service._fallback_store["keys"])
    dashboard_service._fallback_store["keys"].clear()
    try:
        yield client
    finally:
        dashboard_service._fallback_store["keys"][:] = saved
        if original is not None:
            app.dependency_overrides[auth_middleware.get_current_user] = original


def _data(response) -> Any:
    return response.json()["data"]


def _error_text(response) -> str:
    """The app wraps errors in its own envelope; accept either shape so the test checks the message only."""
    body = response.json()
    error = body.get("error")
    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])
    return str(body.get("detail") or body)


def test_new_user_has_no_phantom_keys(free_client):
    """Listing keys must be read-only: no hidden key whose secret nobody can know."""
    assert _data(free_client.get("/api/v1/keys")) == []
    assert _data(free_client.get("/api/v1/keys")) == []  # still empty after repeated loads


def test_free_user_can_create_a_real_key_and_it_is_shown_once(free_client):
    created = free_client.post("/api/v1/keys", json={"name": "CI key"})
    assert created.status_code == 200, created.text
    body = _data(created)
    assert body["key"].startswith("sentinel_sk_") and len(body["key"]) >= 40
    assert body["status"] == "ACTIVE" and body["name"] == "CI key"
    assert "key_hash" not in body and "user_id" not in body

    listed = _data(free_client.get("/api/v1/keys"))
    assert len(listed) == 1
    assert "key" not in listed[0] and "key_hash" not in listed[0], "secret must never be returned again"


def test_only_a_hash_is_stored_and_it_matches_the_returned_key(free_client):
    raw = _data(free_client.post("/api/v1/keys", json={"name": "k"}))["key"]
    stored = dashboard_service._fallback_store["keys"][0]
    assert stored["key_hash"] == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in str(stored.values())


def test_free_plan_limit_returns_403_with_a_clear_message(free_client):
    assert free_client.post("/api/v1/keys", json={"name": "first"}).status_code == 200
    second = free_client.post("/api/v1/keys", json={"name": "second"})
    assert second.status_code == 403
    assert "FREE plan allows up to 1 active API key" in _error_text(second)


def test_revoking_frees_the_slot_and_no_phantom_key_reappears(free_client):
    """The lock-out bug: after revoke, listing re-created a phantom primary key and blocked creation."""
    first = _data(free_client.post("/api/v1/keys", json={"name": "first"}))
    revoked = free_client.delete(f"/api/v1/keys/{first['id']}")
    assert revoked.status_code == 200

    listed = _data(free_client.get("/api/v1/keys"))
    assert [k["status"] for k in listed] == ["REVOKED"], "revoked key stays listed; nothing else is invented"

    replacement = free_client.post("/api/v1/keys", json={"name": "replacement"})
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["data"]["key"] != first["key"]


class _FakeCollection:
    def __init__(self, docs: list[dict[str, Any]]):
        self.docs = docs

    async def find_one(self, query: dict[str, Any]):
        wanted = query.get("status", {}).get("$in")
        for doc in self.docs:
            if "key_hash" in query and doc.get("key_hash") != query["key_hash"]:
                continue
            if "id" in query and doc.get("id") != query["id"]:
                continue
            if wanted is not None and doc.get("status") not in wanted:
                continue
            return doc
        return None


class _FakeDatabase:
    def __init__(self, keys: list[dict[str, Any]], users: list[dict[str, Any]]):
        self._collections = {"keys": _FakeCollection(keys), "users": _FakeCollection(users)}

    def get_collection(self, name: str) -> _FakeCollection:
        return self._collections[name]


class _FakeRequest:
    class state:  # noqa: N801 - mimics starlette's request.state
        pass

    headers: dict[str, str] = {}
    app = None


def _auth_database(monkeypatch):
    keys = dashboard_service._fallback_store["keys"]
    users = [{**FREE_USER, "id": "user-free-1"}]
    monkeypatch.setattr(auth_middleware, "get_database_from_request", lambda request: _FakeDatabase(keys, users))


def test_a_created_key_authenticates_and_is_never_an_admin_session(free_client, monkeypatch):
    import asyncio

    raw = _data(free_client.post("/api/v1/keys", json={"name": "gateway"}))["key"]
    _auth_database(monkeypatch)

    request = _FakeRequest()
    request.state = type("S", (), {})()
    user = asyncio.run(auth_middleware._resolve_user_from_api_key(request, raw))
    assert user["email"] == "free@example.com"
    assert user["is_admin"] is False
    assert request.state.auth_method == "api_key"


def test_wrong_or_revoked_key_is_rejected(free_client, monkeypatch):
    import asyncio

    created = _data(free_client.post("/api/v1/keys", json={"name": "gateway"}))
    _auth_database(monkeypatch)

    def attempt(key: str):
        request = _FakeRequest()
        request.state = type("S", (), {})()
        return asyncio.run(auth_middleware._resolve_user_from_api_key(request, key))

    with pytest.raises(HTTPException) as bad:
        attempt("sentinel_sk_gateway_" + "x" * 32)
    assert bad.value.status_code == 401

    free_client.delete(f"/api/v1/keys/{created['id']}")
    with pytest.raises(HTTPException) as revoked:
        attempt(created["key"])
    assert revoked.value.status_code == 401


def test_storage_failure_is_reported_instead_of_returning_a_key_that_was_never_saved(free_client, monkeypatch):
    """A key shown to the user but only kept in process memory cannot authenticate and vanishes on restart."""

    class _BrokenCollection:
        async def find_one(self, *args, **kwargs):
            return None

        async def insert_one(self, document):
            raise RuntimeError("mongo down")

    monkeypatch.setattr(dashboard_service, "collection_from_request", lambda request, name: _BrokenCollection())
    before = len(dashboard_service._fallback_store["keys"])
    response = free_client.post("/api/v1/keys", json={"name": "doomed"})
    assert response.status_code == 503  # 5xx bodies are generic by design; the UI maps 5xx to "try again"
    assert len(dashboard_service._fallback_store["keys"]) == before