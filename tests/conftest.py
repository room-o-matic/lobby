from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from lobbyd import apikeys, db, endpoints
from lobbyd.app import create_app
from lobbyd.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path / "data", issuer="http://lobby.test", domain="test")


@pytest.fixture
def client(settings) -> TestClient:
    return TestClient(create_app(settings))


@pytest.fixture
def make_key(client, settings) -> Callable[..., dict[str, str]]:
    """Issue an API key and return its Authorization headers."""

    def _make(name: str, scope: apikeys.Scope = "agent") -> dict[str, str]:
        conn = db.connect(settings.db_path)
        try:
            key = apikeys.create_key(conn, name, scope)
        finally:
            conn.close()
        return {"Authorization": f"Bearer {key}"}

    return _make


@pytest.fixture
def approve(settings) -> Callable[..., dict]:
    """Operator approval of a service endpoint (what `lobbyd endpoint approve` does)."""

    def _approve(name: str, url: str, **kw) -> dict:
        conn = db.connect(settings.db_path)
        try:
            return endpoints.approve(conn, name, url, **kw)
        finally:
            conn.close()

    return _approve


@pytest.fixture
def boostie(make_key):
    return make_key("boostie")


@pytest.fixture
def agentd1(make_key, approve):
    headers = make_key("agentd-host1", "agentd")
    approve("agentd-host1", "http://host1:8765")
    return headers


@pytest.fixture
def rooms_a(make_key, approve):
    headers = make_key("rooms-a", "roomsd")
    approve("rooms-a", "https://rooms-a.test")
    return headers
