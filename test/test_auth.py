import os
import tempfile
import pytest
from app import create_app, db

@pytest.fixture
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client

def test_signup_and_login(client):
    resp = client.post("/api/v1/auth/signup", json={"email": "a@b.com", "password": "pass"})
    assert resp.status_code == 201
    resp = client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "pass"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "access_token" in data