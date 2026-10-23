import os, tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["JWT_SECRET"] = "test-secret-key-that-is-at-least-32-chars"
os.environ["DATABASE_URL"] = "sqlite:///./trustvault_test_import.db"
os.environ["STORAGE_DIR"] = tempfile.mkdtemp(prefix="tv-test-")

from app.main import app
from app.database import Base, get_db
from app.models import User, AuditEvent, DocumentGrant
from app.security import hash_password, create_access_token

engine_test = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine_test, autoflush=False, autocommit=False)
Base.metadata.create_all(engine_test)

def override_db():
    db = TestingSession()
    try: yield db
    finally: db.close()

app.dependency_overrides[get_db] = override_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(engine_test)
    Base.metadata.create_all(engine_test)
    yield

def add_user(email, role="viewer"):
    db = TestingSession()
    user = User(email=email, password_hash=hash_password("StrongPassword123!"), role=role, is_active=True)
    db.add(user); db.commit(); db.refresh(user)
    result = (user.id, create_access_token(user.id))
    db.close()
    return result

def auth(token):
    return {"Authorization": f"Bearer {token}"}

def upload(token, name="hello.txt", body=b"hello"):
    return client.post("/documents", headers=auth(token), files={"file": (name, body, "text/plain")}, data={"category": "Test"})

def test_cross_user_cannot_read_or_download_document():
    owner_id, owner_token = add_user("owner@example.com", "owner")
    _, other_token = add_user("other@example.com", "viewer")
    response = upload(owner_token)
    assert response.status_code == 201, response.text
    doc_id = response.json()["id"]
    assert client.get(f"/documents/{doc_id}", headers=auth(other_token)).status_code == 403
    assert client.get(f"/documents/{doc_id}/download", headers=auth(other_token)).status_code == 403

def test_viewer_cannot_edit_document_without_edit_grant():
    _, owner_token = add_user("owner2@example.com", "owner")
    _, viewer_token = add_user("viewer@example.com", "viewer")
    doc_id = upload(owner_token).json()["id"]
    response = client.patch(f"/documents/{doc_id}", headers=auth(viewer_token),
                            json={"title": "stolen", "category": "Test"})
    assert response.status_code == 403

def test_revoke_grant_blocks_subsequent_download():
    _, owner_token = add_user("owner3@example.com", "owner")
    viewer_id, viewer_token = add_user("viewer2@example.com", "viewer")
    doc_id = upload(owner_token).json()["id"]
    assert client.put(f"/documents/{doc_id}/grants/{viewer_id}", headers=auth(owner_token),
                      json={"permission": "read"}).status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=auth(viewer_token)).status_code == 200
    assert client.delete(f"/documents/{doc_id}/grants/{viewer_id}", headers=auth(owner_token)).status_code == 204
    assert client.get(f"/documents/{doc_id}/download", headers=auth(viewer_token)).status_code == 403

def test_denied_access_is_audited():
    _, owner_token = add_user("owner4@example.com", "owner")
    _, other_token = add_user("other4@example.com", "viewer")
    doc_id = upload(owner_token).json()["id"]
    assert client.get(f"/documents/{doc_id}", headers=auth(other_token)).status_code == 403
    db = TestingSession()
    events = db.scalars(select(AuditEvent).where(AuditEvent.document_id == doc_id, AuditEvent.outcome == "denied")).all()
    assert any(e.actor_id is not None for e in events)
    db.close()
