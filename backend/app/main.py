import json, os, re, uuid
from pathlib import Path
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, or_, desc
from sqlalchemy.orm import Session
from .config import STORAGE_DIR, MAX_UPLOAD_BYTES, validate_config
from .database import Base, engine, get_db
from .models import User, Document, DocumentGrant, AuditEvent, new_id, utcnow
from .security import hash_password, verify_password, create_access_token
from .dependencies import current_user, require_admin
from .permissions import require_read, require_edit, permission_for
from .audit import write_audit

validate_config()
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TrustVault API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type"])

class RegisterInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

class LoginInput(BaseModel):
    email: EmailStr
    password: str

class GrantInput(BaseModel):
    permission: str

class MetadataInput(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=80)

def safe_filename(name: str) -> str:
    # Only display basename; never use the supplied filename as a path.
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", Path(name).name).strip(" .")
    return (cleaned or "uploaded-file")[:255]

def validate_file(name: str, content: bytes) -> tuple[str, str]:
    ext = Path(name).suffix.lower()
    signatures = {
        ".pdf": (b"%PDF-", "application/pdf"),
        ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
        ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
        ".jpeg": (b"\xff\xd8\xff", "image/jpeg"),
        ".txt": (None, "text/plain"),
    }
    if ext not in signatures:
        raise HTTPException(status_code=415, detail="Allowed file types: PDF, PNG, JPG, TXT")
    signature, content_type = signatures[ext]
    if signature and not content.startswith(signature):
        raise HTTPException(status_code=415, detail="File content does not match extension")
    if ext == ".txt":
        try: content.decode("utf-8")
        except UnicodeDecodeError: raise HTTPException(status_code=415, detail="TXT file must be UTF-8")
    if not content:
        raise HTTPException(status_code=400, detail="Empty files are not allowed")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds upload limit")
    return ext, content_type

def doc_to_dict(doc: Document, user: User, db: Session):
    return {
        "id": doc.id, "title": doc.title, "category": doc.category,
        "owner_id": doc.owner_id, "original_filename": doc.original_filename,
        "content_type": doc.content_type, "size_bytes": doc.size_bytes,
        "created_at": doc.created_at.isoformat(), "updated_at": doc.updated_at.isoformat(),
        "permission": permission_for(db, user, doc),
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/auth/register", status_code=201)
def register(data: RegisterInput, db: Session = Depends(get_db)):
    email = str(data.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    try: hashed = hash_password(data.password)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc))
    user = User(email=email, password_hash=hashed, role="viewer", is_active=True)
    db.add(user)
    db.flush()
    write_audit(db, user.id, "auth.register", None, "success", {"email": email})
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}

@app.post("/auth/login")
def login(data: LoginInput, db: Session = Depends(get_db)):
    email = str(data.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        write_audit(db, user.id if user else None, "auth.login", None, "denied", {"email": email})
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user.id)
    write_audit(db, user.id, "auth.login", None, "success")
    db.commit()
    return {"access_token": token, "token_type": "bearer", "role": user.role, "user_id": user.id}

@app.post("/documents", status_code=201)
async def upload_document(file: UploadFile = File(...), category: str = Form("General"),
                          user: User = Depends(current_user), db: Session = Depends(get_db)):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    validate_file(file.filename or "uploaded-file", content)
    original = safe_filename(file.filename or "uploaded-file")
    storage_key = str(uuid.uuid4())
    path = STORAGE_DIR / storage_key
    try:
        path.write_bytes(content)
        doc = Document(owner_id=user.id, title=Path(original).stem[:255] or "Untitled",
                       category=category[:80], original_filename=original, storage_key=storage_key,
                       content_type=validate_file(original, content)[1], size_bytes=len(content))
        db.add(doc)
        db.flush()
        write_audit(db, user.id, "document.upload", doc.id, "success", {"filename": original, "size": len(content)})
        db.commit()
        return doc_to_dict(doc, user, db)
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise

@app.get("/documents")
def list_documents(q: str = Query(default="", max_length=100),
                   category: str = Query(default="", max_length=80),
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    docs = db.scalars(select(Document).order_by(desc(Document.created_at))).all()
    visible = []
    for doc in docs:
        if permission_for(db, user, doc) not in ("owner", "read", "edit"):
            continue
        if q and q.casefold() not in doc.title.casefold() and q.casefold() not in doc.original_filename.casefold():
            continue
        if category and category.casefold() != doc.category.casefold():
            continue
        visible.append(doc_to_dict(doc, user, db))
    return visible

@app.get("/documents/{document_id}")
def get_document(document_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    require_read(db, user, doc)
    write_audit(db, user.id, "document.metadata_read", doc.id, "success")
    db.commit()
    return doc_to_dict(doc, user, db)

@app.get("/documents/{document_id}/download")
def download_document(document_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    require_read(db, user, doc)
    path = STORAGE_DIR / doc.storage_key
    if not path.is_file():
        write_audit(db, user.id, "document.download", doc.id, "error", {"reason": "stored file missing"})
        db.commit()
        raise HTTPException(status_code=404, detail="Stored file not found")
    write_audit(db, user.id, "document.download", doc.id, "success")
    db.commit()
    return FileResponse(path, media_type=doc.content_type, filename=doc.original_filename, content_disposition_type="attachment")

@app.patch("/documents/{document_id}")
def edit_document(document_id: str, data: MetadataInput, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    require_edit(db, user, doc)
    doc.title, doc.category, doc.updated_at = data.title, data.category, utcnow()
    write_audit(db, user.id, "document.edit", doc.id, "success", {"title": data.title, "category": data.category})
    db.commit()
    return doc_to_dict(doc, user, db)

@app.delete("/documents/{document_id}", status_code=204)
def delete_document(document_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if user.role != "admin" and doc.owner_id != user.id:
        write_audit(db, user.id, "document.delete", doc.id, "denied", {"reason": "not owner"})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the owner or admin can delete")
    path = STORAGE_DIR / doc.storage_key
    write_audit(db, user.id, "document.delete", doc.id, "success")
    db.delete(doc)
    db.commit()
    path.unlink(missing_ok=True)
    return Response(status_code=204)

@app.put("/documents/{document_id}/grants/{target_user_id}")
def grant_access(document_id: str, target_user_id: str, data: GrantInput,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    if data.permission not in ("read", "edit"):
        raise HTTPException(status_code=422, detail="Permission must be 'read' or 'edit'")
    doc = db.get(Document, document_id)
    target = db.get(User, target_user_id)
    if not doc or not target:
        raise HTTPException(status_code=404, detail="Document or user not found")
    if user.role != "admin" and doc.owner_id != user.id:
        write_audit(db, user.id, "permission.grant", doc.id, "denied", {"target_user_id": target_user_id})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the owner or admin can grant access")
    grant = db.scalar(select(DocumentGrant).where(DocumentGrant.document_id == doc.id, DocumentGrant.user_id == target.id))
    if grant:
        grant.permission = data.permission
    else:
        grant = DocumentGrant(document_id=doc.id, user_id=target.id, permission=data.permission)
        db.add(grant)
    write_audit(db, user.id, "permission.grant", doc.id, "success", {"target_user_id": target.id, "permission": data.permission})
    db.commit()
    return {"document_id": doc.id, "user_id": target.id, "permission": data.permission}

@app.delete("/documents/{document_id}/grants/{target_user_id}", status_code=204)
def revoke_access(document_id: str, target_user_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if user.role != "admin" and doc.owner_id != user.id:
        write_audit(db, user.id, "permission.revoke", doc.id, "denied", {"target_user_id": target_user_id})
        db.commit()
        raise HTTPException(status_code=403, detail="Only the owner or admin can revoke access")
    grant = db.scalar(select(DocumentGrant).where(DocumentGrant.document_id == doc.id, DocumentGrant.user_id == target_user_id))
    if grant:
        db.delete(grant)
    write_audit(db, user.id, "permission.revoke", doc.id, "success", {"target_user_id": target_user_id})
    db.commit()
    return Response(status_code=204)

@app.get("/admin/audit")
def audit_feed(limit: int = Query(default=100, ge=1, le=500),
               _admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    events = db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit)).all()
    return [{
        "id": e.id, "actor_id": e.actor_id, "action": e.action, "document_id": e.document_id,
        "outcome": e.outcome, "details": e.details, "created_at": e.created_at.isoformat(),
        "previous_hash": e.previous_hash, "event_hash": e.event_hash
    } for e in events]
