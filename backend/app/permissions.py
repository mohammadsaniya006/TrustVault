from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Document, DocumentGrant, User
from .audit import write_audit

def permission_for(db: Session, user: User, doc: Document) -> str | None:
    if user.role == "admin" or doc.owner_id == user.id:
        return "owner"
    grant = db.scalar(select(DocumentGrant).where(
        DocumentGrant.document_id == doc.id, DocumentGrant.user_id == user.id
    ))
    return grant.permission if grant else None

def require_read(db: Session, user: User, doc: Document) -> str:
    permission = permission_for(db, user, doc)
    if permission not in ("owner", "read", "edit"):
        write_audit(db, user.id, "document.read", doc.id, "denied", {"reason": "no read grant"})
        db.commit()
        raise HTTPException(status_code=403, detail="You do not have read access")
    return permission

def require_edit(db: Session, user: User, doc: Document) -> str:
    permission = permission_for(db, user, doc)
    if permission not in ("owner", "edit"):
        write_audit(db, user.id, "document.edit", doc.id, "denied", {"reason": "no edit grant"})
        db.commit()
        raise HTTPException(status_code=403, detail="You do not have edit access")
    return permission
