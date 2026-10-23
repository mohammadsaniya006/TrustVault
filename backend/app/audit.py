import hashlib, json
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from .models import AuditEvent, new_id, utcnow

GENESIS = "0" * 64

def write_audit(db: Session, actor_id: str | None, action: str, document_id: str | None,
                outcome: str, details: dict | None = None):
    # For production, serialize writes with a DB lock/sequence to avoid concurrent-chain races.
    last = db.scalar(select(AuditEvent).order_by(desc(AuditEvent.created_at), desc(AuditEvent.id)).limit(1))
    previous = last.event_hash if last else GENESIS
    
    payload = {
        "id": new_id(), "actor_id": actor_id, "action": action,
        "document_id": document_id, "outcome": outcome,
        "details": json.dumps(details or {}, sort_keys=True),
        "created_at": utcnow(), "previous_hash": previous,
    }
    hash_payload = {
        **payload,
        "created_at": payload["created_at"].isoformat(),
    }
    event_hash = hashlib.sha256(
        json.dumps(hash_payload, sort_keys=True).encode()
    ).hexdigest()
    event = AuditEvent(**payload, event_hash=event_hash)

    db.add(event)
    db.flush()
    return event
