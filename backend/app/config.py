import os
from pathlib import Path

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./trustvault_dev.db")
JWT_SECRET = os.getenv("JWT_SECRET", "")
TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "20"))
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "./private_uploads"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

def validate_config():
    if len(JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET must be set to at least 32 characters.")
