import os
os.environ.setdefault("JWT_SECRET", "test-secret-key-that-is-at-least-32-chars")
os.environ.setdefault("DATABASE_URL", "sqlite:///./trustvault_test_import.db")
os.environ.setdefault("STORAGE_DIR", "./test_private_uploads")
