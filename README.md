# TrustVault — Secure Document Sharing with a Real Audit Trail

A learning/project-submission starter built with React, FastAPI, SQL Server, Docker Compose, and pytest.

## Features
- JWT authentication; passwords hashed with Argon2
- Roles: admin, owner, viewer
- Upload, list/search, download, edit metadata, delete documents
- Per-document read/edit permissions; owners can grant/revoke access
- Server-side authorization on every document operation
- Audit records for successful actions and denied access
- Hash-linked audit records (tamper-evident, not immutable against a database administrator)
- Automated tests for cross-user access, revocation, viewer restrictions, and denied-access audit
- Private file storage; files are not served directly by the web server

## Important honesty note
This is an educational starter, not a production security certification. It has not been built or run in your environment by the authoring process. Run the tests and verify the SQL Server Docker setup before claiming that the app is tested. Audit hash chaining can reveal edits to existing records, but a privileged database administrator could rewrite the entire chain. For stronger assurance, export/sign audit checkpoints to an independently controlled system.

## Requirements
- Docker Desktop / Docker Engine with Compose
- Or Python 3.11+, Node.js 20+, SQL Server and ODBC Driver 18 for local development

## Run with Docker Compose
1. Copy `.env.example` to `.env`.
2. Replace `JWT_SECRET` with a random secret of at least 32 characters.
3. Run `docker compose up --build`.
4. API docs: http://localhost:8000/docs
5. React app: http://localhost:5173

SQL Server may take a minute to start. If API startup fails because SQL Server is not ready, restart the API service after SQL Server is healthy.
## Live Demo

- **Frontend:** https://trust-vault-seven.vercel.app/
- **Backend API Documentation:** https://trustvault-backend.vercel.app/docs
- **Backend Health Check:** https://trustvault-backend.vercel.app/health
- **GitHub Repository:** https://github.com/mohammadsaniya006/TrustVault
- 
## Seed demo users
For a submission, create users through the admin/seed process you implement for your environment. Do not ship fixed public credentials. The current starter intentionally does not create default accounts automatically.

## Run backend tests locally
Create a Python 3.11 virtual environment, install `backend/requirements.txt`, then:
```bash
cd backend
pytest -q
```
Tests use SQLite in-memory so they can run without a SQL Server instance. SQL Server integration should also be tested before final submission.

## Project structure
- `backend/app/` API, models, auth, permissions, storage, audit
- `backend/tests/` security regression tests
- `frontend/` React client
- `database/schema.sql` SQL Server schema reference
- `THREATS.md` threat model
- `PROMPTS.md` AI assistance log template
- `docs/API.md` API overview
