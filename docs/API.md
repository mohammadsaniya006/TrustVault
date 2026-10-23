# API overview

All protected endpoints require `Authorization: Bearer <access_token>`.

- `POST /auth/register` — create a user (public registration creates viewer role only)
- `POST /auth/login` — obtain access token
- `GET /health` — health check
- `POST /documents` — upload a document (multipart `file`, plus `category`)
- `GET /documents?q=&category=` — list/search documents visible to current user
- `GET /documents/{id}` — metadata, only if read access is allowed
- `GET /documents/{id}/download` — download after fresh authorization check
- `PATCH /documents/{id}` — update metadata, owner/admin or edit grant
- `DELETE /documents/{id}` — owner/admin only
- `PUT /documents/{id}/grants/{user_id}` — owner/admin grants `read` or `edit`
- `DELETE /documents/{id}/grants/{user_id}` — owner/admin revokes grant
- `GET /admin/audit` — admin-only audit feed

The backend's authorization checks are authoritative. UI state is not trusted.
