# TrustVault threat model

## Assets
- Private document contents and metadata
- User passwords and access tokens
- Per-document grants
- Audit events and integrity chain

## Threats and mitigations
1. **Cross-user document access** — Every read/download/edit/delete/grant endpoint calls server-side authorization against the current database state. Tests cover user A trying to access user B's document.
2. **Permission revocation delay** — No public/static file URLs are issued. Download requests go through the API and check current grants every time.
3. **Role spoofing** — JWT contains subject identity; role is reloaded from the database for protected requests instead of trusting a client-supplied role.
4. **Malicious upload** — Size limit, extension allowlist, signature checks for supported types, server-generated storage key, private volume.
5. **Path traversal** — Client filename is never used as a storage path; a random UUID is used.
6. **Password disclosure** — Argon2 password hashing; passwords are never returned by API.
7. **Audit tampering** — Each event includes the previous event hash and its own SHA-256 hash. This is tamper-evident, not immutable against an administrator able to rewrite all rows. Production should sign and export checkpoints to an independently controlled destination.
8. **Brute force / token theft** — Short-lived bearer tokens. Production needs rate limiting, TLS, refresh-token rotation, secret management, and monitoring.
9. **SQL injection** — SQLAlchemy parameterized queries; no string-concatenated SQL in request handlers.
10. **XSS / malicious files** — UI renders metadata as text; do not render uploaded HTML. Download with attachment disposition. Production should add malware scanning and content-disarm where appropriate.

## Residual risks / not production ready
- No MFA, password reset, rate limiting, malware scanner, external immutable audit sink, or formal penetration test.
- Local development CORS and HTTP settings must be tightened for deployment.
- SQLite-based tests are not a substitute for SQL Server integration tests.
- Admin can access audit events; admin document access should be explicitly scoped by policy if added.
