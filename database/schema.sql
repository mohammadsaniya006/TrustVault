-- SQL Server reference schema. The application uses SQLAlchemy models to create tables.
CREATE TABLE Users (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    email NVARCHAR(320) NOT NULL UNIQUE,
    password_hash NVARCHAR(512) NOT NULL,
    role NVARCHAR(20) NOT NULL CHECK (role IN ('admin','owner','viewer')),
    is_active BIT NOT NULL DEFAULT 1,
    created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
);

CREATE TABLE Documents (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    owner_id UNIQUEIDENTIFIER NOT NULL REFERENCES Users(id),
    title NVARCHAR(255) NOT NULL,
    category NVARCHAR(80) NOT NULL,
    original_filename NVARCHAR(255) NOT NULL,
    storage_key NVARCHAR(100) NOT NULL UNIQUE,
    content_type NVARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    updated_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET()
);

CREATE TABLE DocumentGrants (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    document_id UNIQUEIDENTIFIER NOT NULL REFERENCES Documents(id),
    user_id UNIQUEIDENTIFIER NOT NULL REFERENCES Users(id),
    permission NVARCHAR(10) NOT NULL CHECK (permission IN ('read','edit')),
    created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    CONSTRAINT UQ_DocumentGrants_Document_User UNIQUE(document_id, user_id)
);

CREATE TABLE AuditEvents (
    id UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    actor_id UNIQUEIDENTIFIER NULL,
    action NVARCHAR(80) NOT NULL,
    document_id UNIQUEIDENTIFIER NULL,
    outcome NVARCHAR(20) NOT NULL,
    details NVARCHAR(MAX) NOT NULL,
    created_at DATETIMEOFFSET NOT NULL DEFAULT SYSDATETIMEOFFSET(),
    previous_hash CHAR(64) NOT NULL,
    event_hash CHAR(64) NOT NULL
);
