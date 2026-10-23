ALTER TABLE users ADD COLUMN description TEXT NOT NULL DEFAULT '';

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL CHECK (scope IN ('admin','read')),
    created_by_user_id TEXT NOT NULL DEFAULT '', -- no foreign key: the token outlives its creator
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    expires_at TEXT
);
CREATE INDEX api_tokens_account_idx ON api_tokens(service_account_id);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_id);
CREATE INDEX audit_events_target_idx ON audit_events(target_id);
