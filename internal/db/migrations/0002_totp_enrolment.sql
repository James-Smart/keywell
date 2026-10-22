-- A TOTP enrolment in progress, one per session: the sealed secret from
-- "begin" until "confirm", then the plaintext recovery codes until they are
-- shown once. Deleted when shown, or with the session.
CREATE TABLE totp_enrolments (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    secret_enc BLOB NOT NULL,
    codes_json TEXT,
    created_at TEXT NOT NULL
);

-- Wrong codes entered at the TOTP step of this session's sign-in.
ALTER TABLE sessions ADD COLUMN totp_failures INTEGER NOT NULL DEFAULT 0;
