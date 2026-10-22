CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'member' CHECK (type IN ('member','service')),
    email TEXT,
    username TEXT,
    password_hash TEXT NOT NULL DEFAULT '',
    legacy_password_hash TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    metadata TEXT NOT NULL DEFAULT '{}',
    totp_secret_enc BLOB,
    totp_confirmed_at TEXT,
    authentik_pk INTEGER,
    authentik_uuid TEXT,
    authentik_uid TEXT,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX users_email_idx ON users(lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_username_idx ON users(username) WHERE username IS NOT NULL;

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX recovery_codes_user_idx ON recovery_codes(user_id);

CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    require_totp INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',
    authentik_uuid TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX memberships_group_idx ON memberships(group_id);

CREATE TABLE applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL DEFAULT '',
    client_type TEXT NOT NULL DEFAULT 'confidential',
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    subject_mode TEXT NOT NULL DEFAULT 'id',
    access_token_ttl INTEGER,
    refresh_token_ttl INTEGER,
    id_token_ttl INTEGER,
    launch_url TEXT NOT NULL DEFAULT '',
    icon_url TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    show_tile INTEGER NOT NULL DEFAULT 0,
    service_account_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    authentik_provider_pk INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE application_groups (
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (application_id, group_id)
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    totp_passed INTEGER NOT NULL DEFAULT 0,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE auth_codes (
    code_hash TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    auth_time TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    auth_time TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens(user_id);

CREATE TABLE password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens(user_id);

CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    private_key_enc BLOB NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    at TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_at_idx ON audit_events(at);
