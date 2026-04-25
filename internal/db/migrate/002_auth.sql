CREATE TABLE IF NOT EXISTS users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email         TEXT        UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'member', -- 'admin' | 'member'
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_org ON users (org_id);

CREATE TABLE IF NOT EXISTS api_keys (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name       TEXT        NOT NULL,
    key_hash   TEXT        UNIQUE NOT NULL, -- bcrypt hash of the raw key
    key_prefix TEXT        NOT NULL,        -- first 8 chars shown in UI e.g. "ck_live_"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_apikeys_org ON api_keys (org_id);

INSERT INTO schema_migrations (version) VALUES (2) ON CONFLICT DO NOTHING;
