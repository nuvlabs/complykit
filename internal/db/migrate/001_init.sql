-- Organizations
CREATE TABLE IF NOT EXISTS orgs (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       TEXT        UNIQUE NOT NULL,
    name       TEXT        NOT NULL,
    plan       TEXT        NOT NULL DEFAULT 'free',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Scan records — findings stored as JSONB (matches existing engine.Finding struct)
CREATE TABLE IF NOT EXISTS scans (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    framework    TEXT        NOT NULL,
    score        INT         NOT NULL DEFAULT 0,
    passed       INT         NOT NULL DEFAULT 0,
    failed       INT         NOT NULL DEFAULT 0,
    skipped      INT         NOT NULL DEFAULT 0,
    findings     JSONB       NOT NULL DEFAULT '[]',
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_org_collected ON scans (org_id, collected_at DESC);

-- Track applied migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INT  PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES (1) ON CONFLICT DO NOTHING;
