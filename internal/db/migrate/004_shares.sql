CREATE TABLE IF NOT EXISTS share_links (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_by UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_id    UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    token      TEXT        UNIQUE NOT NULL,
    label      TEXT        NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_share_links_org   ON share_links (org_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links (token);

INSERT INTO schema_migrations (version) VALUES (4) ON CONFLICT DO NOTHING;
