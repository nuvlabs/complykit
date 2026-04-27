CREATE TABLE IF NOT EXISTS compliance_checks (
    id          TEXT PRIMARY KEY,
    title       TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    integration TEXT        NOT NULL,
    frameworks  JSONB       NOT NULL DEFAULT '[]',
    controls    JSONB       NOT NULL DEFAULT '[]',
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
