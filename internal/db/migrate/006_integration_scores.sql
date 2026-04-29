-- Add per-integration score breakdown to scans table.
-- Old rows default to '{}' — the UI shows gaps (no line) for integrations
-- not present in a scan, so empty is correct for historical data.
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS integration_scores JSONB NOT NULL DEFAULT '{}';
