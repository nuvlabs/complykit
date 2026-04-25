-- System org for super admins (not a real customer org)
INSERT INTO orgs (id, slug, name, plan)
VALUES ('00000000-0000-0000-0000-000000000000', 'system', 'System', 'super')
ON CONFLICT (id) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES (3) ON CONFLICT DO NOTHING;
