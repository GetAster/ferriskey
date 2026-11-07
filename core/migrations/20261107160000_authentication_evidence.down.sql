ALTER TABLE refresh_tokens DROP COLUMN auth_evidence;
ALTER TABLE user_sessions DROP COLUMN auth_evidence;
ALTER TABLE auth_sessions DROP COLUMN auth_evidence, DROP COLUMN auth_requirements;
