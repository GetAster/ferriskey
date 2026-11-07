ALTER TABLE auth_sessions ADD COLUMN auth_evidence JSONB, ADD COLUMN auth_requirements JSONB;
ALTER TABLE user_sessions ADD COLUMN auth_evidence JSONB;
ALTER TABLE refresh_tokens ADD COLUMN auth_evidence JSONB;
