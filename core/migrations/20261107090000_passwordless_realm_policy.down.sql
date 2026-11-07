DROP TRIGGER passwordless_required_action_guard ON user_required_actions;
DROP FUNCTION enforce_passwordless_required_action();
DROP TRIGGER passwordless_user_realm_guard ON users;
DROP FUNCTION enforce_passwordless_user_realm();
DROP TRIGGER passwordless_realm_guard ON realm_settings;
DROP FUNCTION enforce_passwordless_realm();
DROP TRIGGER passwordless_credential_guard ON credentials;
DROP FUNCTION enforce_passwordless_credential();
ALTER TABLE realm_settings DROP COLUMN passwordless_enabled;
