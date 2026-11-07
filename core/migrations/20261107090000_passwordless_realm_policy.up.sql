-- Opt-in only: existing realms (including master) keep their password policy.
ALTER TABLE realm_settings ADD COLUMN passwordless_enabled boolean NOT NULL DEFAULT false;

-- Serialize password writes with policy changes. This also covers imports and
-- direct database writes rather than relying on every caller remembering a check.
CREATE FUNCTION enforce_passwordless_credential() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE passwordless boolean;
BEGIN
    IF NEW.credential_type = 'password' THEN
        -- Match user-move lock order, then serialize with realm policy changes.
        PERFORM 1 FROM users WHERE id = NEW.user_id FOR NO KEY UPDATE;
        PERFORM 1 FROM realms r JOIN users u ON u.realm_id = r.id
         WHERE u.id = NEW.user_id FOR NO KEY UPDATE OF r;
        SELECT s.passwordless_enabled INTO passwordless
          FROM realm_settings s JOIN users u ON u.realm_id = s.realm_id
         WHERE u.id = NEW.user_id;
        IF passwordless THEN
            RAISE EXCEPTION 'local passwords are disabled for this realm' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER passwordless_credential_guard BEFORE INSERT OR UPDATE ON credentials
FOR EACH ROW EXECUTE FUNCTION enforce_passwordless_credential();

CREATE FUNCTION enforce_passwordless_realm() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM realms WHERE id = NEW.realm_id FOR NO KEY UPDATE;
    IF NEW.passwordless_enabled THEN
        IF EXISTS (SELECT 1 FROM credentials c JOIN users u ON u.id = c.user_id
                   WHERE u.realm_id = NEW.realm_id AND c.credential_type = 'password') THEN
            RAISE EXCEPTION 'remove local password credentials before enabling passwordless policy'
                USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM user_required_actions a JOIN users u ON u.id = a.user_id
                   WHERE u.realm_id = NEW.realm_id AND a.action = 'update_password') THEN
            RAISE EXCEPTION 'clear password-update required actions before enabling passwordless policy'
                USING ERRCODE = '23514';
        END IF;
        NEW.email_verification_enabled := true;
        NEW.forgot_password_enabled := false;
        IF TG_OP = 'INSERT' OR NOT OLD.passwordless_enabled THEN
            DELETE FROM user_sessions WHERE realm_id = NEW.realm_id;
            DELETE FROM auth_sessions WHERE realm_id = NEW.realm_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER passwordless_realm_guard BEFORE INSERT OR UPDATE ON realm_settings
FOR EACH ROW EXECUTE FUNCTION enforce_passwordless_realm();

-- Moving an existing user must not smuggle a password into a protected realm.
CREATE FUNCTION enforce_passwordless_user_realm() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE passwordless boolean;
BEGIN
    PERFORM 1 FROM realms WHERE id = NEW.realm_id FOR NO KEY UPDATE;
    SELECT passwordless_enabled INTO passwordless FROM realm_settings
     WHERE realm_id = NEW.realm_id;
    IF passwordless AND (EXISTS (SELECT 1 FROM credentials WHERE user_id = NEW.id AND credential_type = 'password')
        OR EXISTS (SELECT 1 FROM user_required_actions WHERE user_id = NEW.id AND action = 'update_password')) THEN
        RAISE EXCEPTION 'local passwords are disabled for the destination realm' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER passwordless_user_realm_guard BEFORE UPDATE OF realm_id ON users
FOR EACH ROW WHEN (OLD.realm_id IS DISTINCT FROM NEW.realm_id)
EXECUTE FUNCTION enforce_passwordless_user_realm();

CREATE FUNCTION enforce_passwordless_required_action() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE passwordless boolean;
BEGIN
    IF NEW.action = 'update_password' THEN
        PERFORM 1 FROM users WHERE id = NEW.user_id FOR NO KEY UPDATE;
        PERFORM 1 FROM realms r JOIN users u ON u.realm_id = r.id
         WHERE u.id = NEW.user_id FOR NO KEY UPDATE OF r;
        SELECT s.passwordless_enabled INTO passwordless
          FROM realm_settings s JOIN users u ON u.realm_id = s.realm_id WHERE u.id = NEW.user_id;
        IF passwordless THEN
            RAISE EXCEPTION 'password updates are disabled for this realm' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER passwordless_required_action_guard BEFORE INSERT OR UPDATE ON user_required_actions
FOR EACH ROW EXECUTE FUNCTION enforce_passwordless_required_action();
