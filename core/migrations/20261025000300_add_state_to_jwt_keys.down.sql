-- Only the active key survives: a realm is back to one key.
DELETE FROM jwt_keys WHERE state <> 'active';

DROP INDEX IF EXISTS jwt_keys_one_next_per_realm;
DROP INDEX IF EXISTS jwt_keys_one_active_per_realm;
DROP INDEX IF EXISTS jwt_keys_realm_id_idx;
CREATE UNIQUE INDEX IF NOT EXISTS jwt_keys_realm_id_key ON jwt_keys (realm_id);

ALTER TABLE jwt_keys DROP CONSTRAINT IF EXISTS jwt_keys_verify_until_check;
ALTER TABLE jwt_keys DROP CONSTRAINT IF EXISTS jwt_keys_retired_at_check;
ALTER TABLE jwt_keys DROP CONSTRAINT IF EXISTS jwt_keys_state_check;
ALTER TABLE jwt_keys DROP COLUMN IF EXISTS verify_until;
ALTER TABLE jwt_keys DROP COLUMN IF EXISTS retired_at;
ALTER TABLE jwt_keys DROP COLUMN IF EXISTS state;
