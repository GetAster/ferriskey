-- A realm may hold several signing keys. `active` signs; `next` is published in
-- the JWKS ahead of promotion; `retired` is published and verifies until the
-- longest token it could have signed has expired. Every existing key was the
-- realm's only key and keeps signing.
ALTER TABLE jwt_keys
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS retired_at TIMESTAMP NULL,
    -- When a retired key stops verifying and leaves the JWKS: its retirement
    -- plus the longest token it could have signed, fixed at retirement so that
    -- lowering a token lifetime later cannot cut a live token off.
    ADD COLUMN IF NOT EXISTS verify_until TIMESTAMP NULL;

ALTER TABLE jwt_keys
    ADD CONSTRAINT jwt_keys_state_check
        CHECK (state IN ('next', 'active', 'retired')),
    ADD CONSTRAINT jwt_keys_retired_at_check
        CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
    ADD CONSTRAINT jwt_keys_verify_until_check
        CHECK ((state = 'retired') = (verify_until IS NOT NULL));

DROP INDEX IF EXISTS jwt_keys_realm_id_key;

CREATE INDEX IF NOT EXISTS jwt_keys_realm_id_idx ON jwt_keys (realm_id);
CREATE UNIQUE INDEX IF NOT EXISTS jwt_keys_one_active_per_realm
    ON jwt_keys (realm_id) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS jwt_keys_one_next_per_realm
    ON jwt_keys (realm_id) WHERE state = 'next';
