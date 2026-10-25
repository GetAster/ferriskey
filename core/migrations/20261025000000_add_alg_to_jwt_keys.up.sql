-- A realm key records the algorithm it signs with, so signing and verification
-- follow the key and a later key of another type can replace it. Every existing
-- key is RSA and signs RS256.
ALTER TABLE jwt_keys
    ADD COLUMN IF NOT EXISTS kty TEXT NOT NULL DEFAULT 'RSA',
    ADD COLUMN IF NOT EXISTS alg TEXT NOT NULL DEFAULT 'RS256';

ALTER TABLE jwt_keys
    ADD CONSTRAINT jwt_keys_kty_alg_check
        CHECK ((kty, alg) IN (('RSA', 'RS256'), ('OKP', 'EdDSA')));
