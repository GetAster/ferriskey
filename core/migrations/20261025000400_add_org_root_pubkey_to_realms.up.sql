-- The organisation root's Ed25519 public key, as 64 lowercase hex characters.
-- Public material. Nullable: a realm has none until an admin sets it.
ALTER TABLE realms
    ADD COLUMN IF NOT EXISTS org_root_pubkey VARCHAR(64) NULL;

ALTER TABLE realms
    ADD CONSTRAINT realms_org_root_pubkey_check
        CHECK (org_root_pubkey IS NULL OR org_root_pubkey ~ '^[0-9a-f]{64}$');
