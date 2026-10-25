ALTER TABLE realms DROP CONSTRAINT IF EXISTS realms_org_root_pubkey_check;
ALTER TABLE realms DROP COLUMN IF EXISTS org_root_pubkey;
