-- Pending registration proofs cannot be represented by the old schema.
DELETE FROM magic_links WHERE user_id IS NULL;
ALTER TABLE magic_links ALTER COLUMN user_id SET NOT NULL;
