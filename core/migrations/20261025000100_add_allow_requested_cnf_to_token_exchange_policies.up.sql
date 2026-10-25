-- A policy must opt in before its client may ask for a `cnf` (confirmation)
-- claim on the exchanged token. Existing policies keep refusing it.
ALTER TABLE token_exchange_policies
  ADD COLUMN IF NOT EXISTS allow_requested_cnf BOOLEAN NOT NULL DEFAULT FALSE;
