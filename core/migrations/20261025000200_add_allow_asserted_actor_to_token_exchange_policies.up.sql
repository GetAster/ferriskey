-- A policy must opt in before its client may name an actor it merely vouches
-- for (`actor_assertion`) instead of presenting an actor token. Delegation must
-- be allowed as well. Existing policies keep refusing it.
ALTER TABLE token_exchange_policies
  ADD COLUMN IF NOT EXISTS allow_asserted_actor BOOLEAN NOT NULL DEFAULT FALSE;
