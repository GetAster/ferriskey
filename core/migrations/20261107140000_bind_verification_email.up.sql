-- Old tokens cannot safely be bound to a mutable current user address.
-- Leave them unbound; recipients can request a fresh verification email.
ALTER TABLE email_verification_tokens ADD COLUMN email TEXT;
