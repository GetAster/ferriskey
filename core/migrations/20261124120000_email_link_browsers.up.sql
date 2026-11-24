-- Browsers that have redeemed an email link for an account, by a hash of
-- the browser's recognition cookie (never the cookie value itself).
CREATE TABLE email_link_browsers (
    id UUID PRIMARY KEY,
    realm_id UUID NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_hash BYTEA NOT NULL,
    label TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, browser_hash)
);
