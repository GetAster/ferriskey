# Email sign-in creates accounts after proof

In a passwordless realm with user registration enabled, requesting a sign-in
link for an unknown address now stores only the expiring, browser-bound proof.
It does not create a user or reserve a username. The account is created with a
verified email only when the link is redeemed in the initiating browser.

## Storage and redemption

This reuses the nullable `magic_links.user_id` column introduced for provider
registration in release 13. A null user with no provider intent represents
ordinary pending email registration. No migration, endpoint or configuration
key is added.

The existing verifier checks the browser transaction, token and expiry before
consumption. The consumption transaction locks that session, rechecks its
state and the realm's passwordless, registration and magic-link settings, then
inserts the verified account, binds the session and consumes the proof together.
The email address captured when the link was sent supplies both email and
username. No password credential is created.

An account or username created meanwhile causes the transaction to fail without
creating a second account or attaching the pending session to the conflicting
account. The person can request a fresh link. Concurrent redemptions cannot
create multiple accounts or consume the same proof twice. Wrong-browser visits
leave the proof available for copying to the requesting browser.

## Delivery and timing

Known and unknown eligible addresses share the same template lookup, rendering
and synchronous delivery path, with the existing recipient, realm and IP limits.
The plain-text email says to sign in or create an account in either case. Magic
link templates receive the recipient email but no stored first or last name,
so pre-authentication email is not personalized from an existing profile.
Password reset template personalization is unchanged. Operators should use
neutral wording in their configured magic-link template.

Removing account creation removes work unique to unknown addresses. It does not
prove that network timings are indistinguishable: mailbox delivery failures,
SMTP latency and throttling can dominate observed response time. Live comparison
must use controlled deliverable addresses and requests below the rate limits.
The application does not add sleeps, detached mail tasks or a mail queue.

## Other account-creation paths

- Legacy password registration creates an unverified account and password before
  email confirmation when passwordless mode is off. Passwordless realms refuse
  that route. This change does not alter legacy password registration.
- Resending verification requires a validated login-action identity and loads
  the existing account; it does not create one.
- Provider callbacks create accounts immediately only for trusted, verified
  provider email. Other provider registrations use the pending proof flow added
  in release 13.
- Authorized administrator creation, managed LDAP synchronization, startup
  bootstrap and trusted host service-account provisioning intentionally create
  accounts under their respective authority checks.

Existing unverified accounts are not deleted or remediated by this change.

## Verification

`passwordless_login_test` exercises the HTTP request without account creation,
wrong-browser refusal, same-browser verified creation, OAuth continuation,
replay refusal and changed-email rejection for existing accounts.
`deferred_email_registration_test` covers recipient throttling, expiry, session
state, disabled registration settings, case-insensitive email/username conflicts
and concurrent distinct proofs for the same address. The core unit suite asserts
that existing and unknown recipients both render a template and deliver mail,
without calling account creation.
