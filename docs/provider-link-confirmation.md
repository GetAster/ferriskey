# Confirming a provider connection

When an unlinked provider identity presents an address already held by a local
account, automatic linking still requires `trust_email`, upstream
`email_verified: true`, and a verified local address. If that rule fails, an
enabled, unlocked account can prove the address using an explicit connection
email. A `link_only` provider continues to reject this situation.

The callback opens a fresh unauthenticated browser transaction, sends the
connection proof to the existing account's address, and redirects to:

`/realms/{realm}/authentication/connect-identity-provider?provider={encoded_alias}`

Hosts should render the `connect_identity_provider` pending screen there. The
callback sets `FERRISKEY_SESSION` but issues neither an authorization code nor a
primary login-action token for the target account. The provider label is display
text, not proof. The signed provider identity remains server-side in the
`provider_link` JSONB field of its specific magic-link row. This includes the
provider ID, external identity key, target user/address and optional first-consent
profile names; no upstream credential is retained.

The message explicitly asks the person to connect the provider and explains that
it will let that identity sign in. It uses the existing SMTP sender and magic-link
URL, expiry, hash and shared sending limits. It deliberately bypasses a generic
sign-in HTML template so the connection cannot be mistaken for ordinary login.
Recipient or realm suppression has the same response as a successful send.
The shared client-IP limit returns HTTP 429 before attempting delivery.

Redemption requires the original browser cookie and the correct, unexpired token.
One database transaction consumes that exact proof, checks the live unauthenticated
session, unchanged contact address, enabled/unlocked account, enabled provider in
the same realm, and inserts the connection without overwriting another link.
Optional first-consent names fill only missing profile names. Ordinary email
verification, OTP and required-action handling then continue. Authentication is
still email-link authentication; connecting a provider does not manufacture
federated authentication evidence.

To decline, the host sends a credentialed JSON `{}` POST to:

`/api/realms/{realm}/login-actions/decline-provider-link`

(The `/api` prefix follows the configured root path.) It returns 204, deletes only
pending connection proofs for that browser session in that realm, and expires the
pending transaction. It cannot cancel ordinary magic links or another session.
Redemption and decline use the same row-lock order. After a successful redemption,
declining does not unlink the account.

New surface: one nullable database column and one decline endpoint. No new realm
setting, persisted required-action enum, OAuth client, or secret is introduced.

## Opening the email in another browser

Verification returns HTTP 400 with `reason: magic_link_browser_mismatch` when
`FERRISKEY_SESSION` is missing or does not match the initiating transaction.
This check precedes token consumption and does not modify the account or session.
It is not an assertion that the token is otherwise valid or unexpired.

Render the original email-page URL in a read-only selectable field and provide
**Copy sign-in link**. Tell the person to paste it into the browser where they
started signing in, and to close the page if they did not initiate the request.
Clipboard failures must permit manual copying. Do not put the browser session
cookie into the URL, restore it from the URL, or start a replacement transaction.
The original browser must still hold its independently established session cookie.
Use a no-referrer policy for pages containing email proofs.

## New registrations with untrusted provider email

A new provider identity can create an account immediately only when the provider
has `trust_email=true` and its validated upstream identity reports `email_verified=true`.
Missing/false verification, or a provider whose email we do not trust, uses the
same confirmation screen and email proof as existing-account linking. A missing
or blank email on a new provider identity is refused; an existing provider link
continues to identify its already-linked account.

Until the proof is redeemed, there is no user row, provider link, login-action
token, authorization code or authenticated session for the new identity. The
pending intent stores a reserved prospective user UUID, a registration username
and display profile. The magic-link row has a null user foreign key. This does
not reserve the email address: its real owner can register independently.

After the existing browser, token and expiry checks, one database transaction
creates the verified account, inserts its provider link, binds the browser
transaction and consumes the proof. Case-insensitive email/username conflicts or
an already-connected provider identity abort the whole transaction. No existing
account is silently merged or overwritten: restart provider sign-in to obtain
an explicit existing-account connection proof. Expiry, decline or failed
confirmation leave no provisional account to clean up.

This requires `magic_link_enabled`, the configured magic-link template and SMTP
for the realm. Disabled delivery fails closed; it cannot fall back to trusting
the provider email. The existing shared email limits apply before generating a
proof, and pending-registration delivery events have no user actor. Connection
emails name the provider and explicitly describe connecting it; they do not use
the generic sign-in template.

Migration `20261108200000_pending_provider_registration` makes
`magic_links.user_id` nullable, retaining its foreign key. Old ordinary and
provider-link proofs remain compatible. Rolling back discards only null-user
pending-registration proofs before restoring the non-null requirement. The
repository's `consume` now returns the committed user ID; callers must use it
instead of assuming every pending proof already belongs to a user.

This change prevents new unverified provider registrations. It does not unlink
or otherwise remediate accounts created through the older behavior; assess those
separately before making changes to existing account access.
