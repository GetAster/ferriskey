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
