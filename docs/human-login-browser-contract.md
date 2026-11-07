# Human login browser contract

This is the contract for aster-idp's same-origin human pages. Ferriskey owns the
OAuth authorization transaction, authentication proofs, required actions, consent,
and code issuance. The page renders the current step and follows the server's
returned URL. It must not issue tokens, manufacture a redirect URI, or store a
password to bootstrap a passwordless account.

Paths below are relative to `{root_path}/realms/{realm}`. `root_path` is the API
mount prefix, not the human-page prefix. Requests with bodies use JSON and
`Content-Type: application/json`; responses are plain JSON, without a `data`
envelope unless explicitly shown. Browser fetches must retain same-origin
cookies. Server-rendered pages may use browser JavaScript for these calls and
WebAuthn. A server-side proxy must forward cookies and every `Set-Cookie` header;
it must not share a cookie jar between users. In particular, a page handler under
`/authentication/*` does not receive the action cookie scoped to `/login-actions`.
Render the page there, then call the API directly from the browser; do not assume
that handler can forward a cookie the browser did not send.

## Start an authorization transaction

Navigate the browser to `GET /protocol/openid-connect/auth` with the relying
party's `client_id`, registered `redirect_uri`, `response_type=code`, requested
`scope`, `state`, and its PKCE `code_challenge`/`code_challenge_method=S256`.
OIDC clients also provide `nonce`. Preserve the relying party's values; the
human page is not a new OAuth client in the middle of this transaction.

The endpoint validates the request, creates an authentication session and normally
returns 302 to `{webapp_url}/realms/{realm}/authentication/login?...`. It sets
`FERRISKEY_SESSION` before that redirect. Existing SSO can instead complete the
request or go to consent. `prompt=login` or `max_age=0` asks for fresh
authentication. `prompt=none` never opens a human page; errors return to the
validated callback. Invalid clients/redirects go to the login error screen, not
an untrusted callback.

The configured `webapp_url` must route the selected realm's human screens to
aster-idp. The API `root_path` is applied independently. WebAuthn RP identity is
also derived from `webapp_url`; changing its hostname is not a cosmetic change.

## Cookies and proof state

| Cookie | Path | Purpose |
| --- | --- | --- |
| `FERRISKEY_SESSION` | `/` | UUID identifying the OAuth authentication transaction. Read by password login, registration, passkey challenge and proof, magic-link request, and consent. It is not a completed login. |
| `FERRISKEY_LOGIN_ACTION` | `{root_path}/realms/{realm}/login-actions` | Signed, expiring, server-validated temporary token authorizing only the remaining login steps. Never expose it to JavaScript. |
| `FERRISKEY_SSO` | `/` | Opaque authenticated session secret. Subsequent authorization requests may reuse it under realm/client and freshness policy. |

All three are host-only, `HttpOnly`, `SameSite=Lax`; HTTPS sets `Secure`.
`FERRISKEY_SESSION` and the action cookie have browser-session cookie lifetime;
the server separately enforces their transaction/token expiry. SSO is also a
browser-session cookie unless remember-me is requested and enabled, in which
case the response supplies `Max-Age`. `FERRISKEY_IDENTITY` is obsolete and cleared.

Login-action middleware validates the signature, realm, live session and token
purpose. When a session cookie is supplied it must match the action token's
session. A pending OTP limits actions to the OTP challenge/recovery-code paths.
Successful completing steps consume their token; if more actions remain, the
response replaces it with a follow-up cookie. Serialize completing requests:
replaying a consumed token fails, and concurrent consumption can return 409.
A normal bearer access token is not a substitute for the action cookie.

## Primary authentication endpoints

| Method and path | Input | Result |
| --- | --- | --- |
| `POST /login-actions/authenticate?client_id=...` | `{username,password,remember_me?:false}` plus session cookie | `AuthenticateResponse` below. Local-password authentication is forbidden in a passwordless realm. |
| `POST /login-actions/send-magic-link` | `{email,remember_me?:false}` plus session cookie for OAuth continuation | `{message}`; show check-your-email. Do not infer account existence from the success message. |
| `GET /login-actions/verify-magic-link?token_id=...&magic_token=...` | Values from the received link; preserve session cookie | Authentication result. Consume the link once; retain `Referrer-Policy: no-referrer`, remove secret query values from page history after completion. |
| `POST /login-actions/passkey-request-options` | `{}` for discoverable credentials, or `{username}`; session cookie required | WebAuthn request options with `publicKey`. |
| `POST /login-actions/passkey-authenticate?remember_me=false` | Serialized WebAuthn assertion JSON directly, not wrapped in another field; session cookie required | Completed login or required-action continuation. |

Convert base64url values in WebAuthn JSON into the browser API's expected binary
values, invoke `navigator.credentials.get`, then serialize the assertion back to
JSON. The existing `front/src/lib/webauthn.ts` is prior art; no React component
state is needed for verification. Credential creation uses `navigator.credentials.create`
with the analogous conversion.

The established `AuthenticateResponse` is
`{status,url,required_actions,email,message}`. Status values are case-sensitive:
`Success`, `RequiresActions`, `RequiresOtpChallenge`, `Failed`. Required-action
values are lower snake case. Success navigates to the supplied `url`; this may
be consent rather than the relying party yet. Required actions select the first
returned action. OTP challenge opens its challenge page. Do not turn every 200
into successful authentication.

Passkey authentication preserves its existing `login_url` field: success returns
`{status:"Success",login_url:"...",required_actions:[]}`; pending steps return
`{status:"RequiresActions",login_url:"",required_actions:[...]}`. Magic-link
verification uses `AuthenticateResponse` above, including `RequiresOtpChallenge`
when applicable. Both issue the same action cookie when another step is needed.
Handle the empty passkey `login_url` by rendering the returned actions, not by
navigating to an empty URL.

## Required actions and email verification

| Method and path | Input/proof | Result |
| --- | --- | --- |
| `POST /login-actions/webauthn-public-key-create-options` | Session and action cookies; no body | WebAuthn creation options with `publicKey`. |
| `POST /login-actions/webauthn-public-key-create` | Serialized creation credential JSON; action cookie | `{url? ,required_actions?}` and cookie continuation. |
| `POST /login-actions/verify-email` | `{token}` from the verification email; no login cookie required | `{user_id,verified}`. Verifies the contact address, not the browser's identity. |
| `POST /login-actions/resend-verification-email` | Valid action cookie; no body | `{message}`. Sends only for the authenticated pending user in this realm. An unsigned bearer payload is never accepted. |
| `POST /login-actions/skip` | Valid action cookie and `{action:"configure_passkey"}` | Declines only the optional offer; returns `{url?,required_actions?}` like continue. Stored mandatory actions cannot be skipped. |
| `POST /login-actions/continue` | Valid action cookie; no body | Re-reads pending actions and returns `{url?,required_actions?}`. Complete only when all server-side conditions are satisfied. |

Verification tokens bind the exact address to which the email was sent. Consuming
one atomically verifies only that unchanged address; it never writes an older
profile snapshot back over the current account. Legacy verification links created
before address binding require a fresh email. Repeating a used link is idempotent
only while the account still has the same captured, verified address.

After verification in the same browser, call `continue`. When a link opens in a
different browser, show verification success and ask the user to return to their
original login. That browser can call `continue` after an explicit “I've verified
my email” action. Without a valid action cookie, start a fresh login; do not treat
`{verified:true}` as an OAuth callback. A verification link alone cannot claim or
complete an arbitrary browser session.

The React route `page-required-action-feature.tsx` reads `execution` from the
URL. Its UI maps `verify_email`, `configure_passkey`, `configure_otp`, and
`update_password` to individual forms. `continue-login.ts` follows `url` if
present; otherwise it opens the first returned action. Those are presentation
choices; the server validates every action again. Passwordless pages must not
render `update_password` as a fallback.

The legacy verify-email UI stored client context locally, hardcoded
`security-admin-console`, and returned to login. That is not the new protocol:
use the existing authenticated transaction and `continue`. No localStorage or
React router state is required by the API.

## Optional passkey offer

With both `passwordless_enabled` and `passkey_enabled`, a verified email-link or
social sign-in offers `configure_passkey` when the account has no passkey. The
server computes this after mandatory actions and any OTP proof; it never stores
an extra required-action row. Passkey sign-in does not offer enrollment again.
The page offers **Create a passkey** and **Maybe later**.

Creation uses the existing action-cookie ceremony and requests a discoverable
credential (`residentKey: "required"`, `requireResidentKey: true`) with
`userVerification: "required"`. Successful creation returns the completion URL
and sets the SSO cookie through the same completion path as other login actions;
if consent is pending, follow that URL and finish consent first.

**Maybe later** calls `POST /login-actions/skip` with
`{"action":"configure_passkey"}`. The server rechecks the account and mandatory
requirements. A stored `configure_passkey` action is mandatory and returns 403
with reason `action_required`; keep the creation button and explain that this
account needs a passkey. Other actions cannot be skipped. The optional offer is
last, so successful skip completes this transaction or returns its consent URL.
It consumes the action token: replaying skip or calling continue with the spent
cookie fails. There is no saved decline; the next email/social sign-in offers
again until a passkey exists. The next transaction gets its own cookie.

Named passkey assertions may omit `userHandle`: their server-side challenge is
bound to the selected account, and the credential must belong to that account.
If a handle is supplied it must match, as required by [WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion). Discoverable assertions still require a
valid handle. The browser never chooses the authoritative account at proof time.
Sign-in proofs consume their server challenge atomically. Expired/completed
transactions and challenges older than five minutes are refused; a failed proof
requires fresh options. Existing non-discoverable credentials remain usable via
named sign-in; making new credentials discoverable does not convert old ones.

## Registration

The existing React `useRegistrationMutation` calls
`POST /protocol/openid-connect/registrations`, not a login-actions registration
endpoint. Its baseline body is `{email,password,username?,first_name?,last_name?}`.
The API reads an optional session cookie and returns HTTP 201 with one of:

- `{status:"redirect",data:{url}}` for a continued browser transaction;
- `{status:"pending_action",data:{message,user_id}}` for verification;
- `{status:"authenticated",data:{access_token,...}}` for the legacy standalone path.

The last form is not the design for aster-idp's browser OAuth flow. Begin an
OAuth transaction first and retain its cookie. In a realm with
`passwordless_enabled=true` and `user_registration_enabled=true`, submit the
same `{email,remember_me?}` body to `POST /login-actions/send-magic-link` for a
new person. The live browser session must belong to that realm. The server creates
a password-free account for an unknown address and sends its verification/login
link; it creates no temporary or random password. With registration disabled,
an unknown address does not become an account. There is no separate registration
alias: one email entry point covers returning users and permitted signup.

## Consent and completion

A server-returned consent URL includes `consent_token`. The human page reads
`GET /auth/consent?consent_token=...` with the session cookie. The result has
`client_name`, optional `client_uri_host`, `granted_by_default`, and
`awaiting_decision`; scope entries have `name` and optional `description`.
Submit `POST /auth/consent` with `{consent_token,approved_scopes:[...]}` and the
same cookie. It returns `{redirect_url}` and may set SSO. Follow that URL exactly.

The final server-generated redirect contains the authorization code and the
original state, and includes issuer identification. The relying party exchanges
the code at `/protocol/openid-connect/token` with its PKCE verifier and applicable
client authentication. The human page must not exchange that client's code or
replace its redirect URI. An error, remaining required action, or consent screen
is not completion.

## Social provider continuation

The broker callback verifies the external provider's response before binding its
user to the browser authentication session. Local requirements still apply.
When email verification, passkey setup or another action remains, the callback
sets the same action cookie and returns 302 to
`/realms/{realm}/authentication/required-action?execution=...`; an outstanding
OTP redirects to `/realms/{realm}/authentication/otp`. It issues no authorization
code at that stage. Verification email delivery is attempted for `verify_email`;
the page can use the protected resend action. A provider that supplies no contact
email cannot satisfy the verified-contact policy; do not mark the account verified
or accept an arbitrary browser-supplied replacement address as proof.

## Enabling the realm policy

`passwordless_enabled` defaults to false. Enabling it refuses a realm that still
contains local password credentials or `update_password` required actions. It
forces email verification on and password
recovery off, and invalidates existing realm authentication/user sessions. It
does not delete password hashes automatically. Credential creation/import/update
and concurrent password writes are guarded by the server and database.

For migration, first test replacement login and recovery methods, stop/drain realm
login traffic, explicitly remove the old password hashes and obsolete `update_password` actions
under the agreed migration plan, enable the setting, then restart/resume. Concurrent sign-ins during the policy
transition are not supported: a password check already in progress could otherwise
finish under the old policy. Do not enable it for the master realm without its
separate administration/recovery plan.

Portal page requirements and theme validation use these effective settings.
Passwordless login/register pages do not require `password_input`; disabled
registration, recovery and magic-link pages have no mandatory form blocks.

## Passwordless passkey management

Enrollment during a pending login uses the action-cookie endpoints above.
Management after login uses the account API's authenticated session and short
recent-authentication elevation. A refresh token does not count as fresh human
authentication. When too old, run a normal authorization request with
`prompt=login`/`max_age=0`, then request elevation before changing credentials.
In a passwordless realm, `POST /users/me/reauthenticate` with
`{recent_authentication:true}` uses the current authenticated session and returns
`{elevation_id,expires_at}`. It is exclusive with `password`/`otp_code`. The
session must belong to this caller and realm, be live, and have authenticated
within five minutes. The request must also carry the matching `FERRISKEY_SSO`
browser cookie for that access token's session; a bearer token alone does not
prove a recent interactive login. Verified, nonempty contact email is required. Elevation
expires no later than that authentication time plus five minutes.

The bearer-authenticated management calls are
`POST /users/me/passkeys/options` with `{elevation_id}`, then
`POST /users/me/passkeys` with `{elevation_id,credential}`; removal uses
`DELETE /users/me/passkeys/{credential_id}` with `{elevation_id}`. These are
separate from the pending-login cookie endpoints. Do not fall back to asking a
passwordless user for a local password. Changing the contact email through
`PUT /users/me` is currently refused in a passwordless realm: a verified
email-change journey is not implemented. Other profile fields and the same
email remain supported.

## Source map and implementation boundary

The source of truth is `libs/ferriskey-api-authentication/src/router.rs`,
`libs/ferriskey-api-trident/src/router.rs`, their handlers, and
`libs/ferriskey-api-core/src/{auth,login_step,sso_cookie}.rs`.
The email continuation and optional offer add two endpoints (`continue` and `skip`) and no new cookie or
browser-held credential. The realm policy adds `passwordless_enabled`; signup
reuses `send-magic-link`. The implementation preserves the existing password
flows for realms that do not enable this policy, including the master console.

## Standards and implementation boundary

OAuth authorization code flow and OpenID Connect remain the client-facing
protocol. Reauthentication uses the existing OIDC `prompt=login` / `max_age`
semantics; credential-management recency is checked against the server session,
not a client timestamp ([OIDC Core authentication request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)).
The passwordless realm disables the resource owner password credentials grant,
consistent with [OAuth Security BCP section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4).
WebAuthn registration/assertion verification remains in the existing WebAuthn
library. Email links and login-action JSON endpoints are FerrisKey browser
implementation contracts, not new OAuth grants. Agent `cnf` and proof-of-possession
contracts are unchanged.

Email links created before the captured-email migrations must be requested again;
the server does not infer a delivered address for an old token. Migration never
marks an email verified by itself.
