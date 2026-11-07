# Authentication evidence and OpenID Connect requirements

The engine records successful proofs in the authorization transaction before any required action or consent continuation. It copies that evidence into the durable SSO session and the refresh-token lineage. An OpenID access token carries a signed snapshot for UserInfo; UserInfo never reads the latest authentication on a mutable SSO session. Enrollment is not authentication. An OTP added after a primary proof does not make that primary proof newer.

The additive migration adds nullable `auth_evidence` JSONB to `auth_sessions`, `user_sessions`, and `refresh_tokens`, plus nullable `auth_requirements` JSONB to `auth_sessions`. Older sessions have unknown evidence and gain no method or assurance claims. No new endpoint or deployment setting is required.

## Claims

- Verified passkey: `amr=[pop,user,mfa]`, `acr=phr`, and `aster_auth={method:passkey,credential:<base64url SHA-256 credential ID>,uv:true}`. AAGUID is optional and informational; the current assertion path omits it. The existing engine requires user verification and does not relax that policy. The evidence type can describe presence-only assertions without claiming MFA.
- Email magic link: `amr=[otp]`, `aster_auth={method:email_link}`.
- Password: `amr=[pwd]`, `aster_auth={method:password}`. A verified local OTP adds `otp` and, for a password primary proof, `mfa`.
- Federation: `aster_auth={method:federated,provider:...,upstream_iss:...,upstream_sub:...}`. Upstream identifiers come only from a verified provider ID token; OAuth UserInfo fallback supplies neither. No private `fed` AMR is emitted.

`auth_time` is preserved across SSO and refresh. Federated authentication uses a verified upstream `auth_time` when supplied; otherwise its authentication time is unknown and is omitted. A local callback time is not evidence of a fresh upstream authentication. Such a federated session cannot meet `max_age`; the existing login screen requests a local fresh proof instead. The engine does not claim upstream PIN, biometric, or hardware assurance.

`amr`, `acr`, `auth_time`, and `aster_auth` are reserved in both normal mapper execution and exchange issuance. Mappers cannot fabricate or retain authentication facts when the engine has no corresponding proof.

## Requirements and browser contract

For a strict passkey requirement use `claims={"id_token":{"acr":{"essential":true,"values":["phr"]}}}` and optionally `max_age`. Requirements remain on the transaction through proof, required actions, consent, SSO and code exchange. They are checked before code issuance and again before exchange. A different account cannot replace a transaction already bound to a proved account.

`acr_values` remains a preference. A resumable SSO session with a weaker proof and an available passkey is sent to passkey authentication; a fresh weaker sign-in can still complete when no essential requirement was requested. `max_age=0` requests a proof for the current transaction. `prompt=none` never opens interactive screens and returns standard noninteractive errors.

- `passkey_authentication_required`: HTTP 401 JSON with `message` and `reason`; retain the transaction and use the existing public passkey endpoints. The authorization endpoint and broker callback use the existing login page with `passkey_required=true`.
- `unmet_authentication_requirements`: HTTP 403 JSON with `message`, `reason`, and `redirect_url` during API-driven login. The URL is built solely from the stored validated authorization redirect, state and issuer, retaining its existing query. The screen follows it to return the standard error to the relying party. Authorization and broker callbacks use a direct redirect.
- A federation that cannot demonstrate the requested freshness returns to the same login transaction with `reauthentication_required=true`; local password, email-link or passkey proof can satisfy freshness.

A relying party must still verify the signed result and enforce its own policy. `phr` is phishing resistance, not hardware assurance. A credential hash identifies a credential, which may sync between devices, not one physical device.
