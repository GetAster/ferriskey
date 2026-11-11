# Token endpoint review: undirected decisions

This note lists ten behaviours of the OIDC token endpoint that nothing in the repository accounts for: no RFC section, test, commit message or comment says they are intended. Some may be deliberate. Each needs a decision: keep it and record why, or change it. None has been raised upstream.

The review read `main` at `2716f02d` (2026-11-11). Line numbers refer to that revision. The service is `core/src/domain/authentication/services.rs` and the handler is `libs/ferriskey-api-authentication/src/handlers/token.rs`.

## How the list was made

An AI model (Claude Opus) charted the token endpoint as WebProcess Action charts, one per function, from `exchange_token` down through each grant. For every step it looked for a basis: the RFC 6749 or RFC 7636 section the code implements, a test that asserts the behaviour, the commit that introduced it, or a code comment. A step with none was marked undirected. A tool checked that every line of each function belongs to exactly one step.

Of 190 steps, 162 had a basis and 38 were undirected. The ten below are the ones with the most effect on clients or security. "Checked" means the behaviour was confirmed by reading the cited lines; the rest are the model's reading, with spot checks noted.

## The ten decisions

1. **A concurrent refresh revokes the whole token family.** When two refreshes of one token race, the loser finds the token already consumed, treats it as reuse and revokes the family (`refusal_for_unconsumed_refresh_token`, 3418–3433; the legacy path, 3683–3694). The winner's new token dies too, so a client that refreshes twice at once (two tabs, a retry) is logged out. The test `spec_rtp_4` asserts only that exactly one refresh succeeds. The authors' reproducer `sso_08_parallel_refreshes_keep_the_session_alive` (`api/tests/it/oidc_findings_test.rs:37`) is ignored as "SSO-08 open". Checked.

2. **An opaque refresh consumes the token before checking the session, resource, realm and account.** The consume runs first (3472–3491), then `ensure_session_binding` (3495–3506) and the rest. A failure after that point, including a storage fault reported as `session_invalid`, leaves the token used and the successor never handed out. The client's retry then looks like reuse and loses the family. Commit `a22e7d5e` moved only the resource check ahead of the consume. Checked.

3. **Disabled and locked accounts are refused before the password is checked.** `verify_login` refuses a disabled account at 3127–3131 and a locked one at 3134–3138, each with its own `invalid_grant` description, and without the dummy hash that the unknown-user path runs. Anyone who knows a username learns, without the password and faster than a real check, whether the account exists and its state. A locked account also refuses the right password, so the lock works as a denial of service on any known username. Commits `86dd4a18` and `9382e044` add the checks; neither discusses the order. Checked.

4. **Consent narrowing fails open.** `narrow_scope_by_consent_decision` reads the client's optional scopes with `unwrap_or_default()` (2622–2629). If that read fails, the list is empty and the full requested scope is granted without the user's consent. Checked.

5. **A storage error during the code lookup is answered as a bad code.** In `authorization_code` (2675–2682), a repository error becomes `MissingAuthorizationCode`, which the handler answers as 400 `invalid_grant`. A client following RFC 6749 then discards a code that was valid. Checked.

6. **The `scope` parameter is ignored on refresh.** The new tokens carry the scope of the consumed token (opaque path, 3565; legacy path, 3712). RFC 6749 §6 lets a client ask for a narrower scope on refresh, so a client asking for less silently receives everything. No test covers a scope parameter on refresh. Checked.

7. **Basic and form credentials can both be sent.** When the `Authorization` header carries client credentials, any `client_id` and `client_secret` in the form are ignored (`token.rs` 224–230), and the two client ids are not compared. RFC 6749 §2.3 forbids using more than one authentication method in a request, and §5.2 lists that case under `invalid_request`. Checked.

8. **Replaying a code that has no bound session revokes nothing.** `revoke_tokens_of_a_replayed_code` returns early when the login session has no `user_session_id` (2042–2044). For such a code, `authorization_code` opens a fresh SSO session and mints tokens against it, but does not record that session on the login session, so a replay cannot reach the tokens it should revoke. Commit `ee07ab91` speaks only of "the session it was bound to". Early return checked; the model's account of the unrecorded session was not traced.

9. **The code exchange checks that the account is enabled, but not that it is locked.** `authorization_code` checks `user.enabled` (2769–2772) and nothing else. Commit `99e85449` is titled "refuse a login completion and a code exchange for a disabled or locked user", but adds only the enabled check here. A user locked after logging in, for example by failed attempts elsewhere, can still redeem a code. Checked.

10. **Some token endpoint errors do not use the RFC 6749 format.** `token_endpoint_error` maps the grant errors to RFC 6749 bodies and passes every other error to the general `ApiError` conversion (`token.rs` 190). By the model's reading that gives 404 for `NotFound` and `InvalidRealm`, 503 for `ClientUnderMaintenance` and 500 for `InternalServerError`, each with FerrisKey's own body. Commit `49903ab7` is titled "answer every token endpoint error in the oauth format". The fallthrough is checked; the resulting status codes were not.

## Smaller findings

The other 28 undirected steps are mostly error-code choices (for example, a disabled client is answered `invalid_client` rather than `unauthorized_client`) and silent fallbacks: roles that fail to load give a token with no roles; realm settings that fail to load give default lockout limits of 10 attempts and 900 s. They are listed in the WebProcess repository, in `spec/chart/charts/experiments/ferriskey-opus-reviewed/`, with a "To review" list at the top of each chart.
