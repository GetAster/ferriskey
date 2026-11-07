# Aster patch ledger: ferriskey

This repository is Aster's fork of [ferriskey/ferriskey](https://github.com/ferriskey/ferriskey). Aster carries the patches listed below on top of upstream releases. Upstream maintainers are welcome to incorporate any of them, in whole or in part, at their discretion.

Aster runs FerrisKey as the engine of `aster-idp`, Aster's identity provider. The fork supplies both the standalone server and an embeddable API library. Container builds retain image tags; aster-idp pins the API crate to an exact Git revision.

## Branch and tag model

- `main` is upstream `main` plus the Aster README preamble, this ledger, the removal of `.github/dependabot.yml` (Dependabot would open PRs on the mirror and spend our GitHub allowance; Actions are also off on Forge and GitHub) and the rust-dev house-rule build changes (dev/test debug info capped at zero; one integration-test binary per crate, so upstream's new `api/tests/*.rs` files are moved into `api/tests/it/` when merged). Nothing is built from `main`. It is refreshed with `git merge upstream/main` and is never reset or force-pushed. Ledger edits are commits on `main`, never on `upgrade/*`.
- The current patched line is `upgrade/ferriskey-v0.10.2`: the upstream release tag `v0.10.2` plus the patches in this ledger. The line follows upstream release tags only: for each new release `upgrade/ferriskey-v<upstream version>` is cut from the tag and the patches are cherry-picked onto it. Aster-only fixes append to the current branch. Published `upgrade/*` branches and tags are never rewritten.
- `upgrade/ferriskey-main-9a7d5d8c` was the line before it: upstream `main` at the pinned commit `9a7d5d8c`, chosen by owner decision (2026-10-25) because the changes this fork needs (sealed realm keys, signing-key cache, aws-lc-rs signing) had landed after `v0.9.0`. It was superseded on 2026-11-05 by the `v0.10.2` line, is left unchanged and was never tagged. Its topic branches (`feat/eddsa-signing-main`, `feat/confirmation-claim`, `feat/asserted-actor`, `feat/signing-key-rotation`, `feat/realm-org-root`) are kept as they are.
- `upgrade/ferriskey-v0.9.0` was published on Forge before that decision. It is superseded, left unchanged and carries no patches.
- Topic branches carry one change each, are named for the change (for example `feat/eddsa-signing`), are based on the release tag the upgrade branch is cut from, or on a prerequisite patch's commit, which its row names, and are cherry-picked with `git cherry-pick -x` onto the upgrade branch, so every upgrade-branch commit names its source. Re-cutting a topic onto a new upstream release takes a versioned name, `<topic>-v<upstream version>`.
- Tags: `aster-ferriskey-v<upstream version>-<n>`, where `n` counts Aster builds on that upstream release (`aster-ferriskey-v0.10.2-1`, `-2`, …). The container image built from a tag carries the same tag, and `aster-idp` pins the image by digest. A tag is created only after `aster-idp`'s tests pass against that exact commit, because tags cannot be moved.
- Forge (`forge.emrul.dev/Aster/ferriskey`) is canonical and push-mirrors to `github.com/getaster/ferriskey`. Never push to GitHub or upstream directly.
- Aster does not submit patches upstream; upstream maintainers are welcome to take any patch here.

## Current release

`aster-ferriskey-v0.10.2-4` on `upgrade/ferriskey-v0.10.2`, published on 2026-11-07 at `01aa97d11c24b67cc05db994a76e2433a6637e16`. This release adds the optional passkey offer and browser ceremony repairs (row 11). Before tagging, aster-idp passed 154 tests against this exact revision (2 real-binary smoke tests ignored). Deployment and live browser rerun have been handed to the aster-idp deployment agent and are pending confirmation.

Previous release: `aster-ferriskey-v0.10.2-3` on `upgrade/ferriskey-v0.10.2`, published on 2026-11-07 at `b6b51c55af2f5e37a5e457474427775e0c108c03`. This release adds opt-in passwordless realm policy and human browser login continuation (row 10). Before tagging, aster-idp's full suite passed 154 tests against this exact revision (2 real-binary smoke tests remained ignored). Deployed at `https://auth.getaster.now` inside aster-idp `a9e77e3`, image digest `sha256:6279c7c66fa85b6688dc8fd9fc0507c809a0ccb9d2fe1c03c717c83cf594fd39`. The public API confirms passwordless mode on realm `aster` and off on `master`; the console was rebuilt from this tag.

Earlier release: `aster-ferriskey-v0.10.2-2` on `upgrade/ferriskey-v0.10.2`, published on 2026-11-07 at `4e3781da9f311b7352b735f7df82bdb8af6e7808`. This release adds the embedded application builder, trusted issuance, atomic service-account provisioning and public host API exports. Before tagging, aster-idp `d737911` passed 151 tests and both explicit PostgreSQL smoke tests against this exact revision; default and no-default builds passed. The embedded host consumes the pinned Rust crate. The embedded revision was subsequently deployed inside aster-idp `54c8cf0` at the development instance on 2026-11-07. This is not a standalone FerrisKey API image release.

The previous `-1` tag was created on 2026-11-05 by owner decision before aster-idp tests existed; its unpublished local image IDs are retained below.
| Tag | Commit | Image digest |
| --- | --- | --- |
| `aster-ferriskey-v0.10.2-4` | `01aa97d1` | Deployment pending confirmation. |
| `aster-ferriskey-v0.10.2-3` | `b6b51c55` | aster-idp `a9e77e3`: `sha256:6279c7c66fa85b6688dc8fd9fc0507c809a0ccb9d2fe1c03c717c83cf594fd39`. |
| `aster-ferriskey-v0.10.2-2` | `4e3781da` | Embedded in deployed aster-idp `54c8cf0`; see the aster-idp deployment record for its image digest. |
| `aster-ferriskey-v0.10.2-1` | `2508c406` | Not published. Image IDs: api `sha256:66ea5e2ea364e8fe7ab03e61c06a4c64c94e7dded46eb66c726a51d61441e7c5`, webapp `sha256:25d43e942ccb8b6becfcfcc326da79f9aeb92fa4414c9176b13d0bcfe2521b89` |

## Patches

| # | Topic branch | Summary | Upstream status |
| --- | --- | --- | --- |
| 1 | `feat/eddsa-signing-v0.10.2` | Per-key signing algorithm on the `jwt_keys` row (`kty`, `alg`); EdDSA (Ed25519) realm keys, OKP JWKS (RFC 8037), discovery lists the realm's algorithms; `default_signing_algorithm` accepts `RS256`/`EdDSA` and chooses the type of newly generated keys; SAML refused in EdDSA realms. Re-cut for `v0.10.2`: upstream's offloaded signer becomes per-algorithm and its cached JWK is built for the key's type; the migration is `20261025000050` (upstream took `20261025000000`). | Not submitted. |
| 2 | `feat/confirmation-claim-v0.10.2` | Token-exchange request parameter `cnf_jkt` (RFC 7638 thumbprint) emits `cnf: {"jkt": …}`, gated by the new policy flag `allow_requested_cnf`; a `cnf`-bound subject token is exchanged only with the flag and a new `cnf_jkt`; mapper-produced `cnf`/`act` are dropped; thumbprint recorded in the security event. | Not submitted. |
| 3 | `feat/asserted-actor-v0.10.2` | Token-exchange request parameter `actor_assertion`: a name the requesting client vouches for, in place of an `actor_token`. Gated by the new policy flag `allow_asserted_actor` plus `allow_delegation`; exclusive with `actor_token`; 1-256 bytes without control or invisible characters. Emits `act: {sub, client_id, asserted: true}`, wrapping any recorded chain as an actor token does; recorded in the security event. Cherry-picks onto row 2 with trivial conflicts (policy fields, tests, locales). | Not submitted. |
| 4 | `feat/signing-key-rotation-v0.10.2` | Several signing keys per realm with a state (`next`, `active`, `retired`); tokens verify by the `kid` in their header with that key's own algorithm; the JWKS publishes active, next and unexpired retired keys; `POST /realms/{name}/keys/next` and `/keys/rotate` stage and promote keys (new keys follow `default_signing_algorithm`, so a realm moves from RS256 to EdDSA by rotating). Based on row 1 (`feat/eddsa-signing-v0.10.2`). | Not submitted. |
| 5 | `feat/realm-org-root-v0.10.2` | Nullable `realms.org_root_pubkey`: the organisation root's Ed25519 public key as 64 lowercase hex characters (public material), validated in the API and the repository and checked by the database; `PUT /realms/{name}/org-root` sets or replaces it (needs the right to update the realm); returned with the realm. Based on the patched line at row 4 (`19d1baf9`). Re-cut for `v0.10.2`: upstream's `InvalidatingRealmRepository` forwards the setter and announces the change. | Not submitted. |

| 6 | `feat/embeddable-builder-v0.10.2` | Host-owned embedding builder returns router, application service and controlled shutdown. Host supplies metrics and owns tracing, crypto and listeners; explicit schema-migration policy; standalone uses the same builder. Background workers and delivery children are cancelled and joined before pools close. Based on patched line `2508c406`; topic `0a0884a5`, integrated `240a9e65`. | Not submitted. |
| 7 | `feat/issuance-api-v0.10.2` | Trusted in-process sessionless access-token issuance reuses realm signing and target mappers; rechecks subject/client/realm eligibility, exact scope and lifetime limits. Typed confirmation and generic extra claims cannot override security claims or mapper output. Caller owns proof and authority checks. Based on row 6 topic `0a0884a5`; topic `127d4690`, integrated `bc83b76e`. | Not submitted. |

| 8 | `feat/embedded-service-account-v0.10.2` | Trusted atomic service-account provisioning, idempotent by realm/client id. Creates a secretless confidential client and linked user, optional existing scopes and immutable attributes in one transaction. Existing incompatible/disabled/locked accounts and removed permissions are refused, never repaired; concurrent creation yields one account. Based on row 7 topic `127d4690`; topic `660941c7`, integrated `48ec9de8`. | Not submitted. |

| 9 | `feat/host-api-exports-v0.10.2` | Re-export the existing AuthService trait and CoreError from ferriskey-api so embedded hosts can fetch realm keys and handle errors without a direct core dependency. No behavior changes. Based on row 8 topic `660941c7`; topic `2a511e1d`, integrated `4e3781da`. | Not submitted. |

The published patched line contains rows 6–9 at `4e3781da9f311b7352b735f7df82bdb8af6e7808`. These commits are included in release tag `aster-ferriskey-v0.10.2-2` and in the subsequent aster-idp development deployment. Validation: real PostgreSQL builder and issuance tests, lifecycle cancellation tests, and token-exchange regressions; the aster-idp Salvo integration proof is recorded in the internal embedding plan.

| 10 | `feat/passwordless-realms-v0.10.2` | Opt-in realm prohibition on local passwords, verified contact before human access, email-link signup without bootstrap credentials, cookie-bound recent authentication for passkey management, and required-action continuation for magic links/passkeys/social login. Email proof tokens bind the exact delivery address and consume atomically; portal requirements follow realm settings, browser contract documented, theme font stylesheet loaded. Based on row 9 integrated `4e3781da`; topic `fe8f6760`, integrated `b6b51c55`. | Not submitted. |

Row 10 is published on the patched branch at `b6b51c55af2f5e37a5e457474427775e0c108c03`, released as `aster-ferriskey-v0.10.2-3` after aster-idp passed 154 tests against this exact revision. Validation: core 1,142 passed (173 database tests ignored by the ordinary unit run); mail 22; portal 22; explicit PostgreSQL policy/concurrency 2, email continuation/address-binding 2, passwordless signup 1, root-path compatibility 2 and legacy registration 6. Frontend TypeScript build and changed-file formatting passed. Independent review findings were fixed before publication.

Migration is opt-in: drain login traffic, establish replacement access, explicitly remove obsolete password hashes/password-update actions, enable the policy, then restart/resume. Existing master access is unchanged. Old email links without delivery-address snapshots require resend; no migration invents verified contact or deletes passwords. See `docs/human-login-browser-contract.md` on the patched branch.

| 11 | `feat/optional-passkey-v0.10.2` | Optional passkey offer after verified email/social login, protected transaction-only skip, discoverable enrollment and account-bound named assertions, atomic one-use WebAuthn challenges with session/age checks, partial profile-update preservation, and template-derived email subjects. Based on row 10 integrated `b6b51c55`; topic `3726af25`, integrated `01aa97d1`. | Not submitted. |

Row 11 is published on the patched branch at `01aa97d11c24b67cc05db994a76e2433a6637e16`, released as `aster-ferriskey-v0.10.2-4` after exact-revision aster-idp validation: 154 passed, zero failed, two real-binary smoke tests ignored across 17 test binaries (exit 0). Validation: core 1,152 passed (174 ignored), mail 55, policy 31, explicit PostgreSQL concurrent challenge consumption 1, and API regressions 7 (optional offer/skip/replay, partial admin update, signup, email continuation/address binding, root-path compatibility). Independent review blockers were fixed and re-reviewed. No schema migration or configuration key is added; `POST /login-actions/skip` is the sole new route. The offer is computed after mandatory actions and never stored on the account; mandatory passkey actions cannot be skipped. Old non-discoverable credentials still work with named sign-in. Reimport existing MJML templates to recover titles that the former importer discarded. Live browser rerun remains pending, including the previously unexplained same-browser request-options refusal.

Planned patches are not listed here until they land.

## Development browser verification for release -3

The deployment agent verified returning-user magic-link login, new-person signup
with zero password credentials and verified contact, and SSO reuse in a real
browser. Mail travelled through Stalwart to test mailboxes read over IMAP, and
the authorization endpoint returned code, state and issuer to the relying party.
AgentMail accepted SMTP delivery but did not surface the messages in its inbox;
that provider path is not verified. Browser passkey enrollment/authentication and
the email-verification continuation screen remain unverified by the available
browser tools; their server paths have automated regression coverage. The new
human screens still need an optional passkey-enrollment entry point; enrollment
must not silently become mandatory for new users.
