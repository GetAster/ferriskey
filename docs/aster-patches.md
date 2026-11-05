# Aster patch ledger: ferriskey

This repository is Aster's fork of [ferriskey/ferriskey](https://github.com/ferriskey/ferriskey). Aster carries the patches listed below on top of upstream releases. Upstream maintainers are welcome to incorporate any of them, in whole or in part, at their discretion.

Aster runs FerrisKey as the engine of `aster-idp`, Aster's identity provider. The fork is a deployed server, not a published library, so its versions are container image tags rather than crate versions.

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

`aster-ferriskey-v0.10.2-1` on `upgrade/ferriskey-v0.10.2`, cut from the upstream tag `v0.10.2` (`15a1148a`). By owner decision (2026-11-05) this tag was created before `aster-idp` had tests to run against it; no image has been built from it yet.

| Tag | Commit | Image digest |
| --- | --- | --- |
| `aster-ferriskey-v0.10.2-1` | `2508c406` | Not built yet |

## Patches

| # | Topic branch | Summary | Upstream status |
| --- | --- | --- | --- |
| 1 | `feat/eddsa-signing-v0.10.2` | Per-key signing algorithm on the `jwt_keys` row (`kty`, `alg`); EdDSA (Ed25519) realm keys, OKP JWKS (RFC 8037), discovery lists the realm's algorithms; `default_signing_algorithm` accepts `RS256`/`EdDSA` and chooses the type of newly generated keys; SAML refused in EdDSA realms. Re-cut for `v0.10.2`: upstream's offloaded signer becomes per-algorithm and its cached JWK is built for the key's type; the migration is `20261025000050` (upstream took `20261025000000`). | Not submitted. |
| 2 | `feat/confirmation-claim-v0.10.2` | Token-exchange request parameter `cnf_jkt` (RFC 7638 thumbprint) emits `cnf: {"jkt": …}`, gated by the new policy flag `allow_requested_cnf`; a `cnf`-bound subject token is exchanged only with the flag and a new `cnf_jkt`; mapper-produced `cnf`/`act` are dropped; thumbprint recorded in the security event. | Not submitted. |
| 3 | `feat/asserted-actor-v0.10.2` | Token-exchange request parameter `actor_assertion`: a name the requesting client vouches for, in place of an `actor_token`. Gated by the new policy flag `allow_asserted_actor` plus `allow_delegation`; exclusive with `actor_token`; 1-256 bytes without control or invisible characters. Emits `act: {sub, client_id, asserted: true}`, wrapping any recorded chain as an actor token does; recorded in the security event. Cherry-picks onto row 2 with trivial conflicts (policy fields, tests, locales). | Not submitted. |
| 4 | `feat/signing-key-rotation-v0.10.2` | Several signing keys per realm with a state (`next`, `active`, `retired`); tokens verify by the `kid` in their header with that key's own algorithm; the JWKS publishes active, next and unexpired retired keys; `POST /realms/{name}/keys/next` and `/keys/rotate` stage and promote keys (new keys follow `default_signing_algorithm`, so a realm moves from RS256 to EdDSA by rotating). Based on row 1 (`feat/eddsa-signing-v0.10.2`). | Not submitted. |
| 5 | `feat/realm-org-root-v0.10.2` | Nullable `realms.org_root_pubkey`: the organisation root's Ed25519 public key as 64 lowercase hex characters (public material), validated in the API and the repository and checked by the database; `PUT /realms/{name}/org-root` sets or replaces it (needs the right to update the realm); returned with the realm. Based on the patched line at row 4 (`19d1baf9`). Re-cut for `v0.10.2`: upstream's `InvalidatingRealmRepository` forwards the setter and announces the change. | Not submitted. |

Planned patches are not listed here until they land.
