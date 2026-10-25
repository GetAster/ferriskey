# Aster patch ledger: ferriskey

This repository is Aster's fork of [ferriskey/ferriskey](https://github.com/ferriskey/ferriskey). Aster carries the patches listed below on top of upstream releases. Upstream maintainers are welcome to incorporate any of them, in whole or in part, at their discretion.

Aster runs FerrisKey as the engine of `aster-idp`, Aster's identity provider. The fork is a deployed server, not a published library, so its versions are container image tags rather than crate versions.

## Branch and tag model

- `main` is upstream `main` plus one commit: the Aster README preamble and this ledger. Nothing is built from `main`. It is refreshed with `git merge upstream/main` and is never reset or force-pushed. Ledger edits are commits on `main`, never on `upgrade/*`.
- The current patched line is `upgrade/ferriskey-main-9a7d5d8c`: upstream `main` at the pinned commit `9a7d5d8c`, plus the patches in this ledger. By owner decision (2026-10-25) it is based on upstream `main` rather than a release tag, because the changes this fork needs (sealed realm keys, signing-key cache, aws-lc-rs signing) have landed after `v0.9.0`. It moves to the next upstream release tag as soon as one ships, and from then on follows release tags only: `upgrade/ferriskey-v<upstream version>` is cut from the tag and the patches are cherry-picked onto it. Never track upstream `main` beyond the pinned commit. Aster-only fixes append to the current branch. Published `upgrade/*` branches and tags are never rewritten.
- `upgrade/ferriskey-v0.9.0` was published on Forge before that decision. It is superseded, left unchanged and carries no patches.
- Topic branches carry one change each, are named for the change (for example `feat/eddsa-signing`), are based on the upstream commit the upgrade branch is cut from (a release tag, or the pinned `main` commit for the current line), or on a prerequisite patch's commit, which its row names), and are cherry-picked with `git cherry-pick -x` onto the upgrade branch, so every upgrade-branch commit names its source. Re-cutting a topic onto a new upstream release takes a versioned name, `<topic>-v<upstream version>`.
- Tags: `aster-ferriskey-v<upstream version>-<n>`, where `n` counts Aster builds on that upstream release (`aster-ferriskey-v0.9.0-1`, `-2`, …); on the pinned-`main` line the upstream part is `main-9a7d5d8c` (`aster-ferriskey-main-9a7d5d8c-1`, …). The container image built from a tag carries the same tag, and `aster-idp` pins the image by digest. A tag is created only after `aster-idp`'s tests pass against that exact commit, because tags cannot be moved.
- Forge (`forge.emrul.dev/Aster/ferriskey`) is canonical and push-mirrors to `github.com/getaster/ferriskey`. Never push to GitHub or upstream directly.
- Aster does not submit patches upstream; upstream maintainers are welcome to take any patch here.

## Current release

None yet. The current line is `upgrade/ferriskey-main-9a7d5d8c`, cut from upstream `main` at `9a7d5d8c`.

| Tag | Commit | Image digest |
| --- | --- | --- |

## Patches

| # | Topic branch | Summary | Upstream status |
| --- | --- | --- | --- |
| 1 | `feat/eddsa-signing-main` | Per-key signing algorithm on the `jwt_keys` row (`kty`, `alg`); EdDSA (Ed25519) realm keys, OKP JWKS (RFC 8037), discovery lists the realm's algorithms; `default_signing_algorithm` accepts `RS256`/`EdDSA` and chooses the type of newly generated keys; SAML refused in EdDSA realms. | Not submitted; `fa9901dc` (aws-lc-rs signing) is already in the base. |
| 2 | `feat/confirmation-claim` | Token-exchange request parameter `cnf_jkt` (RFC 7638 thumbprint) emits `cnf: {"jkt": …}`, gated by the new policy flag `allow_requested_cnf`; a `cnf`-bound subject token is exchanged only with the flag and a new `cnf_jkt`; mapper-produced `cnf`/`act` are dropped; thumbprint recorded in the security event. | Not submitted. |

Planned patches are described in Aster's `aster-idp` design (`_internal/docs/agentIdentity/`), not here, until they land.
