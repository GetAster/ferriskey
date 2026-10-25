# Aster patch ledger: ferriskey

This repository is Aster's fork of [ferriskey/ferriskey](https://github.com/ferriskey/ferriskey). Aster carries the patches listed below on top of upstream releases. Upstream maintainers are welcome to incorporate any of them, in whole or in part, at their discretion.

Aster runs FerrisKey as the engine of `aster-idp`, Aster's identity provider. The fork is a deployed server, not a published library, so its versions are container image tags rather than crate versions.

## Branch and tag model

- `main` is upstream `main` plus one commit: the Aster README preamble and this ledger. Nothing is built from `main`. It is refreshed with `git merge upstream/main` and is never reset or force-pushed. Ledger edits are commits on `main`, never on `upgrade/*`.
- `upgrade/ferriskey-v<upstream version>` (for example `upgrade/ferriskey-v0.9.0`) is the patched integration line: an upstream release tag plus the patches in this ledger. A new upstream release always gets a new branch, cut from its tag; Aster-only fixes append to the current branch. Upstream `main` moves quickly before 1.0, so upgrade branches follow release tags only, never upstream `main`. Published `upgrade/*` branches and tags are never rewritten.
- Topic branches carry one change each, are named for the change (for example `feat/eddsa-signing`), are based on the upstream release tag (or on a prerequisite patch's commit, which its row names), and are cherry-picked with `git cherry-pick -x` onto the upgrade branch, so every upgrade-branch commit names its source. Re-cutting a topic onto a new upstream release takes a versioned name, `<topic>-v<upstream version>`.
- Tags: `aster-ferriskey-v<upstream version>-<n>`, where `n` counts Aster builds on that upstream release (`aster-ferriskey-v0.9.0-1`, `-2`, …). The container image built from a tag carries the same tag, and `aster-idp` pins the image by digest. A tag is created only after `aster-idp`'s tests pass against that exact commit, because tags cannot be moved.
- Forge (`forge.emrul.dev/Aster/ferriskey`) is canonical and push-mirrors to `github.com/getaster/ferriskey`. Never push to GitHub or upstream directly.
- Aster does not submit patches upstream; upstream maintainers are welcome to take any patch here.

## Current release

None yet. The first upgrade branch is `upgrade/ferriskey-v0.9.0`, cut from upstream `v0.9.0` (commit `93ffe7c9`).

| Tag | Commit | Image digest |
| --- | --- | --- |

## Patches

| # | Topic branch | Summary | Upstream status |
| --- | --- | --- | --- |

Planned patches are described in Aster's `aster-idp` design (`_internal/docs/agentIdentity/`), not here, until they land.
