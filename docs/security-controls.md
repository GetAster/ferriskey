# Production documentation routes and dependency checks

## Public documentation switch

Set `SERVER_API_DOCS_ENABLED=false` (CLI `--server-api-docs-enabled=false`).
Embedded hosts can set `args.server.api_docs_enabled = false` before calling
`build`. The default is `true` for upstream compatibility; the embedding host
must choose its production setting explicitly.

Disabled routes, relative to `SERVER_ROOT_PATH`:

- `/api-docs/openapi.json`
- `/swagger-ui` and its assets
- `/scalar`
- `/redoc`
- `/rapidoc`

The routes are not registered and return 404 in the fork router. A host fallback
may supply its own response for unregistered routes. OAuth/OIDC discovery and
JWKS remain available. This is a surface-reduction setting, not an authorization
boundary. The offline OpenAPI export command remains available.

## Forgejo checks

`.forgejo/workflows/security.yml` runs `cargo deny --locked check` on every push
and manual dispatch. On Mondays at 06:17 UTC it checks both `main` and
`upgrade/ferriskey-v0.10.2`, because the deployed host follows the latter while
Forgejo discovers schedules on the default branch. Keep that branch list aligned
with maintained production branches. The workflow must exist on `main` and each
branch whose pushes should be checked; Actions must be enabled on the repository.

It uses the existing Aster Linux runner and pinned CI image/checkout action from
sibling repositories. Cargo-deny 0.19.0 is pinned; the advisory database is fetched
on every run. Advisory, license, source and dependency-ban failures fail the job.
There is no automatic dependency update or deployment. Dependabot configuration
under `.github` does not provide dependency monitoring in Forgejo.

The gate uses Cargo's resolved graph, including development dependencies and all
workspace features per `deny.toml`. `cargo audit` additionally examines inactive
optional packages retained in `Cargo.lock`; a lockfile finding alone does not
prove a package reaches the executable. Do not add blanket RSA/rkyv ignores.

## Review of release 11 dependencies (2026-11-08)

Reviewed with RustSec database commit
`309392b18f6b17022f82c701f300433126901068` and these commands:

```sh
cargo tree --locked -p ferriskey-api --target x86_64-unknown-linux-gnu --edges normal,build -i PACKAGE
cargo tree --locked --workspace --all-features --target all --edges normal,build,dev -i PACKAGE
cargo audit --json
cargo deny --locked check
```

| Package | Reachability and disposition |
| --- | --- |
| `rsa 0.9.10` (Marvin) | Lockfile-only through disabled `sqlx-mysql`; absent from the active workspace graph and production API graph. |
| `rkyv 0.7.46` | Lockfile-only through disabled `rust_decimal/rkyv`; absent from the active graph. |
| `crypto-bigint 0.5.5` | Only test keys through core's `p256 0.13`; absent from the production/build graph. Existing exception retained with corrected explanation. Test migration to P-256 0.14 remains deferred. |
| `zip 3.0.0` | Build-only through Swagger UI 9.0.2; never a runtime archive parser in the API. See the bounded exception below. |
| `pin-utils 0.1.0` | Newly reported unmaintained; removed by updating Hyper to 1.12.0 and its `want` dependency to 0.3.2. |

These statements describe the reviewed feature graph, not every possible future
host configuration. A host needs its own lockfile check: dependencies introduced
by the embedding binary are not covered by the fork workspace scan.

### ZIP build exception

Swagger UI now uses its existing `vendored` feature. Cargo.lock verifies the
`utoipa-swagger-ui-vendored 0.1.2` crate checksum instead of the previous default
unchecked network download. Its Swagger 5.17.14 ZIP SHA256 is
`481244d0812097b11fbaeef79f71d942b171617f9c9f9514e63acbe13e71ccdc`.
All 1,097 archive entries were inspected: no privileged permission bits or symlinks.

Swagger's custom `extract_dist` does not call `ZipArchive::extract` or create
symlinks, so the functions described by RUSTSEC-2026-0368, 0369 and 0429 are unused.
It does copy Unix permission bits, which is why the known vendored input matters
for 0367. Do not override `SWAGGER_UI_DOWNLOAD_URL` in release builds. Re-review
these exceptions when changing the Swagger version or archive. A future move to
Swagger UI 10 / Utoipa 6 can remove ZIP 3; that API migration is outside this patch.

References: [Marvin](https://rustsec.org/advisories/RUSTSEC-2023-0071.html),
[crypto-bigint](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
[rkyv](https://rustsec.org/advisories/RUSTSEC-2026-0235.html),
[ZIP extraction](https://rustsec.org/advisories/RUSTSEC-2026-0429.html),
[pin-utils](https://rustsec.org/advisories/RUSTSEC-2026-0441.html).

Surface changes: one boolean configuration field and CLI/environment option;
no new endpoint, database migration, service or credential. One Forgejo workflow.
