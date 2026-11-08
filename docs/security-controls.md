# Production documentation routes and dependency checks

## No public API documentation routes

The patched fork does not serve OpenAPI JSON, Swagger UI, Scalar, Redoc or
RapiDoc. Their routes and viewer dependencies have been removed. The temporary
`SERVER_API_DOCS_ENABLED` / `args.server.api_docs_enabled` switch from release 12
is removed too: there is no runtime documentation surface to enable. Embedded
hosts must remove assignments to that field; remove the obsolete environment
variable or CLI option from deployment configuration.

OAuth/OIDC discovery and JWKS remain available. Developers can export the OpenAPI
schema offline with `ferriskey-api gen-api --output openapi.json`; the `utoipa`
schema definitions remain for this purpose. A host fallback may still handle
unknown paths, but the fork router does not register any documentation routes.

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
| `zip 3.0.0` | Build-only through Swagger UI 9.0.2; never a runtime archive parser in the API. Removed with the documentation viewers; see below. |
| `pin-utils 0.1.0` | Newly reported unmaintained; removed by updating Hyper to 1.12.0 and its `want` dependency to 0.3.2. |

These statements describe the reviewed feature graph, not every possible future
host configuration. A host needs its own lockfile check: dependencies introduced
by the embedding binary are not covered by the fork workspace scan.

### ZIP dependency removed

The earlier vendored-archive mitigation is superseded: removing all four viewer
libraries removes `utoipa-swagger-ui`, its vendored assets, and `zip` from the
patched workspace's lockfile and active dependency graph. The ZIP advisory
exceptions have been removed from `deny.toml`. The table above describes release
11 findings, not dependencies retained in this candidate.

An embedding host must regenerate its own lockfile after changing the fork pin;
Git dependencies do not inherit the fork lockfile. Other host dependencies may
independently use ZIP and need their own review.

Surface changes: removed all five public API documentation routes, four viewer
libraries, and the temporary documentation configuration switch. No endpoint,
database migration, service or credential added by this removal.
