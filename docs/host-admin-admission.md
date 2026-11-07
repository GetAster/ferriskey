# Host admission for administrative APIs

FerrisKey's embedded host can impose an additional restriction on administrative
API callers without changing the realm permission model. Standalone FerrisKey
and hosts that leave `HostOptions.admin_admission` as `None` retain their existing
behavior, including legitimate nonmaster administrators.

`ferriskey_api::AdminAdmission` is an
`Arc<dyn Fn(&Identity) -> bool + Send + Sync>`. The predicate receives the identity
returned by ordinary bearer-token verification and management-client admission.
It runs once before the administrative handler. Returning `true` only lets the
handler perform its existing permission checks; it does not grant permissions.
Returning `false` produces HTTP 403 with `reason: admin_admission_denied` in the
normal structured API error body. Invalid tokens are rejected before this hook.

Keep this synchronous predicate free of request I/O. For a host that admits only
its master realm, resolve the realm's ID once and compare it with
`identity.realm_id()`. Compare the caller's verified realm, not the realm being
managed: a master administrator may legitimately manage another realm.

```rust,no_run
use std::sync::{Arc, OnceLock};
use ferriskey_api::{build, HostOptions, RealmId};
# async fn example(args: Arc<ferriskey_api::args::Args>) -> Result<(), anyhow::Error> {
let master = Arc::new(OnceLock::<RealmId>::new());
let admitted_realm = master.clone();
let app = build(args, HostOptions {
    admin_admission: Some(Arc::new(move |identity| {
        admitted_realm.get().is_some_and(|id| *id == identity.realm_id())
    })),
    ..HostOptions::default()
}).await?;
let master_id = match app.service.resolve_realm_id("master").await {
    Ok(id) => id,
    Err(error) => {
        app.shutdown.shutdown().await;
        return Err(error.into());
    }
};
master.set(master_id).expect("configured once before serving");
// Only now mount app.router and start serving. Retain app.shutdown as usual.
# Ok(())
# }
```

The unset predicate fails closed. If resolving the realm fails, do not start
serving; shut down the application resources before returning the startup error.
`resolve_realm_id` is a trusted embedding API over the existing realm repository,
not a new HTTP endpoint or a token-name parser. Existing exhaustive `HostOptions`
struct literals must add `admin_admission: None` or `..HostOptions::default()`.

## Route ownership

Administrative routes opt into `auth_admin` at their existing authentication
boundary. This is not a URL classifier maintained by the host. The hook covers
realm administration, user administration, clients, roles, organizations,
webhooks, maintenance, email templates, portal themes/layouts, client scopes,
identity providers/federation/link administration, security events, flow
observability, and AuthZEN policy/schema/template management.

The following keep their original authentication and authorization:

- Public OAuth/OIDC/SAML/broker, device, discovery and login-action routes.
- Account `/users/me/*` and locale self-service.
- Caller realm introspection `/users/@me/realms` and `/settings` beneath it.
- Reading one's own `/users/{user_id}/permissions`. Reading another user's
  permissions invokes the host gate inside the handler after ordinary `auth`;
  both cases still run the original realm and permission checks.
- Trident bearer-authenticated passkey/recovery self-service operations.
- AuthZEN evaluation/batch endpoints (resource APIs, not policy management).
- Public theme/layout/password-policy/login settings and client registration.

`GET /users/{user_id}` is administrative even when the IDs happen to match: its
existing policy requires user-view permission. Self-profile access uses
`/users/me`. Identity-provider link administration likewise already requires
user-management permission; it is not the public broker login flow.

This hook governs administrative API access only. The host still owns static
console delivery and its sign-in experience. It neither changes OAuth grants
nor prevents serving the console HTML to an unauthenticated browser.

## Validation

`api/tests/admin_admission_test.rs` exercises real composed routers and signed
tokens using the existing isolated PostgreSQL test harness. Run with
`cargo test -p ferriskey-api --test admin_admission_test -- --ignored`.
