//! PostgreSQL integration coverage for host admission on the actual API routers.
//! Run explicitly with --ignored; the common harness uses an isolated schema.
mod common;

use axum_test::TestServer;
use common::{ClientSpec, app, password_grant, rt};
use ferriskey_api::{
    AdminAdmission, HostOptions,
    application::http::server::{app_state::AppState, http_server::router_with_metrics},
    args::Args,
};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn server_with(policy: Option<AdminAdmission>) -> TestServer {
    let mut args = Args::default();
    args.authz_enabled = true;
    let mut state = AppState::new(Arc::new(args), app().service.clone());
    state.admin_admission = policy;
    TestServer::new(router_with_metrics(state, None).expect("build router")).unwrap()
}

#[test]
fn host_options_default_preserves_normal_admission() {
    assert!(HostOptions::default().admin_admission.is_none());
}

#[test]
#[ignore = "requires PostgreSQL"]
fn administrative_routes_run_host_gate_after_verification() {
    let app = app();
    rt().block_on(async {
        let baseline = app.server();
        let token = app.admin_token(&baseline).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let realm_id = app.service.resolve_realm_id(&app.realm).await.unwrap();
        assert_eq!(realm_id, app.realm_id);
        assert!(app.service.resolve_realm_id("missing-realm").await.is_err());
        let server = server_with(Some(Arc::new(move |identity| {
            assert_eq!(identity.realm_id(), realm_id);
            seen.fetch_add(1, Ordering::SeqCst);
            false
        })));
        for suffix in [
            "",
            "/users",
            "/clients",
            "/roles",
            "/webhooks",
            "/organizations",
            "/portal/themes",
            "/portal-layouts",
            "/client-scopes",
            "/email-templates",
            "/settings/maintenance/whitelist",
            "/compass/v1/flows",
            "/seawatch/v1/security-events",
            "/authz/state",
            "/identity-providers",
            "/federation/providers",
        ] {
            let response = server
                .get(&app.path(suffix))
                .authorization_bearer(&token)
                .await;
            assert_eq!(response.status_code(), 403, "{suffix}: {}", response.text());
            assert_eq!(
                response.json::<Value>()["reason"],
                "admin_admission_denied",
                "{suffix}"
            );
        }
        let before = calls.load(Ordering::SeqCst);
        server
            .get(&app.path("/users"))
            .await
            .assert_status_unauthorized();
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, replacement);
        server
            .get(&app.path("/users"))
            .authorization_bearer(parts.join("."))
            .await
            .assert_status_unauthorized();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "invalid tokens never reach host policy"
        );
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn public_account_and_own_permissions_are_not_administrative() {
    let app = app();
    rt().block_on(async {
        let baseline = app.server();
        let token = app.admin_token(&baseline).await;
        let own = common::decode_unverified(&token)["sub"]
            .as_str()
            .unwrap()
            .to_string();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let server = server_with(Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            false
        })));
        for suffix in [
            "/users/me",
            "/users/@me/realms",
            "/users/@me/realms/settings",
            &format!("/users/{own}/permissions"),
        ] {
            let response = server
                .get(&app.path(suffix))
                .authorization_bearer(&token)
                .await;
            assert_eq!(response.status_code(), 200, "{suffix}: {}", response.text());
        }
        server
            .get(&app.oidc("userinfo"))
            .authorization_bearer(&token)
            .await
            .assert_status_ok();
        server
            .get(&app.path("/.well-known/openid-configuration"))
            .await
            .assert_status_ok();
        server
            .get(&app.path("/login-settings"))
            .await
            .assert_status_ok();
        // No bearer login action / device SSO is deliberately denied by its own
        // authentication, not the host's administrative gate.
        server
            .post(&app.path("/login-actions/continue"))
            .await
            .assert_status_unauthorized();
        server
            .get(&app.path("/device/preview"))
            .add_query_param("user_code", "ABCD-EFGH")
            .await
            .assert_status_unauthorized();
        server
            .post(&app.path("/login-actions/generate-recovery-codes"))
            .authorization_bearer(&token)
            .await;
        server
            .post(&app.path("/authzen/access/v1/evaluation"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({}))
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let other = uuid::Uuid::new_v4();
        let response = server
            .get(&app.path(&format!("/users/{other}/permissions")))
            .authorization_bearer(&token)
            .await;
        assert_eq!(response.status_code(), 403);
        assert_eq!(response.json::<Value>()["reason"], "admin_admission_denied");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn allowing_host_never_replaces_existing_handler_or_client_permissions() {
    let app = app();
    rt().block_on(async {
        let baseline = app.server();
        let user = app.user(&baseline, "Str0ng!P@ssword#2024").await;
        let client = app.client(ClientSpec::public().with_direct_access()).await;
        let granted = password_grant(
            &baseline,
            app,
            &client.client_id,
            None,
            &user.username,
            "Str0ng!P@ssword#2024",
        )
        .await;
        granted.assert_status_ok();
        let token = granted.json::<Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let server = server_with(Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            true
        })));
        let response = server
            .get(&app.path("/users"))
            .authorization_bearer(&token)
            .await;
        assert_eq!(
            response.status_code(),
            403,
            "ordinary user remains unauthorized: {}",
            response.text()
        );
        assert_ne!(response.json::<Value>()["reason"], "admin_admission_denied");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        sqlx::query("UPDATE clients SET registration_source = 'dynamic' WHERE id = $1")
            .bind(client.id)
            .execute(&app.pool)
            .await
            .unwrap();
        server
            .get(&app.path("/users"))
            .authorization_bearer(&token)
            .await
            .assert_status_unauthorized();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "management client admission precedes host policy"
        );
        let admin = app.admin_token(&baseline).await;
        server_with(None)
            .get(&app.path("/users"))
            .authorization_bearer(&admin)
            .await
            .assert_status_ok();
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn host_can_admit_master_issuer_while_it_manages_a_different_realm() {
    use ferriskey_core::domain::common::{entities::StartupConfig, ports::CoreService};
    let app = app();
    rt().block_on(async {
        app.service
            .initialize_application(StartupConfig {
                master_realm_name: "master".into(),
                admin_username: "admin".into(),
                admin_password: "admin".into(),
                admin_email: "admin@master.test".into(),
                default_client_id: "security-admin-console".into(),
                webapp_url: "http://localhost:5555".into(),
            })
            .await
            .unwrap();
        let master_id = app.service.resolve_realm_id("master").await.unwrap();
        let baseline = app.server();
        let response = baseline
            .post("/realms/master/protocol/openid-connect/token")
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", "admin"),
                ("password", "admin"),
            ])
            .await;
        response.assert_status_ok();
        let master_token = response.json::<Value>()["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        // Create through the real API so master gains the target's ordinary
        // mirror-client role. Host admission must not manufacture that role.
        let target = format!("target-{}", uuid::Uuid::new_v4().simple());
        baseline
            .post("/realms")
            .authorization_bearer(&master_token)
            .json(&serde_json::json!({ "name": target }))
            .await
            .assert_status(axum::http::StatusCode::CREATED);
        let server = server_with(Some(Arc::new(move |identity| {
            identity.realm_id() == master_id
        })));
        server
            .get(&format!("/realms/{target}/users"))
            .authorization_bearer(&master_token)
            .await
            .assert_status_ok();
        let other_token = app.admin_token(&baseline).await;
        let refused = server
            .get(&format!("/realms/{target}/users"))
            .authorization_bearer(&other_token)
            .await;
        assert_eq!(refused.json::<Value>()["reason"], "admin_admission_denied");
    });
}
