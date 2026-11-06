mod common;

use common::{ClientSpec, app, rt};
use ferriskey_api::{EnsureServiceAccountError, EnsureServiceAccountInput};
use std::collections::BTreeMap;
use uuid::Uuid;

fn request(realm: &str) -> EnsureServiceAccountInput {
    EnsureServiceAccountInput {
        realm_name: realm.into(),
        client_id: format!("agent-{}", Uuid::new_v4().simple()),
        name: "Agent".into(),
        allowed_scopes: vec![],
        attributes: BTreeMap::from([("owner".into(), "immutable-owner".into())]),
    }
}

#[test]
fn provisioning_is_atomic_idempotent_and_respects_admin_changes() {
    rt().block_on(async {
        let app = app();
        let scope = format!("agent-scope-{}", Uuid::new_v4().simple());
        app.ensure_client_scope(&scope).await;
        let mut input = request(&app.realm);
        input.allowed_scopes = vec![scope.clone(), scope.clone()];
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let service = app.service.clone(); let input = input.clone();
            calls.spawn(async move { service.ensure_service_account(input).await.unwrap() });
        }
        let mut outputs = Vec::new();
        while let Some(result) = calls.join_next().await { outputs.push(result.unwrap()); }
        assert_eq!(outputs.iter().filter(|result| result.created).count(), 1);
        let account = &outputs[0];
        assert!(outputs.iter().all(|result| result.client_uuid == account.client_uuid && result.subject_id == account.subject_id && result.enabled));
        let (clients,): (i64,) = sqlx::query_as("SELECT count(*) FROM clients WHERE realm_id = $1 AND client_id = $2").bind(app.realm_id).bind(&input.client_id).fetch_one(&app.pool).await.unwrap();
        let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE client_id = $1").bind(account.client_uuid).fetch_one(&app.pool).await.unwrap();
        let (mappings,): (i64,) = sqlx::query_as("SELECT count(*) FROM client_scope_mappings WHERE client_id = $1 AND default_scope_type = 'OPTIONAL'").bind(account.client_uuid).fetch_one(&app.pool).await.unwrap();
        assert_eq!((clients, users, mappings), (1, 1, 1));
        let (secret, direct, device, exchange): (Option<String>, Option<bool>, Option<bool>, bool) = sqlx::query_as("SELECT secret, direct_access_grants_enabled, oauth_device_code_grant_enabled, token_exchange_enabled FROM clients WHERE id = $1").bind(account.client_uuid).fetch_one(&app.pool).await.unwrap();
        assert!(secret.is_none()); assert_eq!((direct, device, exchange), (Some(false), Some(false), false));
        let issued = app.service.issue_subject_access_token(ferriskey_api::IssueAccessTokenInput {
            base_url: "http://localhost:5555".into(), realm_name: app.realm.clone(), subject_id: account.subject_id, client_id: account.client_id.clone(), audience: account.client_id.clone(), scope: scope.clone(), confirmation: None, additional_claims: Default::default(), lifetime_seconds: 60,
        }).await.unwrap();
        assert_eq!(issued.scope, scope);
        assert_eq!(common::decode_unverified(&issued.access_token)["scope"], scope);
        let denied = app.server().post(&app.oidc("token")).form(&[("grant_type", "client_credentials"), ("client_id", account.client_id.as_str())]).await;
        assert_ne!(denied.status_code(), 200, "secretless account must not authenticate through native grants");
        let mut renamed = input.clone(); renamed.name = "Ignored rename".into();
        assert!(!app.service.ensure_service_account(renamed).await.unwrap().created);
        let (name,): (String,) = sqlx::query_as("SELECT name FROM clients WHERE id = $1").bind(account.client_uuid).fetch_one(&app.pool).await.unwrap(); assert_eq!(name, "Agent");
        let mut different = input.clone(); different.attributes.insert("owner".into(), "different-owner".into());
        assert!(matches!(app.service.ensure_service_account(different).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        let mut missing_attr = input.clone(); missing_attr.attributes.insert("new-pin".into(), "value".into());
        assert!(matches!(app.service.ensure_service_account(missing_attr).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        let (owner,): (String,) = sqlx::query_as("SELECT value FROM user_attributes WHERE user_id = $1 AND key = 'owner'").bind(account.subject_id).fetch_one(&app.pool).await.unwrap(); assert_eq!(owner, "immutable-owner");
        sqlx::query("UPDATE clients SET secret = 'admin-secret' WHERE id = $1").bind(account.client_uuid).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(input.clone()).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        let (still_secret,): (Option<String>,) = sqlx::query_as("SELECT secret FROM clients WHERE id = $1").bind(account.client_uuid).fetch_one(&app.pool).await.unwrap(); assert_eq!(still_secret.as_deref(), Some("admin-secret"));
        sqlx::query("UPDATE clients SET secret = NULL WHERE id = $1").bind(account.client_uuid).execute(&app.pool).await.unwrap();
        // Explicitly disabled and removed scope grants must stay disabled/removed.
        sqlx::query("UPDATE client_scope_mappings SET default_scope_type = 'NONE' WHERE client_id = $1").bind(account.client_uuid).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(input.clone()).await, Err(EnsureServiceAccountError::MissingScopes { .. })));
        sqlx::query("DELETE FROM client_scope_mappings WHERE client_id = $1").bind(account.client_uuid).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(input.clone()).await, Err(EnsureServiceAccountError::MissingScopes { .. })));
        let mut without_scopes = input.clone(); without_scopes.allowed_scopes.clear();
        assert!(app.service.ensure_service_account(without_scopes.clone()).await.is_ok());
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1").bind(account.subject_id).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(without_scopes.clone()).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        sqlx::query("UPDATE users SET enabled = true, locked_until = now() + interval '5 minutes' WHERE id = $1").bind(account.subject_id).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(without_scopes.clone()).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        sqlx::query("DELETE FROM users WHERE id = $1").bind(account.subject_id).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(without_scopes).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        // Undefined scopes fail before any client or subject can be persisted.
        let mut unknown_scope = request(&app.realm); unknown_scope.allowed_scopes.push("undefined-scope".into());
        assert!(matches!(app.service.ensure_service_account(unknown_scope.clone()).await, Err(EnsureServiceAccountError::InvalidInput(_))));
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM clients WHERE client_id = $1").bind(unknown_scope.client_id).fetch_one(&app.pool).await.unwrap(); assert_eq!(count, 0);
        let mut unknown_realm = request("unknown-realm"); unknown_realm.allowed_scopes.clear();
        assert!(matches!(app.service.ensure_service_account(unknown_realm).await, Err(EnsureServiceAccountError::UnknownRealm)));
        let occupied = request(&app.realm);
        sqlx::query("INSERT INTO users (id,realm_id,username,firstname,lastname,email,email_verified,enabled,created_at,updated_at) VALUES ($1,$2,$3,NULL,NULL,NULL,false,true,now(),now())").bind(Uuid::new_v4()).bind(app.realm_id).bind(format!("service-account-{}", occupied.client_id)).execute(&app.pool).await.unwrap();
        assert!(matches!(app.service.ensure_service_account(occupied.clone()).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))));
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM clients WHERE client_id = $1").bind(occupied.client_id).fetch_one(&app.pool).await.unwrap(); assert_eq!(count, 0);
        // Existing client configurations cannot be silently repurposed.
        for kind in ["disabled", "public", "no-account", "saml", "wrong-type"] {
            let existing = app.client(ClientSpec::confidential().with_service_account()).await;
            let query = match kind {
                "disabled" => "UPDATE clients SET enabled = false WHERE id = $1",
                "public" => "UPDATE clients SET public_client = true WHERE id = $1",
                "no-account" => "UPDATE clients SET service_account_enabled = false WHERE id = $1",
                "saml" => "UPDATE clients SET protocol = 'saml' WHERE id = $1",
                _ => "UPDATE clients SET client_type = 'public' WHERE id = $1",
            };
            sqlx::query("UPDATE clients SET secret = NULL WHERE id = $1").bind(existing.id).execute(&app.pool).await.unwrap();
            sqlx::query(query).bind(existing.id).execute(&app.pool).await.unwrap();
            let mut incompatible = request(&app.realm); incompatible.client_id = existing.client_id;
            assert!(matches!(app.service.ensure_service_account(incompatible).await, Err(EnsureServiceAccountError::IncompatibleExisting(_))), "{kind}");
        }
        // The same deterministic identifier is distinct in another realm.
        let (other, other_id) = app.create_realm().await;
        let mut cross_realm = input; cross_realm.realm_name = other; cross_realm.allowed_scopes.clear();
        let other_account = app.service.ensure_service_account(cross_realm).await.unwrap();
        assert_ne!(other_account.client_uuid, account.client_uuid); assert_ne!(other_account.subject_id, account.subject_id);
        let (realm_id,): (Uuid,) = sqlx::query_as("SELECT realm_id FROM users WHERE id = $1").bind(other_account.subject_id).fetch_one(&app.pool).await.unwrap(); assert_eq!(realm_id, other_id);
    });
}
