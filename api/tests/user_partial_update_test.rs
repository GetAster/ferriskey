mod common;

use common::{app, rt};
use ferriskey_core::domain::common::{entities::StartupConfig, ports::CoreService};
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
#[ignore = "requires PostgreSQL"]
fn admin_required_action_update_preserves_verified_contact_and_disabled_state() {
    let app = app();
    rt().block_on(async {
        let server = app.server();
        // The shared fixture uses a unique realm name; cross-realm administration
        // deliberately requires the actual master realm.
        app.service.initialize_application(StartupConfig {
            webapp_url: "http://localhost:5555".into(),
            master_realm_name: "master".into(),
            admin_username: "admin".into(),
            admin_password: "admin".into(),
            admin_email: "admin@test.local".into(),
            default_client_id: "ferriskey-admin".into(),
        }).await.unwrap();
        let login = server.post("/realms/master/protocol/openid-connect/token")
            .form(&json!({"grant_type":"password", "client_id":"admin-cli", "username":"admin", "password":"admin"})).await;
        assert_eq!(login.status_code(), 200, "{}", login.text());
        let token = login.json::<Value>()["access_token"].as_str().unwrap().to_owned();
        let realm = format!("partial-update-{}", Uuid::new_v4().simple());
        let created_realm = server.post("/realms").authorization_bearer(&token)
            .json(&json!({"name":realm})).await;
        assert_eq!(created_realm.status_code(), 201, "{}", created_realm.text());
        sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, passkey_enabled=true WHERE realm_id=(SELECT id FROM realms WHERE name=$1)")
            .bind(&realm).execute(&app.pool).await.unwrap();
        let created = server.post(&format!("/realms/{realm}/users"))
            .authorization_bearer(&token)
            .json(&json!({"username":"alice", "firstname":"Alice", "lastname":"Example", "email":"alice@example.com", "email_verified":true}))
            .await;
        assert_eq!(created.status_code(), 200, "{}", created.text());
        let id = created.json::<Value>()["data"]["id"].as_str().unwrap().to_owned();
        let id_uuid = Uuid::parse_str(&id).unwrap();
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(id_uuid).execute(&app.pool).await.unwrap();
        let path = format!("/realms/{realm}/users/{id}");
        let update = server.put(&path).authorization_bearer(&token)
            .json(&json!({"required_actions":["configure_passkey"]})).await;
        assert_eq!(update.status_code(), 200, "{}", update.text());
        let stored: (Option<String>, Option<String>, Option<String>, bool, bool) = sqlx::query_as(
            "SELECT firstname, lastname, email, email_verified, enabled FROM users WHERE id=$1")
            .bind(id_uuid).fetch_one(&app.pool).await.unwrap();
        assert_eq!(stored, (Some("Alice".into()), Some("Example".into()), Some("alice@example.com".into()), true, false));
        let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM user_required_actions WHERE user_id=$1")
            .bind(id_uuid).fetch_all(&app.pool).await.unwrap();
        assert_eq!(actions, vec!["configure_passkey"]);

        // An explicit contact replacement must not inherit the old proof.
        let update = server.put(&path).authorization_bearer(&token)
            .json(&json!({"email":"new@example.com"})).await;
        assert_eq!(update.status_code(), 200, "{}", update.text());
        let changed: (Option<String>, bool, bool) = sqlx::query_as(
            "SELECT email, email_verified, enabled FROM users WHERE id=$1")
            .bind(id_uuid).fetch_one(&app.pool).await.unwrap();
        assert_eq!(changed, (Some("new@example.com".into()), false, false));
        // Nulls, like omission, do not erase a contact or enable an account.
        let update = server.put(&path).authorization_bearer(&token)
            .json(&json!({"email":null,"firstname":null,"enabled":null})).await;
        assert_eq!(update.status_code(), 200, "{}", update.text());
        let data = &update.json::<Value>()["data"];
        assert_eq!(data["email"], "new@example.com");
        assert_eq!(data["firstname"], "Alice");
        assert_eq!(data["enabled"], false);
    });
}
