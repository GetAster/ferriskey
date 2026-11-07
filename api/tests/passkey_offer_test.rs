mod common;
use axum::http::HeaderValue;
use common::{ClientSpec, app, authorize, rt};
use ferriskey_core::{PasswordHasherRepository, domain::crypto::HasherRepository};
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
#[ignore = "requires PostgreSQL"]
fn optional_passkey_offer_is_transaction_only_and_cannot_skip_mandatory_actions() {
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let client = app.client(ClientSpec::public()).await;
        sqlx::query("DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE realm_id=$1)")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, passkey_enabled=true, magic_link_enabled=true, user_registration_enabled=true WHERE realm_id=$1")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        let email = format!("offer-{}@example.com", Uuid::new_v4());
        // Each email login re-offers enrollment; declining never changes the account.
        for iteration in 0..3 {
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let session = auth.cookie("FERRISKEY_SESSION");
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(session.clone()).json(&json!({"email":email})).await;
            assert_eq!(sent.status_code(),200,"{}",sent.text());
            let user_id: Uuid = sqlx::query_scalar("SELECT id FROM users WHERE realm_id=$1 AND email=$2")
                .bind(app.realm_id).bind(&email).fetch_one(&app.pool).await.unwrap();
            if iteration == 2 {
                sqlx::query("INSERT INTO user_required_actions (id,user_id,action) VALUES ($1,$2,'configure_passkey')")
                    .bind(Uuid::new_v4()).bind(user_id).execute(&app.pool).await.unwrap();
            }
            let token_id: Uuid = sqlx::query_scalar("SELECT token_id FROM magic_links WHERE user_id=$1")
                .bind(user_id).fetch_one(&app.pool).await.unwrap();
            let hash = PasswordHasherRepository::default().hash_magic_token("offer-test-secret").await.unwrap();
            sqlx::query("UPDATE magic_links SET token=$1 WHERE token_id=$2")
                .bind(hash.hash).bind(token_id).execute(&app.pool).await.unwrap();
            let offered = server.get(&app.path("/login-actions/verify-magic-link"))
                .add_cookie(session.clone()).add_query_param("token_id",token_id.to_string())
                .add_query_param("magic_token","offer-test-secret").await;
            assert_eq!(offered.status_code(),200,"{}",offered.text());
            assert_eq!(offered.json::<Value>()["status"],"RequiresActions");
            assert_eq!(offered.json::<Value>()["required_actions"], json!(["configure_passkey"]));
            let step = offered.cookie("FERRISKEY_LOGIN_ACTION");
            let cookie = HeaderValue::from_str(&format!("FERRISKEY_SESSION={}; FERRISKEY_LOGIN_ACTION={}",session.value(),step.value())).unwrap();
            for action in ["verify_email", "configure_otp", "update_password"] {
                let refused = server.post(&app.path("/login-actions/skip"))
                    .add_header("Cookie",cookie.clone()).json(&json!({"action":action})).await;
                assert_eq!(refused.status_code(),403,"{}",refused.text());
            }
            let skipped = server.post(&app.path("/login-actions/skip"))
                .add_header("Cookie",cookie.clone()).json(&json!({"action":"configure_passkey"})).await;
            if iteration == 2 {
                assert_eq!(skipped.status_code(),403,"a stored mandatory action cannot be skipped: {}",skipped.text());
                assert_eq!(skipped.json::<Value>()["reason"], "action_required");
            } else {
                assert_eq!(skipped.status_code(),200,"{}",skipped.text());
                assert!(skipped.json::<Value>()["url"].as_str().unwrap().contains("code="));
                assert!(skipped.cookies().iter().any(|c| c.name() == "FERRISKEY_SSO"));
                for endpoint in ["skip", "continue"] {
                    let replay = server.post(&app.path(&format!("/login-actions/{endpoint}")))
                        .add_header("Cookie",cookie.clone()).json(&json!({"action":"configure_passkey"})).await;
                    assert_eq!(replay.status_code(),401,"consumed step cannot issue another code: {}",replay.text());
                }
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_required_actions WHERE user_id=$1")
                    .bind(user_id).fetch_one(&app.pool).await.unwrap();
                assert_eq!(count,0,"an optional offer never becomes an account requirement");
            }
        }
    });
}
