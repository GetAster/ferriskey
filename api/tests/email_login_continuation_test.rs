mod common;

use axum::http::HeaderValue;
use common::{ClientSpec, app, authorize, rt};
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
#[ignore = "requires PostgreSQL"]
fn email_actions_require_a_valid_login_cookie_and_continue_only_after_verification() {
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let user = app.user(&server, "Str0ng!P@ssword#2024").await;
        let client = app.client(ClientSpec::public()).await;
        sqlx::query("UPDATE users SET email_verified = false WHERE id = $1::uuid")
            .bind(&user.id).execute(&app.pool).await.unwrap();
        sqlx::query("INSERT INTO user_required_actions (id, user_id, action) VALUES ($1, $2::uuid, 'verify_email')")
            .bind(Uuid::new_v4()).bind(&user.id).execute(&app.pool).await.unwrap();

        // Keep a structurally valid payload, but replace the signature. The
        // former resend implementation decoded this bearer without verifying it.
        let valid_token = app.admin_token(&server).await;
        let unsigned = format!("{}.invalid-signature", valid_token.rsplit_once('.').unwrap().0);
        for endpoint in ["resend-verification-email", "continue"] {
            let refused = server.post(&app.path(&format!("/login-actions/{endpoint}")))
                .authorization_bearer(&unsigned).await;
            assert_eq!(refused.status_code(), 401, "{}", refused.text());
        }

        let authorization = authorize(&server, app, &client.client_id, &[]).await;
        let session = authorization.cookie("FERRISKEY_SESSION");
        let login = server.post(&app.path("/login-actions/authenticate"))
            .add_cookie(session.clone()).add_query_param("client_id", &client.client_id)
            .json(&json!({"username":user.username,"password":user.password})).await;
        assert_eq!(login.status_code(), 200, "{}", login.text());
        assert_eq!(login.json::<Value>()["status"], "RequiresActions");
        let step = login.cookie("FERRISKEY_LOGIN_ACTION");

        let pending = server.post(&app.path("/login-actions/continue"))
            .add_header("Cookie", HeaderValue::from_str(&format!("FERRISKEY_SESSION={}; FERRISKEY_LOGIN_ACTION={}", session.value(), step.value())).unwrap()).await;
        assert_eq!(pending.status_code(), 200, "{}", pending.text());
        assert!(pending.json::<Value>()["required_actions"].as_array().unwrap()
            .iter().any(|action| action == "verify_email"));
        assert!(pending.json::<Value>().get("url").is_none());

        // Successful continuation burns the previous step token even while
        // verification remains pending; replay cannot complete the login.
        let replay = server.post(&app.path("/login-actions/continue"))
            .add_header("Cookie", HeaderValue::from_str(&format!("FERRISKEY_SESSION={}; FERRISKEY_LOGIN_ACTION={}", session.value(), step.value())).unwrap()).await;
        assert_eq!(replay.status_code(), 401, "{}", replay.text());

        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1::uuid")
            .bind(&user.id).execute(&app.pool).await.unwrap();
        sqlx::query("DELETE FROM user_required_actions WHERE user_id = $1::uuid AND action = 'verify_email'")
            .bind(&user.id).execute(&app.pool).await.unwrap();
        let completed = server.post(&app.path("/login-actions/continue"))
            .add_header("Cookie", HeaderValue::from_str(&format!("FERRISKEY_SESSION={}; FERRISKEY_LOGIN_ACTION={}", session.value(), pending.cookie("FERRISKEY_LOGIN_ACTION").value())).unwrap()).await;
        assert_eq!(completed.status_code(), 200, "{}", completed.text());
        assert!(completed.json::<Value>()["url"].as_str().unwrap().contains("code="));
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn a_verification_link_cannot_verify_a_changed_contact_address() {
    use sha2::{Digest, Sha256};
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let user = app.user(&server, "Str0ng!P@ssword#2024").await;
        let raw = Uuid::new_v4().to_string();
        let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let original = format!("{}@ferriskey.test", user.username);
        let replacement = format!("replacement-{}@ferriskey.test", user.id);
        sqlx::query("INSERT INTO email_verification_tokens (id,user_id,realm_id,token_hash,email,expires_at) VALUES ($1,$2::uuid,$3,$4,$5,NOW()+INTERVAL '1 hour')")
            .bind(Uuid::new_v4()).bind(&user.id).bind(app.realm_id).bind(&hash).bind(&original)
            .execute(&app.pool).await.unwrap();
        sqlx::query("UPDATE users SET email=$2,email_verified=false WHERE id=$1::uuid")
            .bind(&user.id).bind(&replacement).execute(&app.pool).await.unwrap();
        let refused = server.post(&app.path("/login-actions/verify-email"))
            .json(&json!({"token":raw})).await;
        assert_eq!(refused.status_code(),400,"{}",refused.text());
        let current: (String,bool) = sqlx::query_as("SELECT email,email_verified FROM users WHERE id=$1::uuid")
            .bind(&user.id).fetch_one(&app.pool).await.unwrap();
        assert_eq!(current,(replacement.clone(),false));
        let used: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT used_at FROM email_verification_tokens WHERE token_hash=$1")
            .bind(&hash).fetch_one(&app.pool).await.unwrap();
        assert!(used.is_none(),"a refused transaction rolls token consumption back");

        // A fresh link records the actual new destination, and can verify it.
        let fresh = Uuid::new_v4().to_string();
        let fresh_hash = format!("{:x}",Sha256::digest(fresh.as_bytes()));
        sqlx::query("INSERT INTO email_verification_tokens (id,user_id,realm_id,token_hash,email,expires_at) VALUES ($1,$2::uuid,$3,$4,$5,NOW()+INTERVAL '1 hour')")
            .bind(Uuid::new_v4()).bind(&user.id).bind(app.realm_id).bind(&fresh_hash).bind(&replacement)
            .execute(&app.pool).await.unwrap();
        let verified = server.post(&app.path("/login-actions/verify-email"))
            .json(&json!({"token":fresh})).await;
        assert_eq!(verified.status_code(),200,"{}",verified.text());
        assert_eq!(verified.json::<Value>()["verified"],true);
        sqlx::query("UPDATE users SET email=$2,email_verified=true WHERE id=$1::uuid")
            .bind(&user.id).bind(&original).execute(&app.pool).await.unwrap();
        let replay = server.post(&app.path("/login-actions/verify-email"))
            .json(&json!({"token":fresh})).await;
        assert_eq!(replay.status_code(),400,"a spent link cannot bless another already-verified address: {}",replay.text());
    });
}
