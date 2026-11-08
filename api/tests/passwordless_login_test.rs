mod common;
use common::{ClientSpec, app, authorize, rt};
use ferriskey_core::PasswordHasherRepository;
use ferriskey_core::domain::crypto::HasherRepository;
use serde_json::{Value, json};
use uuid::Uuid;

#[test]
#[ignore = "requires PostgreSQL"]
fn passwordless_signup_verifies_the_delivered_email_and_resumes_once() {
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let client = app.client(ClientSpec::public().with_direct_access()).await;
        sqlx::query("DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE realm_id=$1)")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, magic_link_enabled=true, user_registration_enabled=true WHERE realm_id=$1")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        let auth = authorize(&server, app, &client.client_id, &[]).await;
        let session = auth.cookie("FERRISKEY_SESSION");
        let email = format!("new-{}@example.com", Uuid::new_v4());
        let sent = server.post(&app.path("/login-actions/send-magic-link"))
            .add_cookie(session.clone()).json(&json!({"email":email})).await;
        assert_eq!(sent.status_code(),200,"{}",sent.text());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id).bind(&email).fetch_one(&app.pool).await.unwrap();
        assert_eq!(count,0,"requesting a link must not create an account");
        let login = server.post(&app.path("/login-actions/authenticate"))
            .add_cookie(session.clone()).add_query_param("client_id",&client.client_id)
            .json(&json!({"username":email,"password":"anything"})).await;
        assert!(!login.status_code().is_success());
        let grant = server.post(&app.path("/protocol/openid-connect/token"))
            .form(&json!({"grant_type":"password","client_id":client.client_id,"username":email,"password":"anything"})).await;
        assert!(!grant.status_code().is_success());
        let register = server.post(&app.path("/protocol/openid-connect/registrations"))
            .json(&json!({"email":"legacy@example.com","password":"Str0ng!Password#2026"})).await;
        assert!(!register.status_code().is_success());
        let reset = server.post(&app.path("/login-actions/forgot-password"))
            .json(&json!({"email":email})).await;
        assert!(!reset.status_code().is_success());

        // Replace only the random test token hash, so the actual HTTP verifier,
        // one-time consumption, captured email and OAuth continuation are tested.
        let token_id: Uuid = sqlx::query_scalar("SELECT token_id FROM magic_links WHERE email=$1 AND user_id IS NULL")
            .bind(&email).fetch_one(&app.pool).await.unwrap();
        let hash = PasswordHasherRepository::default().hash_magic_token("test-mail-secret").await.unwrap();
        sqlx::query("UPDATE magic_links SET token=$1 WHERE token_id=$2")
            .bind(hash.hash).bind(token_id).execute(&app.pool).await.unwrap();
        let wrong_browser = server.get(&app.path("/login-actions/verify-magic-link"))
            .add_query_param("token_id",token_id.to_string()).add_query_param("magic_token","test-mail-secret").await;
        assert!(!wrong_browser.status_code().is_success());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id).bind(&email).fetch_one(&app.pool).await.unwrap();
        assert_eq!(count,0,"the wrong browser must not create an account");
        let completed = server.get(&app.path("/login-actions/verify-magic-link"))
            .add_cookie(session.clone()).add_query_param("token_id",token_id.to_string()).add_query_param("magic_token","test-mail-secret").await;
        assert_eq!(completed.status_code(),200,"{}",completed.text());
        assert_eq!(completed.json::<Value>()["status"],"Success");
        assert!(completed.json::<Value>()["url"].as_str().unwrap().contains("code="));
        let (user_id, verified): (Uuid,bool) = sqlx::query_as("SELECT id,email_verified FROM users WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id).bind(&email).fetch_one(&app.pool).await.unwrap();
        assert!(verified);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials WHERE user_id=$1")
            .bind(user_id).fetch_one(&app.pool).await.unwrap();
        assert_eq!(count,0,"signup never creates a bootstrap password");
        let replay = server.get(&app.path("/login-actions/verify-magic-link"))
            .add_cookie(session).add_query_param("token_id",token_id.to_string()).add_query_param("magic_token","test-mail-secret").await;
        assert!(!replay.status_code().is_success());

        // Use another address to avoid the intentional per-recipient cooldown.
        let email = format!("existing-{}@example.com", Uuid::new_v4());
        sqlx::query("UPDATE users SET email=$2 WHERE id=$1")
            .bind(user_id).bind(&email).execute(&app.pool).await.unwrap();
        // A link delivered to the old contact must not verify a replacement email.
        let auth = authorize(&server, app, &client.client_id, &[]).await;
        let next_session = auth.cookie("FERRISKEY_SESSION");
        let sent = server.post(&app.path("/login-actions/send-magic-link"))
            .add_cookie(next_session.clone()).json(&json!({"email":email})).await;
        assert_eq!(sent.status_code(),200,"{}",sent.text());
        let next_id: Uuid = sqlx::query_scalar("SELECT token_id FROM magic_links WHERE user_id=$1")
            .bind(user_id).fetch_one(&app.pool).await.unwrap();
        let hash = PasswordHasherRepository::default().hash_magic_token("old-contact-secret").await.unwrap();
        sqlx::query("UPDATE magic_links SET token=$1 WHERE token_id=$2")
            .bind(hash.hash).bind(next_id).execute(&app.pool).await.unwrap();
        sqlx::query("UPDATE users SET email='replacement@example.com', email_verified=false WHERE id=$1")
            .bind(user_id).execute(&app.pool).await.unwrap();
        let changed = server.get(&app.path("/login-actions/verify-magic-link"))
            .add_cookie(next_session).add_query_param("token_id",next_id.to_string()).add_query_param("magic_token","old-contact-secret").await;
        assert!(!changed.status_code().is_success());
        let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
            .bind(user_id).fetch_one(&app.pool).await.unwrap();
        assert!(!verified);
    });
}
