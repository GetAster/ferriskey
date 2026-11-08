mod common;

use common::{ClientSpec, app, authorize, rt};
use ferriskey_core::{
    PasswordHasherRepository,
    domain::{
        crypto::HasherRepository,
        trident::ports::{TridentService, VerifyMagicLinkInput},
    },
};
use serde_json::json;
use uuid::Uuid;

struct Fixture {
    user: Uuid,
    provider: Uuid,
    session: Uuid,
    token: Uuid,
    raw: String,
}

async fn redeem(f: &Fixture) -> bool {
    app()
        .service
        .verify_magic_link(VerifyMagicLinkInput {
            magic_token_id: f.token,
            magic_token: f.raw.clone(),
            webapp_base_url: "http://localhost:5555".into(),
            browser_session: Some(f.session),
        })
        .await
        .is_ok()
}

async fn fixture() -> Fixture {
    let app = app();
    let server = app.server();
    let user = app.user(&server, "Str0ng!P@ssword#2024").await;
    let user: Uuid = user.id.parse().unwrap();
    let client = app.client(ClientSpec::public()).await;
    let response = authorize(&server, app, &client.client_id, &[]).await;
    let session: Uuid = response
        .cookie("FERRISKEY_SESSION")
        .value()
        .parse()
        .unwrap();
    let provider = Uuid::new_v4();
    let token = Uuid::new_v4();
    let raw = Uuid::new_v4().to_string();
    let hash = PasswordHasherRepository::default()
        .hash_magic_token(&raw)
        .await
        .unwrap()
        .hash;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
        .bind(user)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET email_verified=false WHERE id=$1")
        .bind(user)
        .execute(&app.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO identity_providers (id,realm_id,alias,provider_id) VALUES ($1,$2,$3,'oidc')",
    )
    .bind(provider)
    .bind(app.realm_id)
    .bind(provider.to_string())
    .execute(&app.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO magic_links (id,user_id,realm_id,token_id,token,created_at,expires_at,auth_session_code,email,provider_link) VALUES ($1,$2,$3,$4,$5,now(),now()+interval '5 minutes',$6,$7,$8)")
        .bind(Uuid::new_v4()).bind(user).bind(app.realm_id).bind(token).bind(hash).bind(session).bind(&email)
        .bind(json!({"user_id":user,"provider_id":provider,"provider_name":"Microsoft","external_id":"tenant:subject","email":email}))
        .execute(&app.pool).await.unwrap();
    Fixture {
        user,
        provider,
        session,
        token,
        raw,
    }
}

async fn links(f: &Fixture) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM identity_provider_links WHERE identity_provider_id=$1")
        .bind(f.provider)
        .fetch_one(&app().pool)
        .await
        .unwrap()
}

#[test]
#[ignore = "requires PostgreSQL"]
fn provider_link_requires_same_browser_and_consumes_once_before_login() {
    rt().block_on(async {
        let f = fixture().await;
        let app = app();
        let server = app.server();
        let path = app.path("/login-actions/verify-magic-link");
        let wrong = server
            .get(&path)
            .add_query_param("token_id", f.token.to_string())
            .add_query_param("magic_token", &f.raw)
            .await;
        assert_eq!(wrong.status_code(), 400);
        assert_eq!(
            wrong.json::<serde_json::Value>()["reason"],
            "magic_link_browser_mismatch"
        );
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM magic_links WHERE token_id=$1")
                .bind(f.token)
                .fetch_one(&app.pool)
                .await
                .unwrap();
        assert_eq!(remaining, 1, "wrong browser must leave the proof usable");
        assert_eq!(links(&f).await, 0);
        let cookie = format!("FERRISKEY_SESSION={}", f.session);
        let verified = server
            .get(&path)
            .add_header("cookie", cookie.parse::<axum::http::HeaderValue>().unwrap())
            .add_query_param("token_id", f.token.to_string())
            .add_query_param("magic_token", &f.raw)
            .await;
        assert_eq!(verified.status_code(), 200, "{}", verified.text());
        assert_eq!(links(&f).await, 1);
        let is_verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
            .bind(f.user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert!(is_verified);
        let replay = server
            .get(&path)
            .add_header("cookie", cookie.parse::<axum::http::HeaderValue>().unwrap())
            .add_query_param("token_id", f.token.to_string())
            .add_query_param("magic_token", &f.raw)
            .await;
        assert!(!replay.status_code().is_success());
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn changed_authority_or_existing_link_rolls_back_confirmation() {
    rt().block_on(async {
        for change in ["email", "disabled_user", "locked_user", "disabled_provider", "link_only", "expired", "session_expired", "session_user", "conflict"] {
            let f = fixture().await;
            let pool = &app().pool;
            match change {
                "email" => { sqlx::query("UPDATE users SET email=$2 WHERE id=$1").bind(f.user).bind(format!("changed-{}@example.test",f.user)).execute(pool).await.unwrap(); }
                "disabled_user" => { sqlx::query("UPDATE users SET enabled=false WHERE id=$1").bind(f.user).execute(pool).await.unwrap(); }
                "locked_user" => { sqlx::query("UPDATE users SET locked_until=now()+interval '1 hour' WHERE id=$1").bind(f.user).execute(pool).await.unwrap(); }
                "disabled_provider" => { sqlx::query("UPDATE identity_providers SET enabled=false WHERE id=$1").bind(f.provider).execute(pool).await.unwrap(); }
                "link_only" => { sqlx::query("UPDATE identity_providers SET link_only=true WHERE id=$1").bind(f.provider).execute(pool).await.unwrap(); }
                "expired" => { sqlx::query("UPDATE magic_links SET expires_at=now()-interval '1 hour' WHERE token_id=$1").bind(f.token).execute(pool).await.unwrap(); }
                "session_expired" => { sqlx::query("UPDATE auth_sessions SET expires_at=now()-interval '1 hour' WHERE id=$1").bind(f.session).execute(pool).await.unwrap(); }
                "session_user" => { sqlx::query("UPDATE auth_sessions SET user_id=$2 WHERE id=$1").bind(f.session).bind(f.user).execute(pool).await.unwrap(); }
                "conflict" => { sqlx::query("INSERT INTO identity_provider_links (id,user_id,identity_provider_id,identity_provider_user_id,identity_provider_username) VALUES ($1,$2,$3,'already-connected','existing')").bind(Uuid::new_v4()).bind(f.user).bind(f.provider).execute(pool).await.unwrap(); }
                _ => unreachable!(),
            }
            assert!(!redeem(&f).await,"{change}");
            assert_eq!(links(&f).await, if change == "conflict" {1} else {0}, "{change}");
            let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1").bind(f.user).fetch_one(pool).await.unwrap();
            assert!(!verified,"{change}");
        }
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn declining_is_cookie_bound_and_only_deletes_connection_proofs() {
    rt().block_on(async {
        let f = fixture().await;
        let unrelated = fixture().await;
        let app = app();
        let server = app.server();
        let path = app.path("/login-actions/decline-provider-link");
        assert!(
            !server
                .post(&path)
                .json(&json!({}))
                .await
                .status_code()
                .is_success()
        );
        let cookie = format!("FERRISKEY_SESSION={}", f.session);
        let declined = server
            .post(&path)
            .add_header("cookie", cookie.parse::<axum::http::HeaderValue>().unwrap())
            .json(&json!({}))
            .await;
        assert_eq!(declined.status_code(), 204, "{}", declined.text());
        assert!(!redeem(&f).await);
        assert!(redeem(&unrelated).await);
        assert_eq!(links(&f).await, 0);
        // Ordinary magic-link purpose cannot be cancelled with this endpoint.
        let normal = fixture().await;
        sqlx::query("UPDATE magic_links SET provider_link=NULL WHERE token_id=$1")
            .bind(normal.token)
            .execute(&app.pool)
            .await
            .unwrap();
        app.service
            .decline_provider_link(app.realm.clone(), normal.session)
            .await
            .unwrap();
        assert!(redeem(&normal).await);
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn concurrent_redemptions_create_one_link() {
    rt().block_on(async {
        let f = fixture().await;
        let (a, b) = tokio::join!(redeem(&f), redeem(&f));
        assert_eq!(usize::from(a) + usize::from(b), 1);
        assert_eq!(links(&f).await, 1);
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn a_connection_proof_binds_the_session_against_another_users_magic_link() {
    rt().block_on(async {
        let f = fixture().await;
        let other = fixture().await;
        // Keep the first login pending on a mandatory action, after consumption.
        sqlx::query("INSERT INTO user_required_actions (id,user_id,action) VALUES ($1,$2,'update_password')")
            .bind(Uuid::new_v4()).bind(f.user).execute(&app().pool).await.unwrap();
        assert!(redeem(&f).await);
        sqlx::query("UPDATE magic_links SET auth_session_code=$2,provider_link=NULL WHERE token_id=$1")
            .bind(other.token).bind(f.session).execute(&app().pool).await.unwrap();
        let spoof = Fixture { session:f.session, ..other };
        assert!(!redeem(&spoof).await);
        let bound: Uuid = sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE id=$1")
            .bind(f.session).fetch_one(&app().pool).await.unwrap();
        assert_eq!(bound,f.user);
    });
}

// New registrations use the same browser-bound proof without reserving a user.
async fn registration_fixture() -> Fixture {
    let f = fixture().await;
    sqlx::query("UPDATE magic_links SET user_id=NULL, provider_link=provider_link || jsonb_build_object('registration_username',email) WHERE token_id=$1")
        .bind(f.token).execute(&app().pool).await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(f.user)
        .execute(&app().pool)
        .await
        .unwrap();
    f
}

async fn registered(f: &Fixture) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(f.user)
        .fetch_one(&app().pool)
        .await
        .unwrap()
}

#[test]
#[ignore = "requires PostgreSQL"]
fn untrusted_provider_registration_creates_nothing_until_same_browser_proof() {
    rt().block_on(async {
        let f = registration_fixture().await;
        assert!(!registered(&f).await);
        assert_eq!(links(&f).await, 0);
        let app = app();
        let server = app.server();
        let path = app.path("/login-actions/verify-magic-link");
        let wrong = server
            .get(&path)
            .add_query_param("token_id", f.token.to_string())
            .add_query_param("magic_token", &f.raw)
            .await;
        assert!(!wrong.status_code().is_success());
        assert!(!registered(&f).await);
        assert_eq!(links(&f).await, 0);
        let still_pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM magic_links WHERE token_id=$1 AND user_id IS NULL)",
        )
        .bind(f.token)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        assert!(still_pending);
        assert!(redeem(&f).await);
        assert!(registered(&f).await);
        assert_eq!(links(&f).await, 1);
        let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE id=$1")
            .bind(f.user)
            .fetch_one(&app.pool)
            .await
            .unwrap();
        assert!(verified);
        assert!(!redeem(&f).await);
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn registration_confirmation_refuses_races_and_invalid_authority_without_residual_users() {
    rt().block_on(async {
        for change in ["email_race", "username_race", "provider_link_race", "disabled_provider", "link_only", "expired", "session_expired", "decline"] {
            let f = registration_fixture().await;
            let pool = &app().pool;
            match change {
                "email_race" | "username_race" => {
                    let email: String = sqlx::query_scalar("SELECT email FROM magic_links WHERE token_id=$1")
                        .bind(f.token).fetch_one(pool).await.unwrap();
                    let id = Uuid::new_v4();
                    let (username, address) = if change == "email_race" {
                        (id.to_string(), email.to_uppercase())
                    } else { (email, format!("{id}@example.test")) };
                    sqlx::query("INSERT INTO users (id,realm_id,username,email,email_verified,enabled) VALUES ($1,$2,$3,$4,true,true)")
                        .bind(id).bind(app().realm_id).bind(username).bind(address).execute(pool).await.unwrap();
                }
                "provider_link_race" => {
                    let other = fixture().await;
                    sqlx::query("INSERT INTO identity_provider_links (id,user_id,identity_provider_id,identity_provider_user_id,identity_provider_username) VALUES ($1,$2,$3,'tenant:subject','already-linked')")
                        .bind(Uuid::new_v4()).bind(other.user).bind(f.provider).execute(pool).await.unwrap();
                }
                "disabled_provider" => { sqlx::query("UPDATE identity_providers SET enabled=false WHERE id=$1").bind(f.provider).execute(pool).await.unwrap(); }
                "link_only" => { sqlx::query("UPDATE identity_providers SET link_only=true WHERE id=$1").bind(f.provider).execute(pool).await.unwrap(); }
                "expired" => { sqlx::query("UPDATE magic_links SET expires_at=now()-interval '1 hour' WHERE token_id=$1").bind(f.token).execute(pool).await.unwrap(); }
                "session_expired" => { sqlx::query("UPDATE auth_sessions SET expires_at=now()-interval '1 hour' WHERE id=$1").bind(f.session).execute(pool).await.unwrap(); }
                "decline" => { app().service.decline_provider_link(app().realm.clone(), f.session).await.unwrap(); }
                _ => unreachable!(),
            }
            assert!(!redeem(&f).await, "{change}");
            assert!(!registered(&f).await, "{change}");
            assert_eq!(links(&f).await, if change == "provider_link_race" { 1 } else { 0 }, "{change}");
            let user: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE id=$1")
                .bind(f.session).fetch_one(pool).await.unwrap();
            assert!(user.is_none(), "{change}");
        }
    });
}

#[test]
#[ignore = "requires PostgreSQL"]
fn concurrent_registration_redemptions_create_exactly_one_account_and_link() {
    rt().block_on(async {
        let f = registration_fixture().await;
        let (a, b) = tokio::join!(redeem(&f), redeem(&f));
        assert_eq!(usize::from(a) + usize::from(b), 1);
        assert!(registered(&f).await);
        assert_eq!(links(&f).await, 1);
    });
}
