mod common;

use common::{ClientSpec, app, authorize, rt};
use ferriskey_core::{
    PasswordHasherRepository,
    domain::{
        crypto::HasherRepository,
        trident::ports::{MagicLinkInput, TridentService, VerifyMagicLinkInput},
    },
};
use uuid::Uuid;

struct Proof {
    email: String,
    session: Uuid,
    token: Uuid,
    raw: String,
}

async fn request_link() -> Proof {
    let app = app();
    let server = app.server();
    let client = app.client(ClientSpec::public()).await;
    sqlx::query(
        "DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE realm_id=$1)",
    )
    .bind(app.realm_id)
    .execute(&app.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, magic_link_enabled=true, user_registration_enabled=true WHERE realm_id=$1")
        .bind(app.realm_id).execute(&app.pool).await.unwrap();
    let auth = authorize(&server, app, &client.client_id, &[]).await;
    let cookie = auth.cookie("FERRISKEY_SESSION");
    let session: Uuid = cookie.value().parse().unwrap();
    let email = format!("pending-{}@example.test", Uuid::new_v4());
    let input = || MagicLinkInput {
        provider_link: None,
        realm_name: app.realm.clone(),
        email: email.clone(),
        base_url: "http://localhost:5555".into(),
        session_code: Some(session.to_string()),
        remember_me: false,
        user_agent: None,
    };
    // The HTTP request itself is covered by passwordless_login_test. Call the
    // service here to test many authority cases without exhausting the IP budget.
    app.service
        .generate_magic_link(input())
        .await
        .unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE realm_id=$1 AND email=$2")
        .bind(app.realm_id)
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let (token, user): (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT token_id,user_id FROM magic_links WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id)
            .bind(&email)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(user.is_none());
    // A second unauthenticated request cannot bypass the existing recipient budget.
    app.service.generate_magic_link(input()).await.unwrap();
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM magic_links WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id)
            .bind(&email)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    let raw = Uuid::new_v4().to_string();
    let hash = PasswordHasherRepository::default()
        .hash_magic_token(&raw)
        .await
        .unwrap();
    sqlx::query("UPDATE magic_links SET token=$1 WHERE token_id=$2")
        .bind(hash.hash)
        .bind(token)
        .execute(&app.pool)
        .await
        .unwrap();
    Proof {
        email,
        session,
        token,
        raw,
    }
}

async fn redeem(proof: &Proof) -> bool {
    app()
        .service
        .verify_magic_link(VerifyMagicLinkInput {
            magic_token_id: proof.token,
            magic_token: proof.raw.clone(),
            webapp_base_url: "http://localhost:5555".into(),
            browser_session: Some(proof.session),
        })
        .await
        .is_ok()
}

#[test]
#[ignore = "requires PostgreSQL"]
fn deferred_email_registration_rejects_changed_authority_without_accounts_or_session_binding() {
    rt().block_on(async {
        for change in ["email_conflict", "username_conflict", "expired", "wrong_token", "session_expired", "session_bound", "session_code", "session_authenticated", "registration_disabled", "passwordless_disabled", "magic_link_disabled"] {
            let mut proof = request_link().await;
            let app = app();
            let pool = &app.pool;
            let other = Uuid::new_v4();
            match change {
                "email_conflict" | "username_conflict" | "session_bound" => {
                    let (username, email) = match change {
                        "email_conflict" => (other.to_string(), proof.email.to_uppercase()),
                        "username_conflict" => (proof.email.to_uppercase(), format!("{other}@example.test")),
                        _ => (other.to_string(), format!("{other}@example.test")),
                    };
                    sqlx::query("INSERT INTO users(id,realm_id,username,email,email_verified,enabled) VALUES ($1,$2,$3,$4,false,true)")
                        .bind(other).bind(app.realm_id).bind(username).bind(email).execute(pool).await.unwrap();
                    if change=="session_bound" {
                        sqlx::query("UPDATE auth_sessions SET user_id=$2 WHERE id=$1").bind(proof.session).bind(other).execute(pool).await.unwrap();
                    }
                }
                "wrong_token" => { proof.raw="incorrect-secret".into(); }
                "session_code" => { sqlx::query("UPDATE auth_sessions SET code='already-issued' WHERE id=$1").bind(proof.session).execute(pool).await.unwrap(); }
                "session_authenticated" => { sqlx::query("UPDATE auth_sessions SET authenticated=true WHERE id=$1").bind(proof.session).execute(pool).await.unwrap(); }
                "expired" => { sqlx::query("UPDATE magic_links SET expires_at=now()-interval '1 hour' WHERE token_id=$1").bind(proof.token).execute(pool).await.unwrap(); }
                "session_expired" => { sqlx::query("UPDATE auth_sessions SET expires_at=now()-interval '1 hour' WHERE id=$1").bind(proof.session).execute(pool).await.unwrap(); }
                "registration_disabled" => { sqlx::query("UPDATE realm_settings SET user_registration_enabled=false WHERE realm_id=$1").bind(app.realm_id).execute(pool).await.unwrap(); }
                "passwordless_disabled" => { sqlx::query("UPDATE realm_settings SET passwordless_enabled=false WHERE realm_id=$1").bind(app.realm_id).execute(pool).await.unwrap(); }
                "magic_link_disabled" => { sqlx::query("UPDATE realm_settings SET magic_link_enabled=false WHERE realm_id=$1").bind(app.realm_id).execute(pool).await.unwrap(); }
                _ => unreachable!(),
            }
            assert!(!redeem(&proof).await,"{change}");
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE realm_id=$1 AND (lower(email)=lower($2) OR lower(username)=lower($2))")
                .bind(app.realm_id).bind(&proof.email).fetch_one(pool).await.unwrap();
            assert_eq!(count, i64::from(matches!(change,"email_conflict"|"username_conflict")),"{change}");
            let bound: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE id=$1")
                .bind(proof.session).fetch_one(pool).await.unwrap();
            assert_eq!(bound, if change=="session_bound" { Some(other) } else { None },"{change}");
        }
        two_pending_email_proofs_cannot_create_two_accounts_or_merge_sessions().await;
    });
}

// Same test entry point: both scenarios mutate the shared realm policy.
async fn two_pending_email_proofs_cannot_create_two_accounts_or_merge_sessions() {
    let first = request_link().await;
    let mut second = request_link().await;
    // Simulate another request after the recipient cooldown: both valid proofs
    // can exist before either is redeemed, but only one may create the account.
    sqlx::query("UPDATE magic_links SET email=$2 WHERE token_id=$1")
        .bind(second.token)
        .bind(&first.email)
        .execute(&app().pool)
        .await
        .unwrap();
    second.email = first.email.clone();
    let (a, b) = tokio::join!(redeem(&first), redeem(&second));
    assert_eq!(usize::from(a) + usize::from(b), 1);
    let rows: Vec<(Uuid, bool)> =
        sqlx::query_as("SELECT id,email_verified FROM users WHERE realm_id=$1 AND email=$2")
            .bind(app().realm_id)
            .bind(&first.email)
            .fetch_all(&app().pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].1);
    for (proof, won) in [(&first, a), (&second, b)] {
        let user: Option<Uuid> =
            sqlx::query_scalar("SELECT user_id FROM auth_sessions WHERE id=$1")
                .bind(proof.session)
                .fetch_one(&app().pool)
                .await
                .unwrap();
        assert_eq!(user, if won { Some(rows[0].0) } else { None });
        assert!(
            !redeem(proof).await,
            "neither replay nor conflict may log in"
        );
    }
}
