mod common;
use axum::http::HeaderValue;
use common::{ClientSpec, app, authorize, rt};
use ferriskey_core::{PasswordHasherRepository, domain::crypto::HasherRepository};
use serde_json::{Value, json};
use uuid::Uuid;

/// Both tests rewrite the shared realm's settings and credentials.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
#[ignore = "requires PostgreSQL"]
fn optional_passkey_offer_is_transaction_only_and_cannot_skip_mandatory_actions() {
    let _serial = serial();
    let app = app();
    rt().block_on(async {
        let server = app.server();
        let client = app.client(ClientSpec::public()).await;
        sqlx::query("DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE realm_id=$1)")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, passkey_enabled=true, magic_link_enabled=true, user_registration_enabled=true WHERE realm_id=$1")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
        // An email login offers enrollment; declining never changes the account.
        // Each round has its own verified account: links are created for an
        // existing account only, and one address gets one link a minute.
        for iteration in 0..3 {
            let user_id = Uuid::new_v4();
            let email = format!("offer-{user_id}@example.com");
            sqlx::query("INSERT INTO users (id, realm_id, username, firstname, lastname, email, email_verified, enabled) VALUES ($1,$2,$3,'O','F',$3,true,true)")
                .bind(user_id).bind(app.realm_id).bind(&email).execute(&app.pool).await.unwrap();
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let session = auth.cookie("FERRISKEY_SESSION");
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(session.clone()).json(&json!({"email":email})).await;
            assert_eq!(sent.status_code(),200,"{}",sent.text());
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

mod account_passkey {
    use super::*;
    use common::TestApp;
    use ferriskey_core::domain::credential::entities::CredentialData;
    use webauthn_rs::prelude::{
        AttestationFormat, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType,
        Credential as WebAuthnCredential, ECDSACurve, ParsedAttestation,
    };

    const SECRET: &str = "account-passkey-secret";

    async fn passwordless_realm(app: &TestApp) {
        sqlx::query(
            "DELETE FROM credentials WHERE user_id IN (SELECT id FROM users WHERE realm_id=$1)",
        )
        .bind(app.realm_id)
        .execute(&app.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE realm_settings SET passwordless_enabled=true, passkey_enabled=true, magic_link_enabled=true, user_registration_enabled=true WHERE realm_id=$1")
            .bind(app.realm_id).execute(&app.pool).await.unwrap();
    }

    /// A verified account, made directly: each scenario sends one email to
    /// its own address, under the per-recipient limit.
    async fn account(app: &TestApp) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let email = format!("passkey-only-{id}@example.com");
        sqlx::query("INSERT INTO users (id, realm_id, username, firstname, lastname, email, email_verified, enabled) VALUES ($1,$2,$3,'P','K',$3,true,true)")
            .bind(id).bind(app.realm_id).bind(&email).execute(&app.pool).await.unwrap();
        (id, email)
    }

    /// A passkey row created `age_seconds` ago (negative: in the future).
    async fn passkey(app: &TestApp, user_id: Uuid, age_seconds: i64) {
        let cred_id = Uuid::new_v4().as_bytes().to_vec();
        let credential = WebAuthnCredential {
            cred_id: cred_id.clone().into(),
            cred: COSEKey {
                type_: COSEAlgorithm::ES256,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: [1u8; 32].to_vec().into(),
                    y: [2u8; 32].to_vec().into(),
                }),
            },
            counter: 0,
            transports: None,
            user_verified: true,
            backup_eligible: false,
            backup_state: false,
            registration_policy: Default::default(),
            extensions: Default::default(),
            attestation: ParsedAttestation::default(),
            attestation_format: AttestationFormat::None,
        };
        let data = serde_json::to_value(CredentialData::WebAuthn {
            credential: Box::new(credential),
        })
        .unwrap();
        sqlx::query("INSERT INTO credentials (id, credential_type, user_id, secret_data, credential_data, webauthn_credential_id, created_at) VALUES ($1,'webauthn-public-key-credential',$2,'',$3::jsonb,$4, (now() AT TIME ZONE 'utc') - make_interval(secs => $5))")
            .bind(Uuid::new_v4()).bind(user_id).bind(data).bind(cred_id).bind(age_seconds as f64)
            .execute(&app.pool).await.unwrap();
    }

    async fn links_for(app: &TestApp, user_id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM magic_links WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap()
    }

    /// Redeem the account's one link in the browser that asked for it.
    async fn redeem(
        app: &TestApp,
        server: &axum_test::TestServer,
        session: &str,
        user_id: Uuid,
    ) -> axum_test::TestResponse {
        let token_id: Uuid =
            sqlx::query_scalar("SELECT token_id FROM magic_links WHERE user_id=$1")
                .bind(user_id)
                .fetch_one(&app.pool)
                .await
                .unwrap();
        let hash = PasswordHasherRepository::default()
            .hash_magic_token(SECRET)
            .await
            .unwrap();
        sqlx::query("UPDATE magic_links SET token=$1 WHERE token_id=$2")
            .bind(hash.hash)
            .bind(token_id)
            .execute(&app.pool)
            .await
            .unwrap();
        server
            .get(&app.path("/login-actions/verify-magic-link"))
            .add_header(
                "Cookie",
                HeaderValue::from_str(&format!("FERRISKEY_SESSION={session}")).unwrap(),
            )
            .add_query_param("token_id", token_id.to_string())
            .add_query_param("magic_token", SECRET)
            .await
    }

    #[test]
    #[ignore = "requires PostgreSQL"]
    fn an_account_with_a_passkey_signs_in_with_it_and_nothing_else() {
        let _serial = serial();
        let app = app();
        rt().block_on(async {
            let server = app.server();
            let client = app.client(ClientSpec::public()).await;
            passwordless_realm(app).await;

            // 1. A passkey registered earlier: a link request answers as for
            // anyone, but no link exists and the refusal is recorded.
            let (user, email) = account(app).await;
            passkey(app, user, 3600).await;
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(auth.cookie("FERRISKEY_SESSION")).json(&json!({"email": email})).await;
            assert_eq!(sent.status_code(), 200, "{}", sent.text());
            assert_eq!(links_for(app, user).await, 0, "a passkey-only account is never sent a link");
            let refusals: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events WHERE realm_id=$1 AND details->>'email_type'='passkey_required_refusal' AND details->>'user_id'=$2")
                .bind(app.realm_id).bind(user.to_string()).fetch_one(&app.pool).await.unwrap();
            assert_eq!(refusals, 1);

            // 2. A link issued before the passkey existed is refused when
            // redeemed: the requirement is checked at sign-in, not only at send.
            let (user, email) = account(app).await;
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let session = auth.cookie("FERRISKEY_SESSION");
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(session.clone()).json(&json!({"email": email})).await;
            assert_eq!(sent.status_code(), 200, "{}", sent.text());
            assert_eq!(links_for(app, user).await, 1);
            passkey(app, user, 3600).await;
            let refused = redeem(app, &server, session.value(), user).await;
            assert_ne!(refused.status_code(), 200, "{}", refused.text());
            assert_eq!(refused.json::<Value>()["reason"], "passkey_authentication_required", "{}", refused.text());
            assert!(!refused.text().contains("code="), "{}", refused.text());

            // 3. An administrator's `passkey_required=false` restores the email link.
            let (user, email) = account(app).await;
            passkey(app, user, 3600).await;
            sqlx::query("INSERT INTO user_attributes (user_id, realm_id, key, value) VALUES ($1,$2,'passkey_required','false')")
                .bind(user).bind(app.realm_id).execute(&app.pool).await.unwrap();
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let session = auth.cookie("FERRISKEY_SESSION");
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(session.clone()).json(&json!({"email": email})).await;
            assert_eq!(sent.status_code(), 200, "{}", sent.text());
            assert_eq!(links_for(app, user).await, 1);
            let signed_in = redeem(app, &server, session.value(), user).await;
            assert_eq!(signed_in.status_code(), 200, "{}", signed_in.text());
            assert!(signed_in.json::<Value>()["url"].as_str().is_some_and(|u| u.contains("code=")), "{}", signed_in.text());

            // 4. A passkey created after this sign-in began (the offer after an
            // email link creates one) does not bind the sign-in that created
            // it: the mirror of 2, with the passkey younger than the transaction.
            let (user, email) = account(app).await;
            let auth = authorize(&server, app, &client.client_id, &[]).await;
            let session = auth.cookie("FERRISKEY_SESSION");
            let sent = server.post(&app.path("/login-actions/send-magic-link"))
                .add_cookie(session.clone()).json(&json!({"email": email})).await;
            assert_eq!(sent.status_code(), 200, "{}", sent.text());
            assert_eq!(links_for(app, user).await, 1);
            let session_id: Uuid = session.value().parse().unwrap();
            sqlx::query("UPDATE auth_sessions SET created_at = created_at - interval '120 seconds' WHERE id=$1")
                .bind(session_id).execute(&app.pool).await.unwrap();
            passkey(app, user, 60).await;
            let signed_in = redeem(app, &server, session.value(), user).await;
            assert_eq!(signed_in.status_code(), 200, "{}", signed_in.text());
            assert!(signed_in.json::<Value>()["url"].as_str().is_some_and(|u| u.contains("code=")), "{}", signed_in.text());
        });
    }
}
