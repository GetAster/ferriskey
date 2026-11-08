mod common;

use axum::{
    Json, Router,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{CALLBACK, ClientSpec, app, authorize, exchange_code, query_param, rt};
use ferriskey_core::domain::jwt::entities::{JwkMaterial, JwtKeyPair, SigningAlgorithm};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const NONCE: &str = "original-relying-party-nonce";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// A real HTTP provider, following the local Axum server pattern in backchannel_logout_test.
struct Provider {
    base: String,
    token: Arc<Mutex<String>>,
    key: jsonwebtoken::EncodingKey,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn provider() -> Provider {
    let (private, public) = JwtKeyPair::generate(SigningAlgorithm::Rs256).unwrap();
    let key = JwtKeyPair::from_pem(
        SigningAlgorithm::Rs256,
        &private,
        &public,
        "",
        Uuid::nil(),
        Uuid::nil(),
    )
    .unwrap();
    let JwkMaterial::Rsa { n, e } = key.to_jwk_key().unwrap().material else {
        panic!("RSA key")
    };
    let jwks =
        json!({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key","n":n,"e":e}]});
    let token = Arc::new(Mutex::new(String::new()));
    let tokens = token.clone();
    let router = Router::new()
        .route("/jwks", get(move || { let jwks = jwks.clone(); async move { Json(jwks) } }))
        .route("/token", post(move || { let token = tokens.lock().unwrap().clone(); async move { Json(json!({"access_token":"mock-access-token","token_type":"Bearer","id_token":token})) } }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Provider {
        base,
        token,
        key: key.encoding_key,
        task,
    }
}

async fn journey(verified_email: bool, existing_account: bool) {
    let local_app = app().sibling_with_local_provider().await;
    let app = &local_app;
    let server = app.server();
    sqlx::query("UPDATE realm_settings SET magic_link_enabled=true WHERE realm_id=$1")
        .bind(app.realm_id)
        .execute(&app.pool)
        .await
        .unwrap();
    let provider = provider().await;
    let user = app.user(&server, "Str0ng!P@ssword#2024").await;
    let mut user_id: Uuid = user.id.parse().unwrap();
    let email: String =
        sqlx::query_scalar("UPDATE users SET email_verified=true WHERE id=$1 RETURNING email")
            .bind(user_id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    if !existing_account {
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&app.pool)
            .await
            .unwrap();
    }
    let alias = format!("resume-{}", Uuid::new_v4().simple());
    let provider_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identity_providers (id,realm_id,alias,provider_id,trust_email,config) VALUES ($1,$2,$3,'oidc',$4,$5)")
        .bind(provider_id).bind(app.realm_id).bind(&alias).bind(true)
        .bind(json!({"client_id":"mock-client","client_secret":"mock-secret","authorization_url":format!("{}/authorize",provider.base),"token_url":format!("{}/token",provider.base),"jwks_url":format!("{}/jwks",provider.base),"issuer":provider.base,"scopes":["openid","email"],"use_pkce":false}))
        .execute(&app.pool).await.unwrap();
    let client = app.client(ClientSpec::public().with_required_pkce()).await;
    let authorized = authorize(
        &server,
        app,
        &client.client_id,
        &[
            ("state", "original-state"),
            ("nonce", NONCE),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(authorized.status_code(), 302, "{}", authorized.text());
    let cookie = authorized.cookie("FERRISKEY_SESSION");
    let original: Uuid = cookie.value().parse().unwrap();
    // This is the actual login-page provider button: the query omits nonce and PKCE.
    let login = server
        .get(&app.path(&format!("/broker/{alias}/login")))
        .add_query_param("client_id", &client.client_id)
        .add_query_param("redirect_uri", CALLBACK)
        .add_query_param("state", "original-state")
        .add_cookie(cookie.clone())
        .await;
    assert_eq!(login.status_code(), 302, "{}", login.text());
    let location = login.headers()["location"].to_str().unwrap();
    let state = query_param(location, "state").unwrap();
    let nonce = query_param(location, "nonce");
    // Proves the original nonce is sent upstream, not merely restored after callback.
    assert_eq!(nonce.as_deref(), Some(NONCE));
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({"iss":provider.base,"sub":"upstream-subject","aud":"mock-client","iat":now,"exp":now+300,"nonce":nonce,"email":email});
    if verified_email {
        claims["email_verified"] = json!(true);
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key".into());
    *provider.token.lock().unwrap() =
        jsonwebtoken::encode(&header, &claims, &provider.key).unwrap();
    let callback = server
        .get(&app.path(&format!("/broker/{alias}/endpoint")))
        .add_query_param("code", "upstream-code")
        .add_query_param("state", &state)
        .add_cookie(cookie)
        .await;
    assert_eq!(callback.status_code(), 302, "callback: {}", callback.text());
    let destination = callback.headers()["location"].to_str().unwrap();
    if !existing_account && verified_email {
        user_id = sqlx::query_scalar("SELECT id FROM users WHERE realm_id=$1 AND email=$2")
            .bind(app.realm_id)
            .bind(&email)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    }
    if !existing_account && !verified_email {
        let accounts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM users WHERE realm_id=$1 AND lower(email)=lower($2)",
        )
        .bind(app.realm_id)
        .bind(&email)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        assert_eq!(
            accounts, 0,
            "unverified provider data must not reserve an account"
        );
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM identity_provider_links WHERE identity_provider_id=$1",
        )
        .bind(provider_id)
        .fetch_one(&app.pool)
        .await
        .unwrap();
        assert_eq!(links, 0, "no provider authority before email proof");
        assert!(
            callback
                .cookies()
                .iter()
                .all(|cookie| cookie.name() == "FERRISKEY_SESSION"),
            "no login-action or SSO cookie before proof"
        );
    }
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_provider_links WHERE identity_provider_id=$1 AND user_id=$2",
    )
    .bind(provider_id)
    .bind(user_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    if verified_email {
        assert_eq!(linked, 1);
        assert_eq!(
            query_param(destination, "state").as_deref(),
            Some("original-state")
        );
        let code =
            query_param(destination, "code").expect("automatic link returns authorization code");
        let denied = exchange_code(
            &server,
            app,
            &client,
            &code,
            &[(
                "code_verifier",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )],
        )
        .await;
        assert_eq!(
            denied.status_code(),
            400,
            "wrong PKCE verifier: {}",
            denied.text()
        );
        let exchanged =
            exchange_code(&server, app, &client, &code, &[("code_verifier", VERIFIER)]).await;
        assert_eq!(
            exchanged.status_code(),
            200,
            "code exchange: {}",
            exchanged.text()
        );
        let body: Value = exchanged.json();
        let jwt = body["id_token"].as_str().unwrap();
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["nonce"], NONCE);
        assert_eq!(claims["sub"], user_id.to_string());
    } else {
        assert_eq!(linked, 0, "no link is created before email proof");
        assert!(
            destination.contains("/authentication/connect-identity-provider?"),
            "{destination}"
        );
        let pending: Uuid = callback
            .cookie("FERRISKEY_SESSION")
            .value()
            .parse()
            .unwrap();
        assert_ne!(pending, original);
        let proofs: i64 = sqlx::query_scalar("SELECT count(*) FROM magic_links WHERE auth_session_code=$1 AND user_id IS NOT DISTINCT FROM $2 AND provider_link IS NOT NULL")
            .bind(pending).bind(existing_account.then_some(user_id)).fetch_one(&app.pool).await.unwrap();
        assert_eq!(
            proofs, 1,
            "one pending email confirmation is bound to the fresh transaction"
        );
        let (nonce,challenge,method,user,code): (Option<String>,Option<String>,Option<String>,Option<Uuid>,Option<String>) = sqlx::query_as("SELECT nonce,code_challenge,code_challenge_method::text,user_id,code FROM auth_sessions WHERE id=$1")
            .bind(pending).fetch_one(&app.pool).await.unwrap();
        assert_eq!(nonce.as_deref(), Some(NONCE));
        assert_eq!(challenge.as_deref(), Some(CHALLENGE));
        assert_eq!(method.as_deref(), Some("S256"));
        assert!(
            user.is_none() && code.is_none(),
            "email confirmation must remain unauthenticated"
        );
    }
}

#[test]
#[ignore = "requires PostgreSQL"]
fn cookie_resumed_provider_collision_preserves_nonce_and_pkce_for_confirmation() {
    rt().block_on(journey(false, true));
}

#[test]
#[ignore = "requires PostgreSQL"]
fn cookie_resumed_verified_provider_link_preserves_nonce_and_enforces_pkce_at_exchange() {
    rt().block_on(journey(true, true));
}

#[test]
#[ignore = "requires PostgreSQL"]
fn new_untrusted_provider_callback_sends_pending_proof_without_creating_user_or_link() {
    rt().block_on(journey(false, false));
}

#[test]
#[ignore = "requires PostgreSQL"]
fn new_trusted_provider_callback_retains_immediate_verified_registration() {
    rt().block_on(journey(true, false));
}
