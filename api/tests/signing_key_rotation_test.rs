//! Signing key rotation end to end: a realm's keys are published in its JWKS
//! while they can still verify a token, tokens signed before a rotation keep
//! working until the retired key's window is over, and a realm moves from RS256
//! to EdDSA by rotating.

#[cfg(test)]
mod tests {
    use ferriskey_core::domain::common::PasswordHashingCost;
    use std::{env, sync::Arc};

    use axum::{Router, http::HeaderValue};
    use axum_test::TestServer;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ferriskey_api::{
        application::http::server::{app_state::AppState, http_server::router},
        args::Args,
    };
    use ferriskey_core::{
        application::create_service,
        domain::common::{
            DatabaseConfig, FerriskeyConfig, entities::StartupConfig, ports::CoreService,
        },
    };
    use serde_json::{Value, json};
    use sqlx::Executor;
    use uuid::Uuid;

    const WEBAPP_URL: &str = "http://localhost:5555";
    const MASTER_REALM: &str = "master";
    const SEEDED_CLIENT_ID: &str = "ferriskey-admin";
    const MASTER_ADMIN_USERNAME: &str = "admin";
    const MASTER_ADMIN_PASSWORD: &str = "admin";
    const PASSWORD: &str = "Backchannel-Passw0rd!";

    fn env_or(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    fn env_u16_or(key: &str, default: u16) -> u16 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    struct SharedContext {
        app: std::sync::Mutex<Router>,
        pool: sqlx::PgPool,
    }

    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    static CTX: std::sync::OnceLock<SharedContext> = std::sync::OnceLock::new();

    fn rt() -> &'static tokio::runtime::Runtime {
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build shared runtime")
        })
    }

    fn shared_ctx() -> &'static SharedContext {
        CTX.get_or_init(|| match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(init_shared_ctx())),
            Err(_) => rt().block_on(init_shared_ctx()),
        })
    }

    async fn init_shared_ctx() -> SharedContext {
        let db_host = env_or("DATABASE_HOST", "localhost");
        let db_port = env_u16_or("DATABASE_PORT", 5432);
        let db_name = env_or("DATABASE_NAME", "ferriskey");
        let db_user = env_or("DATABASE_USER", "ferriskey");
        let db_password = env_or("DATABASE_PASSWORD", "ferriskey");

        let schema = format!("signing_key_rotation_test_{}", Uuid::new_v4().simple());

        let admin_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_password, db_host, db_port, db_name
        );
        let admin_pool = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect admin pool");
        admin_pool
            .execute(sqlx::query(&format!(
                "CREATE SCHEMA IF NOT EXISTS \"{}\"",
                schema
            )))
            .await
            .expect("create schema");

        let schema_url = format!(
            "postgres://{}:{}@{}:{}/{}?options=-c search_path={}",
            db_user,
            db_password,
            db_host,
            db_port,
            db_name,
            urlencoding::encode(&schema)
        );
        let pool = sqlx::PgPool::connect(&schema_url)
            .await
            .expect("connect schema pool");
        sqlx::migrate!("../core/migrations")
            .run(&pool)
            .await
            .expect("run migrations");

        // The fake relying party listens on loopback, which only a deployment
        // that allows private endpoints may reach.
        let service = create_service(FerriskeyConfig {
            webhook_allow_private_endpoints: true,
            client_metadata_allow_private_endpoints: false,
            config_cache_ttl_seconds: 0,
            password_hashing: PasswordHashingCost::default(),
            webapp_url: WEBAPP_URL.to_string(),
            database: DatabaseConfig {
                host: db_host,
                port: db_port,
                username: db_user,
                password: db_password,
                name: db_name,
                schema: schema.clone(),
            },
        })
        .await
        .expect("create service");

        service
            .initialize_application(StartupConfig {
                webapp_url: WEBAPP_URL.to_string(),
                master_realm_name: MASTER_REALM.to_string(),
                admin_username: MASTER_ADMIN_USERNAME.to_string(),
                admin_password: MASTER_ADMIN_PASSWORD.to_string(),
                admin_email: "admin@test.local".to_string(),
                default_client_id: SEEDED_CLIENT_ID.to_string(),
            })
            .await
            .expect("initialize application");

        let state = AppState::new(Arc::new(Args::default()), service);
        let app = router(state).expect("build router");
        let ctx = SharedContext {
            app: std::sync::Mutex::new(app),
            pool,
        };

        ctx
    }

    fn make_server() -> TestServer {
        let app = shared_ctx()
            .app
            .lock()
            .expect("router mutex poisoned")
            .clone();
        TestServer::new(app).expect("create test server")
    }

    fn auth_header(token: &str) -> HeaderValue {
        format!("Bearer {}", token)
            .parse()
            .expect("bearer header is valid ASCII")
    }

    fn token_path(realm: &str) -> String {
        format!("/realms/{realm}/protocol/openid-connect/token")
    }

    async fn master_token(server: &TestServer) -> String {
        let response = server
            .post(&token_path(MASTER_REALM))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", MASTER_ADMIN_USERNAME),
                ("password", MASTER_ADMIN_PASSWORD),
            ])
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        response.json::<Value>()["access_token"]
            .as_str()
            .expect("access_token")
            .to_string()
    }

    struct TestClient {
        client_id: String,
        secret: String,
    }

    async fn create_client(server: &TestServer, realm: &str) -> TestClient {
        let master = master_token(server).await;
        let client_id = format!("app-{}", Uuid::new_v4().simple());
        let response = server
            .post(&format!("/realms/{realm}/clients"))
            .add_header("Authorization", auth_header(&master))
            .json(&json!({
                "client_id": client_id,
                "name": "app",
                "client_type": "confidential",
                "protocol": "openid-connect",
                "public_client": false,
                "service_account_enabled": false,
                "direct_access_grants_enabled": true,
                "enabled": true,
                "oauth_device_code_grant_enabled": false,
            }))
            .await;
        assert_eq!(response.status_code(), 201, "{}", response.text());
        let body: Value = response.json();
        let client = TestClient {
            client_id,
            secret: body["client_secret"]
                .as_str()
                .expect("creation hands back the plaintext secret")
                .to_string(),
        };

        client
    }

    struct TestUser {
        username: String,
    }

    async fn create_user(server: &TestServer, realm: &str) -> TestUser {
        let master = master_token(server).await;
        let username = format!("user-{}", Uuid::new_v4().simple());
        let response = server
            .post(&format!("/realms/{realm}/users"))
            .add_header("Authorization", auth_header(&master))
            .json(&json!({
                "username": username,
                "firstname": "Back",
                "lastname": "Channel",
                "email": format!("{username}@backchannel.local"),
                "email_verified": true,
            }))
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        let id = response.json::<Value>()["data"]["id"]
            .as_str()
            .expect("user id")
            .to_string();

        let response = server
            .put(&format!("/realms/{realm}/users/{id}/reset-password"))
            .add_header("Authorization", auth_header(&master))
            .json(&json!({ "value": PASSWORD, "temporary": false, "credential_type": "password" }))
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        TestUser { username }
    }

    /// Logs `user` in through `client`; the password grant opens a session.
    async fn sign_in(
        server: &TestServer,
        realm: &str,
        client: &TestClient,
        user: &TestUser,
    ) -> Value {
        let response = server
            .post(&token_path(realm))
            .form(&[
                ("grant_type", "password"),
                ("client_id", client.client_id.as_str()),
                ("client_secret", client.secret.as_str()),
                ("username", user.username.as_str()),
                ("password", PASSWORD),
                ("scope", "openid profile"),
            ])
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        response.json()
    }

    fn header(token: &str) -> Value {
        let part = token.split('.').next().expect("a JWT has a header");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
    }

    /// Verifies `token` against the realm JWKS and returns its claims.

    async fn create_realm(server: &TestServer, name: &str, algorithm: &str) {
        let master = master_token(server).await;
        let response = server
            .post("/realms")
            .add_header("Authorization", auth_header(&master))
            .json(&json!({ "name": name, "display_name": name }))
            .await;
        assert_eq!(response.status_code(), 201, "{}", response.text());
        let response = server
            .put(&format!("/realms/{name}/settings"))
            .add_header("Authorization", auth_header(&master))
            .json(&json!({ "default_signing_algorithm": algorithm }))
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
    }

    async fn rotate(server: &TestServer, realm: &str) -> Value {
        let master = master_token(server).await;
        let response = server
            .post(&format!("/realms/{realm}/keys/rotate"))
            .add_header("Authorization", auth_header(&master))
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        response.json()
    }

    async fn jwks(server: &TestServer, realm: &str) -> Vec<Value> {
        server
            .get(&format!(
                "/realms/{realm}/protocol/openid-connect/jwks.json"
            ))
            .await
            .json::<Value>()["keys"]
            .as_array()
            .expect("keys")
            .clone()
    }

    async fn userinfo(server: &TestServer, realm: &str, token: &str) -> u16 {
        server
            .get(&format!("/realms/{realm}/protocol/openid-connect/userinfo"))
            .add_header("Authorization", auth_header(token))
            .await
            .status_code()
            .as_u16()
    }

    async fn signed_in(server: &TestServer, realm: &str) -> (Value, String) {
        let client = create_client(server, realm).await;
        let user = create_user(server, realm).await;
        let tokens = sign_in(server, realm, &client, &user).await;
        let access = tokens["access_token"].as_str().expect("access").to_string();
        (tokens, access)
    }

    fn kid(token: &str) -> String {
        header(token)["kid"].as_str().expect("kid").to_string()
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_token_signed_before_a_rotation_keeps_working_beside_new_ones() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-overlap", "RS256").await;
            let client = create_client(&server, "rotate-overlap").await;
            let user = create_user(&server, "rotate-overlap").await;
            let before = sign_in(&server, "rotate-overlap", &client, &user).await["access_token"]
                .as_str()
                .expect("access")
                .to_string();
            assert_eq!(userinfo(&server, "rotate-overlap", &before).await, 200);
            assert_eq!(jwks(&server, "rotate-overlap").await.len(), 1);

            let outcome = rotate(&server, "rotate-overlap").await;
            assert_eq!(outcome["retired"], json!(kid(&before)));
            assert_ne!(outcome["active"], json!(kid(&before)));
            assert!(outcome["next"].is_null());

            let after = sign_in(&server, "rotate-overlap", &client, &user).await["access_token"]
                .as_str()
                .expect("access")
                .to_string();
            assert_eq!(
                json!(kid(&after)),
                outcome["active"],
                "new tokens use the new key"
            );

            // Both verify; the JWKS publishes the signing key first, then the
            // retired one.
            assert_eq!(userinfo(&server, "rotate-overlap", &before).await, 200);
            assert_eq!(userinfo(&server, "rotate-overlap", &after).await, 200);
            let published: Vec<_> = jwks(&server, "rotate-overlap")
                .await
                .iter()
                .map(|key| key["kid"].clone())
                .collect();
            assert_eq!(published, vec![json!(kid(&after)), json!(kid(&before))]);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_retired_key_stops_verifying_when_its_window_is_over() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-expiry", "RS256").await;
            let (_, before) = signed_in(&server, "rotate-expiry").await;
            rotate(&server, "rotate-expiry").await;

            // Nothing has read the retired key since the rotation, so no
            // instance holds it in memory when its window is closed.
            sqlx::query(
                "UPDATE jwt_keys SET verify_until = NOW() - interval '1 second' WHERE id = $1",
            )
            .bind(Uuid::parse_str(&kid(&before)).expect("kid is a uuid"))
            .execute(&shared_ctx().pool)
            .await
            .expect("close the window");

            assert_eq!(userinfo(&server, "rotate-expiry", &before).await, 401);
            let published = jwks(&server, "rotate-expiry").await;
            assert_eq!(published.len(), 1, "the expired key leaves the JWKS");
            assert_ne!(published[0]["kid"], json!(kid(&before)));
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_realm_moves_from_rs256_to_eddsa_by_rotating() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-alg", "RS256").await;
            let client = create_client(&server, "rotate-alg").await;
            let user = create_user(&server, "rotate-alg").await;
            let rsa = sign_in(&server, "rotate-alg", &client, &user).await["access_token"]
                .as_str()
                .expect("access")
                .to_string();
            assert_eq!(header(&rsa)["alg"], json!("RS256"));

            let master = master_token(&server).await;
            let response = server
                .put("/realms/rotate-alg/settings")
                .add_header("Authorization", auth_header(&master))
                .json(&json!({ "default_signing_algorithm": "EdDSA" }))
                .await;
            assert_eq!(response.status_code(), 200, "{}", response.text());
            // The setting alone changes nothing that exists.
            let unchanged = sign_in(&server, "rotate-alg", &client, &user).await["access_token"]
                .as_str()
                .expect("access")
                .to_string();
            assert_eq!(header(&unchanged)["alg"], json!("RS256"));

            rotate(&server, "rotate-alg").await;
            let eddsa = sign_in(&server, "rotate-alg", &client, &user).await["access_token"]
                .as_str()
                .expect("access")
                .to_string();
            assert_eq!(header(&eddsa)["alg"], json!("EdDSA"));

            let keys = jwks(&server, "rotate-alg").await;
            let kinds: Vec<_> = keys
                .iter()
                .map(|key| (key["kty"].clone(), key["alg"].clone()))
                .collect();
            assert_eq!(
                kinds,
                vec![
                    (json!("OKP"), json!("EdDSA")),
                    (json!("RSA"), json!("RS256")),
                ]
            );
            let discovery: Value = server
                .get("/realms/rotate-alg/.well-known/openid-configuration")
                .await
                .json();
            assert_eq!(
                discovery["id_token_signing_alg_values_supported"],
                json!(["EdDSA", "RS256"])
            );

            // Each token verifies under its own key's algorithm.
            assert_eq!(userinfo(&server, "rotate-alg", &rsa).await, 200);
            assert_eq!(userinfo(&server, "rotate-alg", &eddsa).await, 200);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_staged_key_is_published_before_it_signs() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-stage", "RS256").await;
            let (_, before) = signed_in(&server, "rotate-stage").await;

            let master = master_token(&server).await;
            let staged: Value = server
                .post("/realms/rotate-stage/keys/next")
                .add_header("Authorization", auth_header(&master))
                .await
                .json();
            assert_eq!(staged["active"], json!(kid(&before)));
            let next = staged["next"].clone();
            assert!(next.is_string());

            let published: Vec<_> = jwks(&server, "rotate-stage")
                .await
                .iter()
                .map(|key| key["kid"].clone())
                .collect();
            assert_eq!(published, vec![json!(kid(&before)), next.clone()]);
            let (_, still_old) = signed_in(&server, "rotate-stage").await;
            assert_eq!(
                kid(&still_old),
                kid(&before),
                "staging does not change what signs"
            );

            let outcome = rotate(&server, "rotate-stage").await;
            assert_eq!(outcome["active"], next, "rotation promotes the staged key");
            let (_, now_new) = signed_in(&server, "rotate-stage").await;
            assert_eq!(json!(kid(&now_new)), next);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_token_naming_an_unknown_key_is_refused() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-unknown", "RS256").await;
            let (_, token) = signed_in(&server, "rotate-unknown").await;
            let parts: Vec<&str> = token.split('.').collect();
            let forged_header = |header: Value| {
                format!(
                    "{}.{}.{}",
                    URL_SAFE_NO_PAD.encode(header.to_string()),
                    parts[1],
                    parts[2]
                )
            };

            for header in [
                json!({ "alg": "RS256", "typ": "JWT", "kid": Uuid::new_v4().to_string() }),
                json!({ "alg": "RS256", "typ": "JWT", "kid": "not-a-uuid" }),
                json!({ "alg": "RS256", "typ": "JWT" }),
            ] {
                let forged = forged_header(header);
                assert_eq!(userinfo(&server, "rotate-unknown", &forged).await, 401);
            }
            assert_eq!(userinfo(&server, "rotate-unknown", &token).await, 200);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn a_key_of_one_realm_does_not_verify_the_tokens_of_another() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-one", "RS256").await;
            create_realm(&server, "rotate-two", "RS256").await;
            let (_, token) = signed_in(&server, "rotate-one").await;
            signed_in(&server, "rotate-two").await;

            assert_eq!(userinfo(&server, "rotate-two", &token).await, 401);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn rotating_needs_permission_over_the_realm() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-auth", "RS256").await;
            let (_, user_token) = signed_in(&server, "rotate-auth").await;

            let anonymous = server.post("/realms/rotate-auth/keys/rotate").await;
            assert_eq!(anonymous.status_code(), 401);
            for path in ["rotate", "next"] {
                let ordinary_user = server
                    .post(&format!("/realms/rotate-auth/keys/{path}"))
                    .add_header("Authorization", auth_header(&user_token))
                    .await;
                assert_eq!(ordinary_user.status_code(), 403, "{}", ordinary_user.text());
            }
            assert_eq!(
                jwks(&server, "rotate-auth").await.len(),
                1,
                "nothing rotated"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test signing_key_rotation_test -- --ignored"]
    fn an_id_token_hint_is_checked_against_the_key_it_names() {
        rt().block_on(async {
            let server = make_server();
            create_realm(&server, "rotate-hint", "RS256").await;
            let client = create_client(&server, "rotate-hint").await;
            let user = create_user(&server, "rotate-hint").await;
            let logout = |hint: String| {
                let server = &server;
                async move {
                    server
                        .post("/realms/rotate-hint/protocol/openid-connect/logout")
                        .form(&[("id_token_hint", hint.as_str())])
                        .await
                }
            };

            // A hint signed by a key that has since been retired still ends
            // the session it names.
            let old = sign_in(&server, "rotate-hint", &client, &user).await;
            let old_access = old["access_token"].as_str().expect("access").to_string();
            rotate(&server, "rotate-hint").await;
            logout(old["id_token"].as_str().expect("id_token").to_string()).await;
            assert_eq!(userinfo(&server, "rotate-hint", &old_access).await, 401);

            // A hint naming a key the realm never held is ignored: the session
            // it was meant to end survives.
            let fresh = sign_in(&server, "rotate-hint", &client, &user).await;
            let fresh_access = fresh["access_token"].as_str().expect("access").to_string();
            let id_token = fresh["id_token"].as_str().expect("id_token");
            let parts: Vec<&str> = id_token.split('.').collect();
            let forged = format!(
                "{}.{}.{}",
                URL_SAFE_NO_PAD.encode(
                    json!({ "alg": "RS256", "typ": "JWT", "kid": Uuid::new_v4().to_string() })
                        .to_string()
                ),
                parts[1],
                parts[2]
            );
            logout(forged).await;
            assert_eq!(userinfo(&server, "rotate-hint", &fresh_access).await, 200);
        });
    }
}
