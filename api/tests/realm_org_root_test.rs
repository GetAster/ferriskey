//! The organisation root public key on a realm: absent on a fresh realm, set
//! and updated through the admin API, validated as 64 lowercase hex characters,
//! and returned with the realm.

#[cfg(test)]
mod tests {
    use ferriskey_core::domain::common::PasswordHashingCost;
    use std::{env, sync::Arc};

    use axum::{Router, http::HeaderValue};
    use axum_test::TestServer;
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

        let schema = format!("realm_org_root_test_{}", Uuid::new_v4().simple());

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
        SharedContext {
            app: std::sync::Mutex::new(app),
            pool,
        }
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

    const ROOT_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ROOT_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    async fn create_realm(server: &TestServer) -> String {
        let master = master_token(server).await;
        let name = format!("org-{}", Uuid::new_v4().simple());
        let response = server
            .post("/realms")
            .add_header("Authorization", auth_header(&master))
            .json(&json!({ "name": name, "display_name": name }))
            .await;
        assert_eq!(response.status_code(), 201, "{}", response.text());
        name
    }

    async fn get_realm(server: &TestServer, realm: &str) -> Value {
        let master = master_token(server).await;
        let response = server
            .get(&format!("/realms/{realm}"))
            .add_header("Authorization", auth_header(&master))
            .await;
        assert_eq!(response.status_code(), 200, "{}", response.text());
        response.json::<Value>()
    }

    async fn set_root(server: &TestServer, realm: &str, value: &str) -> axum_test::TestResponse {
        let master = master_token(server).await;
        server
            .put(&format!("/realms/{realm}/org-root"))
            .add_header("Authorization", auth_header(&master))
            .json(&json!({ "org_root_pubkey": value }))
            .await
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn a_fresh_realm_has_no_org_root() {
        rt().block_on(async {
            let server = make_server();
            let realm = create_realm(&server).await;

            let fetched = get_realm(&server, &realm).await;
            assert_eq!(fetched["name"], realm.as_str());
            assert!(fetched["org_root_pubkey"].is_null());
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn setting_the_org_root_stores_it_and_returns_it_with_the_realm() {
        rt().block_on(async {
            let server = make_server();
            let realm = create_realm(&server).await;

            let response = set_root(&server, &realm, ROOT_A).await;
            assert_eq!(response.status_code(), 200, "{}", response.text());
            assert_eq!(response.json::<Value>()["data"]["org_root_pubkey"], ROOT_A);

            assert_eq!(get_realm(&server, &realm).await["org_root_pubkey"], ROOT_A);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn the_org_root_can_be_updated() {
        rt().block_on(async {
            let server = make_server();
            let realm = create_realm(&server).await;

            assert_eq!(set_root(&server, &realm, ROOT_A).await.status_code(), 200);
            assert_eq!(set_root(&server, &realm, ROOT_A).await.status_code(), 200);
            let response = set_root(&server, &realm, ROOT_B).await;
            assert_eq!(response.status_code(), 200, "{}", response.text());

            assert_eq!(get_realm(&server, &realm).await["org_root_pubkey"], ROOT_B);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn invalid_org_roots_are_refused_and_change_nothing() {
        rt().block_on(async {
            let server = make_server();
            let realm = create_realm(&server).await;
            assert_eq!(set_root(&server, &realm, ROOT_A).await.status_code(), 200);

            let too_short = &ROOT_A[..62];
            let too_long = format!("{ROOT_A}00");
            let uppercase = ROOT_A.to_uppercase();
            let not_hex = format!("{}zz", &ROOT_A[..62]);
            for rejected in [
                "",
                too_short,
                too_long.as_str(),
                uppercase.as_str(),
                not_hex.as_str(),
            ] {
                let response = set_root(&server, &realm, rejected).await;
                assert!(
                    response.status_code() == 400 || response.status_code() == 422,
                    "{rejected:?} must be refused, got {}: {}",
                    response.status_code(),
                    response.text()
                );
            }

            assert_eq!(get_realm(&server, &realm).await["org_root_pubkey"], ROOT_A);
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn the_org_root_of_an_unknown_realm_is_not_set() {
        rt().block_on(async {
            let server = make_server();

            let response = set_root(&server, "no-such-realm", ROOT_A).await;
            assert!(
                response.status_code() == 401 || response.status_code() == 404,
                "{}: {}",
                response.status_code(),
                response.text()
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test realm_org_root_test -- --ignored"]
    fn the_database_refuses_a_malformed_org_root() {
        rt().block_on(async {
            let server = make_server();
            let realm = create_realm(&server).await;

            let result = sqlx::query("UPDATE realms SET org_root_pubkey = $1 WHERE name = $2")
                .bind("NOT-HEX")
                .bind(&realm)
                .execute(&shared_ctx().pool)
                .await;

            assert!(result.is_err());
        });
    }
}
