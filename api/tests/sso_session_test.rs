#[cfg(test)]
mod tests {
    use ferriskey_core::domain::common::PasswordHashingCost;
    use std::{env, sync::Arc};

    use axum::Router;
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
    use serde_json::json;
    use sqlx::{Executor, PgPool};
    use uuid::Uuid;

    const WEBAPP_URL: &str = "http://localhost:5555";
    const SEEDED_CLIENT_ID: &str = "ferriskey-admin";
    const SURVEY_CLIENT_ID: &str = "survey-app";
    const SURVEY_REDIRECT_URI: &str = "https://survey.example.com/oidc/callback";
    const S256_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const OTP_USERNAME: &str = "otp-user";
    const OTP_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

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
        realm_name: String,
        pool: PgPool,
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

        let schema = format!("sso_session_test_{}", Uuid::new_v4().simple());

        let admin_url = format!(
            "postgres://{}:{}@{}:{}/{}",
            db_user, db_password, db_host, db_port, db_name
        );

        let admin_pool = PgPool::connect(&admin_url)
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

        let pool = PgPool::connect(&schema_url)
            .await
            .expect("connect schema pool");

        sqlx::migrate!("../core/migrations")
            .run(&pool)
            .await
            .expect("run migrations");

        let service = create_service(FerriskeyConfig {
            webhook_allow_private_endpoints: false,
            client_metadata_allow_private_endpoints: false,
            config_cache_ttl_seconds: 0,
            password_hashing: PasswordHashingCost::default(),
            refresh_token_format: Default::default(),
            refresh_token_commit: Default::default(),
            webapp_url: WEBAPP_URL.to_string(),
            database: DatabaseConfig {
                host: db_host,
                port: db_port,
                username: db_user,
                password: db_password,
                name: db_name,
                schema: schema.clone(),
                max_connections: 100,
                min_connections: 5,
            },
        })
        .await
        .expect("create service");

        let realm_name = format!("realm-{}", Uuid::new_v4().simple());

        service
            .initialize_application(StartupConfig {
                webapp_url: WEBAPP_URL.to_string(),
                master_realm_name: realm_name.clone(),
                admin_username: "admin".to_string(),
                admin_password: "admin".to_string(),
                admin_email: "admin@test.local".to_string(),
                default_client_id: SEEDED_CLIENT_ID.to_string(),
            })
            .await
            .expect("initialize application");

        seed_survey_client(&pool, &realm_name).await;
        seed_otp_user(&pool).await;
        seed_no_credential_user(&pool).await;

        let args = Arc::new(Args::default());
        let state = AppState::new(args, service);
        let app = router(state).expect("build router");

        SharedContext {
            app: std::sync::Mutex::new(app),
            realm_name,
            pool,
        }
    }

    async fn seed_survey_client(pool: &PgPool, realm_name: &str) {
        let client_uuid = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO clients (id, realm_id, name, client_id, secret, enabled, protocol, \
             public_client, service_account_enabled, client_type, require_pkce) \
             SELECT $1, r.id, 'Survey', $2, 'survey-secret', TRUE, 'openid-connect', \
             FALSE, FALSE, 'confidential', FALSE \
             FROM realms r WHERE r.name = $3",
        )
        .bind(client_uuid)
        .bind(SURVEY_CLIENT_ID)
        .bind(realm_name)
        .execute(pool)
        .await
        .expect("insert survey client");

        sqlx::query(
            "INSERT INTO redirect_uris (id, client_id, value, enabled) VALUES ($1, $2, $3, TRUE)",
        )
        .bind(Uuid::new_v4())
        .bind(client_uuid)
        .bind(SURVEY_REDIRECT_URI)
        .execute(pool)
        .await
        .expect("insert survey redirect uri");
    }

    /// A second account signing in with a password and an OTP. It is cloned
    /// from `admin` (same password) so the suite needs no user API, and kept
    /// apart so the OTP never gets in the way of the tests signing in as admin.
    async fn seed_otp_user(pool: &PgPool) {
        let otp_user_id = Uuid::new_v4();
        let mut tx = pool.begin().await.expect("begin seeding the otp user");

        for statement in [
            "CREATE TEMP TABLE otp_user ON COMMIT DROP AS \
             SELECT * FROM users WHERE username = 'admin'",
            "UPDATE otp_user SET id = $1, username = 'otp-user', email = 'otp@test.local'",
            "INSERT INTO users SELECT * FROM otp_user",
            "CREATE TEMP TABLE otp_password ON COMMIT DROP AS \
             SELECT c.* FROM credentials c JOIN users u ON u.id = c.user_id \
             WHERE u.username = 'admin' AND c.credential_type = 'password'",
            "UPDATE otp_password SET id = gen_random_uuid(), user_id = $1",
            "INSERT INTO credentials SELECT * FROM otp_password",
        ] {
            let query = sqlx::query(statement);
            let query = if statement.contains("$1") {
                query.bind(otp_user_id)
            } else {
                query
            };
            query
                .execute(&mut *tx)
                .await
                .unwrap_or_else(|e| panic!("seed the otp user ({statement}): {e}"));
        }

        sqlx::query(
            "INSERT INTO credentials (id, credential_type, user_id, secret_data, \
             credential_data, user_label) \
             VALUES ($1, 'otp', $2, $3, '{}'::jsonb, 'test-authenticator')",
        )
        .bind(Uuid::new_v4())
        .bind(otp_user_id)
        .bind(OTP_SECRET)
        .execute(&mut *tx)
        .await
        .expect("enrol the otp user's authenticator");

        tx.commit().await.expect("commit the otp user");
    }

    async fn seed_no_credential_user(pool: &PgPool) {
        let user_id = Uuid::new_v4();
        let mut tx = pool
            .begin()
            .await
            .expect("begin seeding the no_credential user");

        for statement in [
            "CREATE TEMP TABLE nocred_user ON COMMIT DROP AS \
             SELECT * FROM users WHERE username = 'admin'",
            "UPDATE nocred_user SET id = $1, username = 'nocred-user', email = 'nocred@test.local'",
            "INSERT INTO users SELECT * FROM nocred_user",
        ] {
            let query = sqlx::query(statement);
            let query = if statement.contains("$1") {
                query.bind(user_id)
            } else {
                query
            };
            query
                .execute(&mut *tx)
                .await
                .unwrap_or_else(|e| panic!("seed the no_credential user ({statement}): {e}"));
        }

        tx.commit().await.expect("commit the no_credential user");
    }

    fn totp_code_for(secret_base32: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_base32)
            .expect("the enrolled secret decodes as base32");
        let counter = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after the unix epoch")
            .as_secs()
            / 30;

        let mut mac = Hmac::<Sha1>::new_from_slice(&secret).expect("hmac accepts any key length");
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();

        let offset = (digest[19] & 0x0f) as usize;
        let truncated = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);

        format!("{:06}", truncated % 1_000_000)
    }

    fn make_server() -> TestServer {
        let app = shared_ctx()
            .app
            .lock()
            .expect("router mutex poisoned")
            .clone();
        TestServer::new(app).expect("create test server")
    }

    fn realm() -> &'static str {
        shared_ctx().realm_name.as_str()
    }

    fn issuer_param() -> String {
        urlencoding::encode(&format!("http://localhost/realms/{}", realm())).into_owned()
    }

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn set_admin_enabled(enabled: bool) {
        sqlx::query("UPDATE users SET enabled = $1 WHERE username = 'admin'")
            .bind(enabled)
            .execute(&shared_ctx().pool)
            .await
            .expect("update admin enabled");
    }

    async fn count_sso_login_events() -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM security_events \
             WHERE event_type = 'login_success' AND details->>'method' = 'sso_session'",
        )
        .fetch_one(&shared_ctx().pool)
        .await
        .expect("count sso login events")
    }

    async fn count_admin_sessions() -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions s \
             JOIN users u ON u.id = s.user_id WHERE u.username = 'admin'",
        )
        .fetch_one(&shared_ctx().pool)
        .await
        .expect("count admin sessions")
    }

    async fn start_console_authorization(server: &TestServer) -> axum_test::TestResponse {
        let response = server
            .get(&format!("/realms/{}/protocol/openid-connect/auth", realm()))
            .add_query_param("response_type", "code")
            .add_query_param("client_id", SEEDED_CLIENT_ID)
            .add_query_param(
                "redirect_uri",
                format!("{WEBAPP_URL}/realms/{}/authentication/callback", realm()).as_str(),
            )
            .add_query_param("scope", "openid")
            .add_query_param("state", "st")
            .add_query_param("code_challenge", S256_CHALLENGE)
            .add_query_param("code_challenge_method", "S256")
            .await;

        let status = response.status_code().as_u16();
        assert!(
            (300..=399).contains(&status),
            "expected a redirect from /auth, got {status}: {}",
            response.text()
        );

        response
    }

    async fn start_survey_authorization(
        server: &TestServer,
        sso_cookie: Option<&str>,
    ) -> axum_test::TestResponse {
        let mut request = server
            .get(&format!("/realms/{}/protocol/openid-connect/auth", realm()))
            .add_query_param("response_type", "code")
            .add_query_param("client_id", SURVEY_CLIENT_ID)
            .add_query_param("redirect_uri", SURVEY_REDIRECT_URI)
            .add_query_param("scope", "openid")
            .add_query_param("state", "survey-state");

        if let Some(value) = sso_cookie {
            request = request.add_header(
                "Cookie",
                axum::http::HeaderValue::from_str(&format!("FERRISKEY_SSO={value}"))
                    .expect("cookie header"),
            );
        }

        request.await
    }

    fn location_of(response: &axum_test::TestResponse) -> String {
        response
            .headers()
            .get("location")
            .expect("a redirect must carry a Location header")
            .to_str()
            .expect("Location must be readable")
            .to_string()
    }

    async fn sign_in(server: &TestServer) -> String {
        let authorize = start_console_authorization(server).await;

        let login = server
            .post(&format!("/realms/{}/login-actions/authenticate", realm()))
            .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
            .add_query_param("client_id", SEEDED_CLIENT_ID)
            .json(&json!({ "username": "admin", "password": "admin" }))
            .await;

        assert_eq!(
            login.status_code(),
            200,
            "the login must succeed: {}",
            login.text()
        );

        login.cookie("FERRISKEY_SSO").value().to_string()
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_second_application_signs_in_from_the_session_cookie() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            let survey = start_survey_authorization(&server, Some(&sso)).await;
            let location = location_of(&survey);

            assert!(
                location.starts_with(SURVEY_REDIRECT_URI),
                "SSO must send the browser back to the application, not to the login page: {location}"
            );
            assert!(
                location.contains("code="),
                "the redirect must carry an authorization code: {location}"
            );
            assert!(
                location.contains("state=survey-state"),
                "the state must survive the round trip: {location}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn the_login_hands_the_browser_an_opaque_session_cookie() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let authorize = start_console_authorization(&server).await;

            let login = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SEEDED_CLIENT_ID)
                .json(&json!({ "username": "admin", "password": "admin" }))
                .await;

            let raw = login
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .find(|v| v.starts_with("FERRISKEY_SSO="))
                .expect("the login must hand back an SSO cookie")
                .to_string();

            assert!(
                raw.contains("HttpOnly"),
                "the cookie must be HttpOnly: {raw}"
            );
            let value = login.cookie("FERRISKEY_SSO").value().to_string();
            assert_eq!(
                value.split('.').count(),
                1,
                "the cookie must not be a JWT: {value}"
            );
            assert!(
                value.len() >= 32,
                "the cookie must be hard to guess: {value}"
            );

            let session_ids = sqlx::query_scalar::<_, Uuid>(
                "SELECT s.id FROM user_sessions s JOIN users u ON u.id = s.user_id \
                 WHERE u.username = 'admin'",
            )
            .fetch_all(&shared_ctx().pool)
            .await
            .expect("read admin sessions");

            assert!(
                !session_ids.iter().any(|id| id.to_string() == value),
                "the cookie must not be the session id: {value}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn the_second_application_joins_the_session_instead_of_opening_another() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            let before = count_admin_sessions().await;

            let survey = start_survey_authorization(&server, Some(&sso)).await;
            assert!(
                location_of(&survey).starts_with(SURVEY_REDIRECT_URI),
                "pre-condition: SSO must succeed"
            );

            assert_eq!(
                count_admin_sessions().await,
                before,
                "resuming a session must not open a second one for the same sign-in"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn resuming_a_session_is_recorded_as_a_login() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            let before = count_sso_login_events().await;

            let survey = start_survey_authorization(&server, Some(&sso)).await;
            assert!(
                location_of(&survey).starts_with(SURVEY_REDIRECT_URI),
                "pre-condition: SSO must succeed"
            );

            assert_eq!(
                count_sso_login_events().await,
                before + 1,
                "an SSO login must leave a trace in the audit log"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_disabled_user_cannot_resume_a_session() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            set_admin_enabled(false).await;

            let survey = start_survey_authorization(&server, Some(&sso)).await;
            set_admin_enabled(true).await;

            let location = location_of(&survey);

            assert!(
                !location.starts_with(SURVEY_REDIRECT_URI),
                "a disabled account must not walk away with an authorization code: {location}"
            );
            assert!(
                location.starts_with(WEBAPP_URL),
                "the browser must land on the login page instead: {location}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn an_unknown_session_falls_back_to_the_login_page() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();

            let survey =
                start_survey_authorization(&server, Some(&Uuid::new_v4().to_string())).await;
            let location = location_of(&survey);

            assert!(
                location.starts_with(WEBAPP_URL),
                "an unknown session must land on the login page: {location}"
            );
            assert!(
                location.contains("session_expired=1"),
                "the login page should say why the user is seeing it again: {location}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn no_cookie_means_the_ordinary_login_page() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();

            let survey = start_survey_authorization(&server, None).await;
            let location = location_of(&survey);

            assert!(
                location.starts_with(WEBAPP_URL),
                "the browser must land on the login page: {location}"
            );
            assert!(
                !location.contains("session_expired=1"),
                "a first visit is not an expired session: {location}"
            );
        });
    }

    fn code_of(location: &str) -> String {
        location
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or_default()
            .split('&')
            .find_map(|pair| pair.strip_prefix("code="))
            .expect("the redirect must carry an authorization code")
            .to_string()
    }

    /// Sign in, then let the survey application obtain a code from the SSO
    /// session, returning that code unexchanged.
    async fn survey_code_from_sso(server: &TestServer) -> String {
        let sso = sign_in(server).await;
        let survey = start_survey_authorization(server, Some(&sso)).await;
        let location = location_of(&survey);
        assert!(
            location.starts_with(SURVEY_REDIRECT_URI),
            "pre-condition: SSO must succeed: {location}"
        );
        code_of(&location)
    }

    async fn exchange_survey_code(server: &TestServer, code: &str) -> axum_test::TestResponse {
        server
            .post(&format!(
                "/realms/{}/protocol/openid-connect/token",
                realm()
            ))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", SURVEY_CLIENT_ID),
                ("client_secret", "survey-secret"),
                ("code", code),
                ("redirect_uri", SURVEY_REDIRECT_URI),
            ])
            .await
    }

    async fn bound_session_query(sql: &str, code: &str) {
        let affected = sqlx::query(sql)
            .bind(code)
            .execute(&shared_ctx().pool)
            .await
            .expect("alter the session bound to the code")
            .rows_affected();
        assert_eq!(affected, 1, "the code must be bound to exactly one session");
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_code_bound_to_a_live_session_is_exchanged() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;
            let before = count_admin_sessions().await;

            let token = exchange_survey_code(&server, &code).await;

            assert_eq!(
                token.status_code(),
                200,
                "the exchange must succeed: {}",
                token.text()
            );
            assert_eq!(
                count_admin_sessions().await,
                before,
                "the exchange must join the SSO session, not open another"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_code_whose_session_was_revoked_is_refused() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;

            bound_session_query(
                "DELETE FROM user_sessions WHERE id = \
                 (SELECT user_session_id FROM auth_sessions WHERE code = $1)",
                &code,
            )
            .await;
            let before = count_admin_sessions().await;

            let token = exchange_survey_code(&server, &code).await;

            assert_eq!(
                token.status_code(),
                400,
                "a code outliving its session must not be redeemed: {}",
                token.text()
            );
            assert_eq!(token.json::<serde_json::Value>()["error"], "invalid_grant");
            assert_eq!(
                count_admin_sessions().await,
                before,
                "a refused exchange must not open a fresh session"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_code_whose_session_is_being_revoked_is_refused() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;

            // Revocation cuts the SSO secret before touching the tokens.
            bound_session_query(
                "UPDATE user_sessions SET sso_token_hash = NULL WHERE id = \
                 (SELECT user_session_id FROM auth_sessions WHERE code = $1)",
                &code,
            )
            .await;

            let token = exchange_survey_code(&server, &code).await;

            assert_eq!(
                token.status_code(),
                400,
                "a session under revocation must not mint tokens: {}",
                token.text()
            );
            assert_eq!(token.json::<serde_json::Value>()["error"], "invalid_grant");
        });
    }

    async fn count_otp_user_sessions() -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_sessions s \
             JOIN users u ON u.id = s.user_id WHERE u.username = $1",
        )
        .bind(OTP_USERNAME)
        .fetch_one(&shared_ctx().pool)
        .await
        .expect("count otp user sessions")
    }

    fn sso_cookie_of(response: &axum_test::TestResponse) -> Option<String> {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("FERRISKEY_SSO="))
            .and_then(|v| v.split(';').next())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn an_otp_login_hands_out_the_session_cookie() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();
            let authorize = start_console_authorization(&server).await;
            let session_code = authorize.cookie("FERRISKEY_SESSION").value().to_string();

            let password_step = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SEEDED_CLIENT_ID)
                .json(&json!({ "username": OTP_USERNAME, "password": "admin" }))
                .await;
            assert_eq!(
                password_step.status_code(),
                200,
                "the password step must succeed: {}",
                password_step.text()
            );
            assert_eq!(
                sso_cookie_of(&password_step),
                None,
                "a password alone must not open the SSO session while an OTP is due"
            );
            let step_token = password_step
                .cookie("FERRISKEY_LOGIN_ACTION")
                .value()
                .to_string();

            let otp_step = server
                .post(&format!("/realms/{}/login-actions/challenge-otp", realm()))
                .add_header(
                    "Cookie",
                    axum::http::HeaderValue::from_str(&format!(
                        "FERRISKEY_SESSION={session_code}; FERRISKEY_LOGIN_ACTION={step_token}"
                    ))
                    .expect("cookie header"),
                )
                .json(&json!({ "code": totp_code_for(OTP_SECRET) }))
                .await;
            assert_eq!(
                otp_step.status_code(),
                200,
                "the otp step must succeed: {}",
                otp_step.text()
            );
            let sso = sso_cookie_of(&otp_step)
                .expect("completing the login with an OTP must hand out the SSO cookie");
            let sessions_after_login = count_otp_user_sessions().await;

            let survey = start_survey_authorization(&server, Some(&sso)).await;
            let location = location_of(&survey);
            assert!(
                location.starts_with(SURVEY_REDIRECT_URI),
                "the second application must sign in from the OTP login's session: {location}"
            );

            let token = exchange_survey_code(&server, &code_of(&location)).await;
            assert_eq!(
                token.status_code(),
                200,
                "the exchange must succeed: {}",
                token.text()
            );
            assert_eq!(
                count_otp_user_sessions().await,
                sessions_after_login,
                "one sign-in, one session: the exchange must join the OTP login's session"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn the_token_endpoint_hands_out_no_cookie() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;

            let token = exchange_survey_code(&server, &code).await;

            assert_eq!(token.status_code(), 200, "{}", token.text());
            assert!(
                token.headers().get("set-cookie").is_none(),
                "a token response must not carry a bearer token in a cookie: {:?}",
                token.headers().get_all("set-cookie")
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_legacy_identity_cookie_no_longer_signs_in() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;
            let token = exchange_survey_code(&server, &code).await;
            let access_token = token.json::<serde_json::Value>()["access_token"]
                .as_str()
                .expect("an access token")
                .to_string();

            let survey = server
                .get(&format!("/realms/{}/protocol/openid-connect/auth", realm()))
                .add_query_param("response_type", "code")
                .add_query_param("client_id", SURVEY_CLIENT_ID)
                .add_query_param("redirect_uri", SURVEY_REDIRECT_URI)
                .add_query_param("scope", "openid")
                .add_query_param("state", "survey-state")
                .add_header(
                    "Cookie",
                    axum::http::HeaderValue::from_str(&format!(
                        "FERRISKEY_IDENTITY={access_token}"
                    ))
                    .expect("cookie header"),
                )
                .await;
            let location = location_of(&survey);

            assert!(
                location.starts_with(WEBAPP_URL),
                "a valid access token in the old cookie must not sign anyone in: {location}"
            );
            assert!(
                survey
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .any(|v| v.starts_with("FERRISKEY_IDENTITY=") && v.contains("Max-Age=0")),
                "the old cookie must be cleared from the browser"
            );
        });
    }

    async fn set_remember_me_enabled(enabled: bool) {
        sqlx::query(
            "UPDATE realm_settings SET remember_me_enabled = $1 \
             WHERE realm_id = (SELECT id FROM realms WHERE name = $2)",
        )
        .bind(enabled)
        .bind(realm())
        .execute(&shared_ctx().pool)
        .await
        .expect("toggle remember me on the realm");
    }

    /// The raw `Set-Cookie` line handing out `FERRISKEY_SSO`, if any.
    fn sso_set_cookie(response: &axum_test::TestResponse) -> Option<String> {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("FERRISKEY_SSO=") && !v.starts_with("FERRISKEY_SSO=;"))
            .map(str::to_string)
    }

    async fn sign_in_remembering(
        server: &TestServer,
        remember_me: bool,
    ) -> axum_test::TestResponse {
        let authorize = start_console_authorization(server).await;

        let login = server
            .post(&format!("/realms/{}/login-actions/authenticate", realm()))
            .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
            .add_query_param("client_id", SEEDED_CLIENT_ID)
            .json(&json!({ "username": "admin", "password": "admin", "remember_me": remember_me }))
            .await;

        assert_eq!(
            login.status_code(),
            200,
            "the login must succeed: {}",
            login.text()
        );
        login
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn without_remember_me_the_cookie_dies_with_the_browser() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            set_remember_me_enabled(true).await;
            let server = make_server();

            let login = sign_in_remembering(&server, false).await;
            set_remember_me_enabled(false).await;

            let raw = sso_set_cookie(&login).expect("the login must hand out an SSO cookie");
            assert!(
                !raw.contains("Max-Age") && !raw.contains("Expires"),
                "a login nobody asked to remember must get a browser-session cookie: {raw}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn remember_me_keeps_the_cookie_past_the_browser() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            set_remember_me_enabled(true).await;
            let server = make_server();

            let login = sign_in_remembering(&server, true).await;
            let sso = login.cookie("FERRISKEY_SSO").value().to_string();
            let survey = start_survey_authorization(&server, Some(&sso)).await;
            set_remember_me_enabled(false).await;

            let raw = sso_set_cookie(&login).expect("the login must hand out an SSO cookie");
            assert!(
                raw.contains("Max-Age"),
                "a remembered login must outlive the browser: {raw}"
            );

            assert!(
                location_of(&survey).starts_with(SURVEY_REDIRECT_URI),
                "pre-condition: SSO must succeed"
            );
            let reissued =
                sso_set_cookie(&survey).expect("SSO must re-issue the cookie to slide it");
            assert!(
                reissued.contains("Max-Age"),
                "re-issuing the cookie must keep it persistent: {reissued}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_realm_without_remember_me_ignores_the_request() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            set_remember_me_enabled(false).await;
            let server = make_server();

            let login = sign_in_remembering(&server, true).await;

            let raw = sso_set_cookie(&login).expect("the login must hand out an SSO cookie");
            assert!(
                !raw.contains("Max-Age"),
                "a realm that does not offer remember me must not honour it: {raw}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn remember_me_survives_the_otp_step() {
        let _serial = serial();
        rt().block_on(async {
            set_remember_me_enabled(true).await;
            let server = make_server();
            let authorize = start_console_authorization(&server).await;
            let session_code = authorize.cookie("FERRISKEY_SESSION").value().to_string();

            let password_step = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SEEDED_CLIENT_ID)
                .json(
                    &json!({ "username": OTP_USERNAME, "password": "admin", "remember_me": true }),
                )
                .await;
            let step_token = password_step
                .cookie("FERRISKEY_LOGIN_ACTION")
                .value()
                .to_string();

            let otp_step = server
                .post(&format!("/realms/{}/login-actions/challenge-otp", realm()))
                .add_header(
                    "Cookie",
                    axum::http::HeaderValue::from_str(&format!(
                        "FERRISKEY_SESSION={session_code}; FERRISKEY_LOGIN_ACTION={step_token}"
                    ))
                    .expect("cookie header"),
                )
                .json(&json!({ "code": totp_code_for(OTP_SECRET) }))
                .await;
            set_remember_me_enabled(false).await;

            assert_eq!(otp_step.status_code(), 200, "{}", otp_step.text());
            let raw = sso_set_cookie(&otp_step).expect("the otp step must hand out the cookie");
            assert!(
                raw.contains("Max-Age"),
                "the choice made at the password step must reach the session the OTP opens: {raw}"
            );
        });
    }

    async fn survey_authorize_with(
        server: &TestServer,
        sso_cookie: Option<&str>,
        extra: &[(&str, &str)],
    ) -> axum_test::TestResponse {
        let mut request = server
            .get(&format!("/realms/{}/protocol/openid-connect/auth", realm()))
            .add_query_param("response_type", "code")
            .add_query_param("client_id", SURVEY_CLIENT_ID)
            .add_query_param("redirect_uri", SURVEY_REDIRECT_URI)
            .add_query_param("scope", "openid")
            .add_query_param("state", "survey-state");

        for (key, value) in extra {
            request = request.add_query_param(key, value);
        }

        if let Some(value) = sso_cookie {
            request = request.add_header(
                "Cookie",
                axum::http::HeaderValue::from_str(&format!("FERRISKEY_SSO={value}"))
                    .expect("cookie header"),
            );
        }

        request.await
    }

    fn clears_the_sso_cookie(response: &axum_test::TestResponse) -> bool {
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.starts_with("FERRISKEY_SSO=") && v.contains("Max-Age=0"))
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn prompt_none_answers_from_the_session() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            let survey = survey_authorize_with(&server, Some(&sso), &[("prompt", "none")]).await;
            let location = location_of(&survey);

            assert!(
                location.starts_with(SURVEY_REDIRECT_URI) && location.contains("code="),
                "a live session must answer prompt=none with a code: {location}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn prompt_none_without_a_session_hands_back_login_required() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();

            let survey = survey_authorize_with(&server, None, &[("prompt", "none")]).await;

            assert_eq!(
                location_of(&survey),
                format!(
                    "{SURVEY_REDIRECT_URI}?error=login_required&state=survey-state&iss={}",
                    issuer_param()
                ),
                "prompt=none must never show a login page"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn prompt_none_combined_with_another_value_is_an_invalid_request() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();

            let survey = survey_authorize_with(&server, None, &[("prompt", "none login")]).await;

            assert_eq!(
                location_of(&survey),
                format!(
                    "{SURVEY_REDIRECT_URI}?error=invalid_request&state=survey-state&iss={}",
                    issuer_param()
                )
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn prompt_login_re_authenticates_into_the_same_session() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let old_sso = sign_in(&server).await;
            let sessions_before = count_admin_sessions().await;

            let survey =
                survey_authorize_with(&server, Some(&old_sso), &[("prompt", "login")]).await;
            let location = location_of(&survey);
            assert!(
                location.starts_with(WEBAPP_URL) && !location.contains("session_expired=1"),
                "prompt=login must ask for the login again, without calling the session expired: {location}"
            );
            assert!(
                !clears_the_sso_cookie(&survey),
                "an abandoned re-login must not sign the other applications out"
            );

            let login = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(survey.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SURVEY_CLIENT_ID)
                .json(&json!({ "username": "admin", "password": "admin" }))
                .await;
            assert_eq!(login.status_code(), 200, "{}", login.text());
            let new_sso = login.cookie("FERRISKEY_SSO").value().to_string();

            assert_eq!(
                count_admin_sessions().await,
                sessions_before,
                "signing in again must re-authenticate the session, not open a second one"
            );
            assert_ne!(new_sso, old_sso, "the cookie secret must rotate");

            let with_old = start_survey_authorization(&server, Some(&old_sso)).await;
            assert!(
                location_of(&with_old).starts_with(WEBAPP_URL),
                "the secret replaced by the re-authentication must stop working"
            );
            let with_new = start_survey_authorization(&server, Some(&new_sso)).await;
            assert!(
                location_of(&with_new).starts_with(SURVEY_REDIRECT_URI),
                "the rotated secret must sign in"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn max_age_asks_for_a_fresh_login_only_when_exceeded() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;

            sqlx::query(
                "UPDATE user_sessions SET authenticated_at = NOW() - INTERVAL '1 hour' \
                 WHERE user_id = (SELECT id FROM users WHERE username = 'admin')",
            )
            .execute(&shared_ctx().pool)
            .await
            .expect("age the admin sessions");

            let recent_enough =
                survey_authorize_with(&server, Some(&sso), &[("max_age", "7200")]).await;
            assert!(
                location_of(&recent_enough).starts_with(SURVEY_REDIRECT_URI),
                "an authentication within max_age must still sign in"
            );

            let too_old = survey_authorize_with(&server, Some(&sso), &[("max_age", "60")]).await;
            let location = location_of(&too_old);
            assert!(
                location.starts_with(WEBAPP_URL),
                "an authentication older than max_age must ask for the login again: {location}"
            );
            assert!(
                !clears_the_sso_cookie(&too_old),
                "the session is still live and must stay usable elsewhere"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn the_id_token_carries_the_authentication_time() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;
            let authenticated_at = sqlx::query_scalar::<_, i64>(
                "SELECT FLOOR(EXTRACT(EPOCH FROM s.authenticated_at))::BIGINT FROM user_sessions s \
                 JOIN auth_sessions a ON a.user_session_id = s.id WHERE a.code = $1",
            )
            .bind(&code)
            .fetch_one(&shared_ctx().pool)
            .await
            .expect("read the bound session's authentication time");

            let token = exchange_survey_code(&server, &code).await;
            let id_token = token.json::<serde_json::Value>()["id_token"]
                .as_str()
                .expect("an id token")
                .to_string();

            use base64::Engine as _;
            let payload = id_token.split('.').nth(1).expect("a JWT payload");
            let claims: serde_json::Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .expect("base64url payload"),
            )
            .expect("JSON claims");

            assert_eq!(
                claims["auth_time"].as_i64(),
                Some(authenticated_at),
                "auth_time must be the session's last interactive authentication: {claims}"
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL — run with: cargo test -p ferriskey-api --test sso_session_test -- --ignored"]
    fn a_user_with_no_credential_cannot_login() {
        let _serial = serial();
        rt().block_on(async {
            let server = make_server();
            let authorize = start_console_authorization(&server).await;

            let login = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(authorize.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SEEDED_CLIENT_ID)
                .json(&json!({ "username": "nocred-user", "password": "admin" }))
                .await;

            assert_eq!(
                login.status_code(),
                401,
                "the login must fail with 401 Unauthorized for a user with no credentials instead of 500: {}",
                login.text()
            );
        });
    }
    fn token_payload(token: &str) -> serde_json::Value {
        use base64::Engine as _;
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "requires PostgreSQL"]
    fn authentication_evidence_survives_sso_code_exchange_userinfo_and_refresh() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let code = survey_code_from_sso(&server).await;
            let token = exchange_survey_code(&server, &code).await;
            assert_eq!(token.status_code(),200,"{}",token.text());
            let tokens = token.json::<serde_json::Value>();
            let original = token_payload(tokens["id_token"].as_str().unwrap());
            assert_eq!(original["amr"],json!(["pwd"]));
            assert_eq!(original["aster_auth"],json!({"method":"password"}));
            assert!(original.get("acr").is_none());
            // A later login must not upgrade the old token or refresh lineage.
            sqlx::query("UPDATE user_sessions SET auth_evidence = $1 WHERE id = (SELECT user_session_id FROM auth_sessions WHERE code = $2)")
                .bind(json!({"authenticated_at":chrono::Utc::now().timestamp(),"method":"passkey","credential":"another-proof","uv":true}))
                .bind(&code).execute(&shared_ctx().pool).await.unwrap();
            let info = server.get(&format!("/realms/{}/protocol/openid-connect/userinfo",realm())).add_header("Authorization",format!("Bearer {}",tokens["access_token"].as_str().unwrap())).await;
            assert_eq!(info.status_code(),200,"{}",info.text());
            assert_eq!(info.json::<serde_json::Value>()["aster_auth"],original["aster_auth"]);
            let refreshed = server.post(&format!("/realms/{}/protocol/openid-connect/token",realm())).form(&[
                ("grant_type","refresh_token"),("client_id",SURVEY_CLIENT_ID),("client_secret","survey-secret"),("refresh_token",tokens["refresh_token"].as_str().unwrap())]).await;
            assert_eq!(refreshed.status_code(),200,"{}",refreshed.text());
            let refreshed = refreshed.json::<serde_json::Value>();
            let renewed = token_payload(refreshed["id_token"].as_str().unwrap());
            assert_eq!(renewed["aster_auth"],original["aster_auth"]);
            assert_eq!(renewed["auth_time"],original["auth_time"]);
            assert!(renewed.get("acr").is_none());
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL"]
    fn essential_passkey_requirement_cannot_be_satisfied_by_password_or_sso() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;
            let claims = r#"{"id_token":{"acr":{"essential":true,"values":["phr"]}}}"#;
            let refused = survey_authorize_with(&server, Some(&sso), &[("claims", claims)]).await;
            let redirect = location_of(&refused);
            assert!(redirect.starts_with(SURVEY_REDIRECT_URI), "{redirect}");
            assert!(
                redirect.contains("error=unmet_authentication_requirements"),
                "{redirect}"
            );
            assert!(redirect.contains("state=survey-state"), "{redirect}");
            assert!(!redirect.contains("code="), "{redirect}");
            let silent = survey_authorize_with(
                &server,
                Some(&sso),
                &[("claims", claims), ("prompt", "none")],
            )
            .await;
            assert!(location_of(&silent).contains("error=login_required"));
            let start = survey_authorize_with(&server, None, &[("claims", claims)]).await;
            let login = server
                .post(&format!("/realms/{}/login-actions/authenticate", realm()))
                .add_cookie(start.cookie("FERRISKEY_SESSION"))
                .add_query_param("client_id", SURVEY_CLIENT_ID)
                .json(&json!({"username":"admin","password":"admin"}))
                .await;
            assert_eq!(login.status_code(), 403, "{}", login.text());
            let error = login.json::<serde_json::Value>();
            assert_eq!(error["reason"], "unmet_authentication_requirements");
            assert!(
                error["redirect_url"]
                    .as_str()
                    .unwrap()
                    .starts_with(SURVEY_REDIRECT_URI)
            );
        });
    }

    #[test]
    #[ignore = "requires PostgreSQL"]
    fn legacy_session_does_not_invent_method_claims() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;
            sqlx::query("UPDATE user_sessions SET auth_evidence=NULL WHERE user_id=(SELECT id FROM users WHERE username='admin')").execute(&shared_ctx().pool).await.unwrap();
            let response = start_survey_authorization(&server,Some(&sso)).await;
            let token = exchange_survey_code(&server,&code_of(&location_of(&response))).await;
            assert_eq!(token.status_code(),200,"{}",token.text());
            let claims = token_payload(token.json::<serde_json::Value>()["id_token"].as_str().unwrap());
            assert!(claims.get("amr").is_none()); assert!(claims.get("acr").is_none()); assert!(claims.get("aster_auth").is_none());
        });
    }
    #[test]
    #[ignore = "requires PostgreSQL"]
    fn fresh_passkey_snapshot_meets_essential_acr_and_stale_proof_does_not() {
        let _serial = serial();
        rt().block_on(async {
            set_admin_enabled(true).await;
            let server = make_server();
            let sso = sign_in(&server).await;
            let now = chrono::Utc::now().timestamp();
            // Model a server-verified assertion. The cryptographic recording path is
            // separately exercised with actual signed assertions by the core tests.
            sqlx::query("UPDATE user_sessions SET auth_evidence=$1 WHERE user_id=(SELECT id FROM users WHERE username='admin')")
                .bind(json!({"authenticated_at":now,"method":"passkey","credential":"verified-proof","uv":true})).execute(&shared_ctx().pool).await.unwrap();
            let required = r#"{"id_token":{"acr":{"essential":true,"value":"phr"}}}"#;
            let authorize = survey_authorize_with(&server,Some(&sso),&[("claims",required),("max_age","300")]).await;
            let location = location_of(&authorize);
            assert!(location.contains("code="),"{location}");
            let token = exchange_survey_code(&server,&code_of(&location)).await;
            assert_eq!(token.status_code(),200,"{}",token.text());
            let claims = token_payload(token.json::<serde_json::Value>()["id_token"].as_str().unwrap());
            assert_eq!(claims["acr"],"phr"); assert_eq!(claims["amr"],json!(["pop","user","mfa"]));
            assert_eq!(claims["auth_time"],now);
            sqlx::query("UPDATE user_sessions SET auth_evidence=$1 WHERE user_id=(SELECT id FROM users WHERE username='admin')")
                .bind(json!({"authenticated_at":now-301,"method":"passkey","credential":"verified-proof","uv":true})).execute(&shared_ctx().pool).await.unwrap();
            let stale = survey_authorize_with(&server,Some(&sso),&[("claims",required),("max_age","300"),("prompt","none")]).await;
            assert!(location_of(&stale).contains("error=")); assert!(!location_of(&stale).contains("code="));
        });
    }
}
