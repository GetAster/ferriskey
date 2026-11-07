//! Real-router coverage of recipient suppression, IP throttling and registration rollback.
#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use ferriskey_api::{
        application::http::server::{app_state::AppState, http_server::router},
        args::Args,
    };
    use ferriskey_core::{
        application::create_service,
        domain::common::{
            DatabaseConfig, FerriskeyConfig, PasswordHashingCost, entities::StartupConfig,
            ports::CoreService,
        },
    };
    use serde_json::{Value, json};
    use sqlx::Executor;
    use std::{env, sync::Arc};
    use uuid::Uuid;
    fn env_or(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.into())
    }
    fn env_u16_or(key: &str, default: u16) -> u16 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn email_limits_preserve_privacy_and_rollback_registration() {
        let db_host = env_or("DATABASE_HOST", "localhost");
        let db_port = env_u16_or("DATABASE_PORT", 5432);
        let db_name = env_or("DATABASE_NAME", "ferriskey");
        let db_user = env_or("DATABASE_USER", "ferriskey");
        let db_password = env_or("DATABASE_PASSWORD", "ferriskey");

        let schema = format!("registration_test_{}", Uuid::new_v4().simple());

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

        let service = create_service(FerriskeyConfig {
            webhook_allow_private_endpoints: false,
            client_metadata_allow_private_endpoints: false,
            config_cache_ttl_seconds: 0,
            password_hashing: PasswordHashingCost::default(),
            refresh_token_format: Default::default(),
            refresh_token_commit: Default::default(),
            webapp_url: "http://localhost:5555".to_string(),
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
                webapp_url: "http://localhost:5555".to_string(),
                master_realm_name: realm_name.clone(),
                admin_username: "admin".to_string(),
                admin_password: "admin".to_string(),
                admin_email: "admin@test.local".to_string(),
                default_client_id: "ferriskey-admin".to_string(),
            })
            .await
            .expect("initialize application");

        let realm_id: Uuid = sqlx::query_scalar("SELECT id FROM realms WHERE name = $1")
            .bind(&realm_name)
            .fetch_one(&pool)
            .await
            .unwrap();
        let template_id = Uuid::new_v4();
        sqlx::query("INSERT INTO email_templates (id, realm_id, name, email_type, structure, mjml, created_at, updated_at) VALUES ($1,$2,'Test verification','email_verification','{}','<mjml></mjml>',now(),now())")
            .bind(template_id).bind(realm_id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO smtp_configs (id,realm_id,host,port,username,password,from_email,from_name,encryption,created_at,updated_at) VALUES ($1,$2,'127.0.0.1',1,'test','test','test@example.com','Test','none',now(),now())")
            .bind(Uuid::new_v4()).bind(realm_id).execute(&pool).await.unwrap();
        sqlx::query("UPDATE realm_settings SET user_registration_enabled=true, magic_link_enabled=true, email_verification_enabled=true, email_verification_template_id=$1 WHERE realm_id=$2")
            .bind(template_id).bind(realm_id).execute(&pool).await.unwrap();
        let mut args = Args::default();
        args.server.trust_forwarded_for = true;
        let app = router(AppState::new(Arc::new(args), service.clone())).unwrap();
        let server = TestServer::new(app).unwrap();
        let send_path = format!("/realms/{realm_name}/login-actions/send-magic-link");
        let registration_path =
            format!("/realms/{realm_name}/protocol/openid-connect/registrations");
        let email = "limited-new-user@example.com";
        let first = server
            .post(&send_path)
            .add_header("x-forwarded-for", "192.0.2.1")
            .json(&json!({"email":email}))
            .await;
        assert_eq!(first.status_code(), 200, "{}", first.text());
        let second = server
            .post(&send_path)
            .add_header("x-forwarded-for", "192.0.2.2")
            .json(&json!({"email":email}))
            .await;
        assert_eq!(second.status_code(), 200);
        assert_eq!(
            first.json::<Value>(),
            second.json::<Value>(),
            "recipient denial is indistinguishable"
        );
        let registration = server
            .post(&registration_path)
            .add_header("x-forwarded-for", "192.0.2.3")
            .json(&json!({"email":email,"password":"VeryStrong#832password!"}))
            .await;
        assert_eq!(registration.status_code(), 429, "{}", registration.text());
        assert_eq!(registration.json::<Value>()["reason"], "email_rate_limited");
        assert!(registration.headers().contains_key("retry-after"));
        let users: i64 =
            sqlx::query_scalar("SELECT count(*) FROM users WHERE realm_id=$1 AND email=$2")
                .bind(realm_id)
                .bind(email)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(users, 0, "denied registration must leave no account");
        let tokens: i64 =
            sqlx::query_scalar("SELECT count(*) FROM email_verification_tokens WHERE realm_id=$1")
                .bind(realm_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(tokens, 0, "denied registration must create no email token");
        for n in 0..10 {
            let response = server
                .post(&send_path)
                .add_header("x-forwarded-for", "2001:db8:10:20::1")
                .json(&json!({"email":format!("unknown-{n}@example.com")}))
                .await;
            assert_eq!(response.status_code(), 200, "{}", response.text());
        }
        let over_ip = server
            .post(&send_path)
            .add_header("x-forwarded-for", "2001:db8:10:20::2")
            .json(&json!({"email":"different@example.com"}))
            .await;
        assert_eq!(over_ip.status_code(), 429);
        assert!(over_ip.headers().contains_key("retry-after"));
        assert!(over_ip.json::<Value>()["message"].is_string());
        let events: Vec<Value> = sqlx::query_scalar("SELECT details FROM security_events WHERE realm_id=$1 AND details->>'reason'='email_rate_limited'")
            .bind(realm_id).fetch_all(&pool).await.unwrap();
        assert!(events.len() >= 3);
        assert!(
            events
                .iter()
                .all(|details| !details.to_string().contains('@'))
        );
        pool.close().await;
        admin_pool
            .execute(sqlx::query(&format!("DROP SCHEMA \"{}\" CASCADE", schema)))
            .await
            .unwrap();
        admin_pool.close().await;
    }
}
