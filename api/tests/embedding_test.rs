//! Explicitly selected PostgreSQL integration coverage for the public embedding API.
//! Run: cargo test -p ferriskey-api --test embedding_test -- --ignored
use std::sync::Arc;
use std::time::Duration;

use axum_test::TestServer;
use clap::Parser;
use ferriskey_api::{FerriskeyApp, HostOptions, SchemaMigrations, args::Args, build};
use sqlx::Executor;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires PostgreSQL; uses DATABASE_* environment variables and repository defaults"]
async fn public_builder_migrates_serves_and_shuts_down_and_recovers_from_startup_failure() {
    let mut config = Args::parse_from(["embedding-test"]);
    let schema = format!("embedding_test_{}", Uuid::new_v4().simple());
    let admin_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        config.db.user, config.db.password, config.db.host, config.db.port, config.db.name,
    );
    let admin = sqlx::PgPool::connect(&admin_url)
        .await
        .expect("connect PostgreSQL");
    admin
        .execute(format!("CREATE SCHEMA \"{}\"", schema).as_str())
        .await
        .expect("create test schema");
    config.db.schema = schema.clone();
    config.db.max_connections = Some(5);
    config.db.min_connections = 1;
    config.server.root_path = "/embedded".to_string();
    config.server.allowed_origins.clear();
    config.webapp_url_from_request = false;
    config.webapp_url = "http://localhost:5555".to_string();
    // Exercise both token-state synchronization tasks as well as delivery workers.
    config.config_cache_ttl_seconds = 5;
    let config = Arc::new(config);

    let FerriskeyApp {
        router,
        service,
        shutdown,
    } = build(
        config.clone(),
        HostOptions {
            metrics: None,
            schema_migrations: SchemaMigrations::Run,
        },
    )
    .await
    .expect("build and migrate application");
    let pool = sqlx::PgPool::connect(&format!("{}?options=-c search_path={}", admin_url, schema))
        .await
        .expect("connect migrated schema");
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("schema migrations ran");
    assert!(applied > 0);
    let server = TestServer::new(router).expect("mount embedded router");
    let discovery = server
        .get("/embedded/realms/master/.well-known/openid-configuration")
        .await;
    discovery.assert_status_ok();
    assert!(
        discovery.json::<serde_json::Value>()["issuer"]
            .as_str()
            .unwrap()
            .ends_with("/embedded/realms/master")
    );
    server
        .get("/embedded/metrics")
        .await
        .assert_status_not_found();
    drop(server);
    tokio::time::timeout(Duration::from_secs(5), shutdown.shutdown())
        .await
        .expect("bounded shutdown");
    assert!(
        service.run_data_migrations().await.is_err(),
        "shutdown closes service-owned pool clones"
    );
    drop(service);
    pool.close().await;

    // Invalid CORS is detected after initialization and data migrations, so this
    // exercises cleanup after workers have started rather than early validation.
    let mut invalid = config.as_ref().clone();
    invalid.server.allowed_origins = vec!["https://example.com/invalid-path".to_string()];
    let error = match build(Arc::new(invalid), HostOptions::default()).await {
        Ok(_) => panic!("invalid CORS origin must fail startup"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("ALLOWED_ORIGINS"));

    let app = build(config, HostOptions::default())
        .await
        .expect("restart with externally managed schema");
    drop(app.router);
    drop(app.service);
    tokio::time::timeout(Duration::from_secs(5), app.shutdown.shutdown())
        .await
        .expect("restart shutdown");

    // None never installs a process-wide recorder; the host may install its own
    // even after repeated builds in the same process.
    axum_prometheus::metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("host retains metrics recorder ownership");
    admin
        .execute(format!("DROP SCHEMA \"{}\" CASCADE", schema).as_str())
        .await
        .expect("drop test schema");
    admin.close().await;
}
