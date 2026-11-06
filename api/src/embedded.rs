//! Embeds FerrisKey without installing process-wide infrastructure.
use std::sync::Arc;

use axum::Router;
use axum_prometheus::{PrometheusMetricLayer, metrics_exporter_prometheus::PrometheusHandle};
use ferriskey_core::application::{ApplicationService, create_managed_service};
use ferriskey_core::domain::common::{
    FerriskeyConfig, entities::StartupConfig, ports::CoreService,
};

use crate::application::http::server::{app_state::AppState, http_server::router_with_metrics};
use crate::args::Args;

pub use ferriskey_core::application::workers::ApplicationShutdown;

/// Schema migration policy. Data migrations and application initialization always run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SchemaMigrations {
    /// The host or deployment has already applied the schema migrations.
    #[default]
    ExternallyManaged,
    /// Apply the fork's embedded schema migrations before composing services.
    Run,
}

/// Process resources supplied by the host. The builder installs no global state.
#[derive(Default)]
pub struct HostOptions {
    /// A layer and handle using a recorder already installed by the host.
    /// `None` disables the FerrisKey metrics layer and metrics route.
    pub metrics: Option<(PrometheusMetricLayer<'static>, PrometheusHandle)>,
    pub schema_migrations: SchemaMigrations,
}

/// The host mounts `router`, uses `service`, and retains the shutdown owner.
/// Stop serving and finish service calls before consuming `shutdown`.
/// Shutdown cancels background work rather than draining queued deliveries.
pub struct FerriskeyApp {
    pub router: Router,
    pub service: ApplicationService,
    pub shutdown: ApplicationShutdown,
}

/// Build the application without parsing arguments, loading dotenv, installing
/// tracing, a metrics recorder or crypto provider, or binding a listener.
///
/// Startup order is schema migrations (when requested), secret backfill and
/// service composition, application initialization, then data migrations.
/// A startup failure cancels any workers already started.
pub async fn build(config: Arc<Args>, options: HostOptions) -> Result<FerriskeyApp, anyhow::Error> {
    ferriskey_api_core::url::check_webapp_url_settings(&config).map_err(anyhow::Error::msg)?;
    let (service, shutdown) = create_managed_service(
        FerriskeyConfig::from(config.as_ref().clone()),
        &config.secrets_encryption_keys,
        options.schema_migrations == SchemaMigrations::Run,
    )
    .await?;

    // Explicit cleanup also closes pools if initialization or router validation fails.
    let result = async {
        service
            .initialize_application(StartupConfig {
                admin_email: config.admin.email.clone(),
                admin_password: config.admin.password.clone(),
                admin_username: config.admin.username.clone(),
                default_client_id: "security-admin-console".to_string(),
                master_realm_name: "master".to_string(),
                webapp_url: config.webapp_url.clone(),
            })
            .await?;
        let report = service.run_data_migrations().await?;
        for record in &report.applied {
            tracing::info!(version = record.version, name = %record.name, "data migration applied");
        }
        router_with_metrics(AppState::new(config, service.clone()), options.metrics)
    }
    .await;

    match result {
        Ok(router) => Ok(FerriskeyApp {
            router,
            service,
            shutdown,
        }),
        Err(error) => {
            shutdown.shutdown().await;
            Err(error)
        }
    }
}
