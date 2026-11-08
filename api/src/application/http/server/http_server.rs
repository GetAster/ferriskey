use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use crate::application::http::server::app_state::AppState;
use crate::application::http::server::openapi::ApiDoc;
use crate::args::Args;
use ferriskey_api_abyss::routes::abyss_routes;
use ferriskey_api_account::router::account_routes;
use ferriskey_api_aegis::router::aegis_routes;
use ferriskey_api_authentication::router::authentication_routes;
use ferriskey_api_authz::router::authz_routes;
use ferriskey_api_broker::router::broker_routes;
use ferriskey_api_client::router::{client_registration_routes, client_routes};
use ferriskey_api_compass::router::compass_routes;
use ferriskey_api_email_template::router::email_template_routes;
use ferriskey_api_maintenance::router::maintenance_routes;
use ferriskey_api_organization::router::organization_routes;
use ferriskey_api_portal_layouts::router::portal_layouts_routes;
use ferriskey_api_portal_theme::router::portal_theme_routes;
use ferriskey_api_realm::router::realm_routes;
use ferriskey_api_role::router::role_routes;
use ferriskey_api_saml::router::saml_routes;
use ferriskey_api_seawatch::router::seawatch_router;
use ferriskey_api_trident::router::trident_routes;
use ferriskey_api_user::router::user_routes;
use ferriskey_api_webhook::router::webhook_routes;

use super::config::get_config;
use axum::Router;
use axum::http::Method;
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION,
};
use axum::routing::get;
use axum_cookie::prelude::*;
use axum_prometheus::PrometheusMetricLayer;
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
use ferriskey_api_core::cors::CorsOriginResolver;
use ferriskey_api_health::health_routes;
use ferriskey_core::application::create_service_with_secrets;
use ferriskey_core::domain::common::FerriskeyConfig;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, info_span};
use utoipa::OpenApi;
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};
use utoipa_scalar::{Scalar, Servable as ScalarServable};
use utoipa_swagger_ui::SwaggerUi;

const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(600);

// `PrometheusMetricLayer::pair` installs a process-wide recorder and panics on a
// second call, so every router built in this process shares one pair.
fn prometheus_pair() -> (PrometheusMetricLayer<'static>, PrometheusHandle) {
    static PAIR: OnceLock<(PrometheusMetricLayer<'static>, PrometheusHandle)> = OnceLock::new();
    PAIR.get_or_init(PrometheusMetricLayer::pair).clone()
}

pub async fn state(args: Arc<Args>) -> Result<AppState, anyhow::Error> {
    let ferriskey_config: FerriskeyConfig = FerriskeyConfig::from(args.as_ref().clone());
    let service =
        create_service_with_secrets(ferriskey_config, &args.secrets_encryption_keys).await?;

    Ok(AppState::new(args, service))
}

/// Public documentation is independent of OAuth/OIDC discovery.
fn documentation_routes<S: Clone + Send + Sync + 'static>(
    root_path: &str,
    enabled: bool,
) -> Router<S> {
    if !enabled {
        return Router::new();
    }
    let mut openapi = ApiDoc::openapi();
    let mut paths = openapi.paths.clone();
    paths.paths = openapi
        .paths
        .paths
        .into_iter()
        .map(|(path, item)| (format!("{}{path}", root_path), item))
        .collect();
    openapi.paths = paths;

    let api_docs_url = format!("{}/api-docs/openapi.json", root_path);
    axum::Router::new()
        .merge(Scalar::with_url(
            format!("{}/scalar", root_path),
            openapi.clone(),
        ))
        .merge(
            SwaggerUi::new(format!("{}/swagger-ui", root_path))
                .url(api_docs_url.clone(), openapi.clone()),
        )
        .merge(Redoc::with_url(format!("{}/redoc", root_path), openapi))
        .merge(RapiDoc::new(api_docs_url).path(format!("{}/rapidoc", root_path)))
}

///  Returns the [`Router`] of this application.
pub fn router(state: AppState) -> Result<Router, anyhow::Error> {
    router_with_metrics(state, Some(prometheus_pair()))
}

/// Builds routes with host-owned metrics wiring; `None` skips metrics entirely.
pub fn router_with_metrics(
    state: AppState,
    metrics: Option<(PrometheusMetricLayer<'static>, PrometheusHandle)>,
) -> Result<Router, anyhow::Error> {
    let trace_layer = tower_http::trace::TraceLayer::new_for_http().make_span_with(
        |request: &axum::extract::Request| {
            let method = request.method().as_str();
            let path = request
                .extensions()
                .get::<axum::extract::MatchedPath>()
                .map(|p| p.as_str())
                .unwrap_or(request.uri().path());
            let otel_name = format!("{method} {path}");
            let uri: String = request.uri().to_string();
            info_span!("http_request", method, uri, otel.name = %otel_name)
        },
    );

    let resolver = Arc::new(
        CorsOriginResolver::new(
            Arc::new(state.service.clone()),
            state.args.server.root_path.clone(),
            &state.args.server.allowed_origins,
            state.web_origin_cache.clone(),
        )
        .map_err(|error| anyhow::anyhow!("Invalid origin in ALLOWED_ORIGINS: {error}"))?,
    );

    debug!(
        "Bootstrap allowed origins: {:?}",
        state.args.server.allowed_origins
    );

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_origin(AllowOrigin::async_predicate(move |origin, parts| {
            let resolver = Arc::clone(&resolver);
            let path = parts.uri.path().to_owned();

            async move {
                match origin.to_str() {
                    Ok(origin) => resolver.is_allowed(&path, origin).await,
                    Err(_) => false,
                }
            }
        }))
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            CONTENT_LENGTH,
            ACCEPT,
            LOCATION,
        ])
        // The console reads the filename an export chose out of this header.
        // A cross-origin response hides every header the server does not name
        // here, so without it the download falls back to a generic name.
        .expose_headers([CONTENT_DISPOSITION])
        .allow_credentials(true)
        .max_age(PREFLIGHT_MAX_AGE);

    let root_path = state.args.server.root_path.clone();
    let authz_enabled = state.args.authz_enabled;
    let router = documentation_routes(&root_path, state.args.server.api_docs_enabled)
        .route(&format!("{}/config", root_path), get(get_config))
        .merge(realm_routes(state.clone()))
        .merge(client_routes(state.clone()))
        .merge(client_registration_routes(state.clone()))
        .merge(account_routes(state.clone()))
        .merge(user_routes(state.clone()))
        .merge(authentication_routes(state.clone(), &root_path))
        .merge(role_routes(state.clone()))
        .merge(webhook_routes(state.clone()))
        .merge(maintenance_routes(state.clone()))
        .merge(email_template_routes(state.clone()))
        .merge(portal_theme_routes(state.clone()))
        .merge(portal_layouts_routes(state.clone()))
        .merge(trident_routes(state.clone()))
        .merge(seawatch_router(state.clone()))
        .merge(compass_routes(state.clone()))
        .merge(abyss_routes(state.clone()))
        .merge(aegis_routes(state.clone()))
        .merge(broker_routes(state.clone(), &root_path))
        .merge(saml_routes(state.clone(), &root_path))
        .merge(organization_routes(state.clone()))
        .merge(health_routes(&root_path))
        .merge(if authz_enabled {
            authz_routes(state.clone())
        } else {
            axum::Router::new()
        })
        .merge(if let Some((_, handle)) = &metrics {
            let handle = handle.clone();
            Router::new().route(
                &format!("{}/metrics", root_path),
                get(|| async move { handle.render() }),
            )
        } else {
            Router::new()
        })
        .layer(trace_layer)
        .layer(cors)
        .layer(CookieLayer::default())
        .with_state(state);
    let router = if let Some((layer, _)) = metrics {
        router.layer(layer)
    } else {
        router
    };
    Ok(router)
}

#[cfg(test)]
mod documentation_tests {
    use super::documentation_routes;
    use crate::args::Args;
    use axum_test::TestServer;
    use clap::Parser;

    #[tokio::test]
    async fn documentation_switch_removes_every_viewer_and_schema_at_any_root() {
        for root in ["", "/api"] {
            for enabled in [false, true] {
                let server = TestServer::new(documentation_routes::<()>(root, enabled)).unwrap();
                for path in [
                    "/api-docs/openapi.json",
                    "/swagger-ui/",
                    "/scalar",
                    "/redoc",
                    "/rapidoc",
                ] {
                    let response = server.get(&format!("{root}{path}")).await;
                    if enabled {
                        response.assert_status_ok();
                    } else {
                        response.assert_status_not_found();
                    }
                }
                if enabled {
                    let response = server.get(&format!("{root}/api-docs/openapi.json")).await;
                    let spec = response.json::<serde_json::Value>();
                    let paths = spec["paths"].as_object().unwrap();
                    assert!(!paths.is_empty());
                    assert!(paths.keys().all(|path| path.starts_with(root)));
                }
            }
        }
    }

    #[test]
    fn documentation_switch_accepts_explicit_false_and_defaults_to_enabled() {
        assert!(Args::default().server.api_docs_enabled);
        let args = Args::try_parse_from(["test", "--server-api-docs-enabled=false"]).unwrap();
        assert!(!args.server.api_docs_enabled);
        assert!(Args::try_parse_from(["test", "--server-api-docs-enabled=invalid"]).is_err());
    }
}
