// Copyright 2025 FerrisKey Contributors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::logs::SdkLoggerProvider;

use ferriskey_api::application::http::server::openapi::ApiDoc;
use ferriskey_api::args::{Args, Command, LogArgs, ObservabilityArgs};
use ferriskey_api::{FerriskeyApp, HostOptions, SchemaMigrations, build};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{LogExporter, MetricExporter, WithExportConfig};
use opentelemetry_otlp::{Protocol, SpanExporter};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::{Resource, trace::RandomIdGenerator};
use tracing::{debug, error, info};
use tracing_opentelemetry::MetricsLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer, Registry, fmt};
use utoipa::OpenApi;

fn init_tracing_and_logging(
    log_args: &LogArgs,
    service_name: &str,
    observability_args: &ObservabilityArgs,
) -> Result<(), anyhow::Error> {
    let filter = EnvFilter::try_new(&log_args.filter).unwrap_or_else(|err| {
        eprint!("invalid log filter: {err}");
        eprint!("using default log filter: info");
        EnvFilter::new("info")
    });

    // Format layer for logging
    let fmt_layer = if log_args.json {
        fmt::layer().with_writer(std::io::stderr).json().boxed()
    } else {
        fmt::layer().with_writer(std::io::stderr).boxed()
    };

    if observability_args.active_observability {
        // Check if endpoints are provided
        let otlp_endpoint = observability_args.otlp_endpoint.as_ref().ok_or_else(|| {
            anyhow::anyhow!("OTLP endpoint is required when observability is active")
        })?;

        let metrics_endpoint = observability_args
            .metrics_endpoint
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("Metrics endpoint is required when observability is active")
            })?;

        let resource = Resource::builder()
            .with_service_name(service_name.to_string())
            .build();

        // Create the OTLP exporter
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(otlp_endpoint)
            .build()?;

        // Build the tracer provider with the exporter
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder()
                    .with_service_name(service_name.to_string())
                    .build(),
            )
            .with_id_generator(RandomIdGenerator::default())
            .with_batch_exporter(span_exporter)
            .build();

        let tracer = tracer_provider.tracer(service_name.to_string());
        let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        // Prometheus natively supports accepting metrics via the OTLP protocol
        // Create the metric exporter
        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .with_protocol(Protocol::Grpc)
            .with_endpoint(metrics_endpoint)
            .build()?;

        let meter_provider = SdkMeterProvider::builder()
            .with_periodic_exporter(metric_exporter)
            .build();

        // Metrics layer for tracing
        let metrics_layer = MetricsLayer::new(meter_provider);

        let log_exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(otlp_endpoint)
            .build()?;

        let logger_provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(log_exporter)
            .build();

        let otel_log_layer = OpenTelemetryTracingBridge::new(&logger_provider);

        Registry::default()
            .with(fmt_layer)
            .with(trace_layer)
            .with(metrics_layer)
            .with(otel_log_layer)
            .with(filter)
            .init();

        // Trace layer for tracing

        // Combine layers into a subscriber
        // let subscriber = Registry::default()
        //     .with(fmt_layer)
        //     .with(trace_layer)
        //     .with(metrics_layer)
        //     .with(filter);

        // subscriber.init();
        std::mem::forget(logger_provider);
    } else {
        let subscriber = Registry::default().with(fmt_layer).with(filter);

        subscriber.init();
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenvy::dotenv().ok();

    let args = Arc::new(Args::parse());
    init_tracing_and_logging(&args.log, "ferriskey_server", &args.observability)?;
    if let Some(Command::GenApi { output }) = &args.command {
        let spec = ApiDoc::openapi();
        let json = serde_json::to_string_pretty(&spec)?;
        match output {
            Some(path) => std::fs::write(path, &json)?,
            None => print!("{json}"),
        }
        return Ok(());
    }

    // The executable is the host and selects crypto before service composition.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install crypto provider"))?;

    let FerriskeyApp {
        router,
        service: _,
        shutdown,
    } = build(
        args.clone(),
        HostOptions {
            admin_admission: None,
            metrics: Some(axum_prometheus::PrometheusMetricLayer::pair()),
            schema_migrations: SchemaMigrations::ExternallyManaged,
        },
    )
    .await?;

    let addr = {
        let addrs = format!("{}:{}", args.server.host, args.server.port)
            .to_socket_addrs()?
            .collect::<Vec<SocketAddr>>();

        match addrs.first() {
            Some(addr) => *addr,
            None => {
                error!("At least one host and port must be provided.");
                return Err(anyhow::anyhow!(
                    "At least one host and port must be provided."
                ));
            }
        }
    };

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let serving = async {
        if let Some(tls) = &args.server.tls {
            debug!("loading tls config");
            let tls_cfg = RustlsConfig::from_pem_file(tls.cert.clone(), tls.key.clone()).await?;
            info!("listening on {addr}");
            axum_server::bind_rustls(addr, tls_cfg)
                .handle(server_handle)
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        } else {
            info!("listening on {addr}");
            axum_server::bind(addr)
                .handle(server_handle)
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(serving);
    let result = tokio::select! {
        result = &mut serving => result,
        signal = tokio::signal::ctrl_c() => {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
            let result = serving.await;
            signal.map_err(anyhow::Error::from).and(result)
        }
    };
    shutdown.shutdown().await;
    result
}
