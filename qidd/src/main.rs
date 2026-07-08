use anyhow::{Context, bail};
use axum::{
    Json, Router,
    extract::{MatchedPath, State},
    middleware,
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use qid_core::config::{DeploymentProfile, QidConfig, StaticClientConfig};
use qid_core::jwt::Signer;
use qid_core::models::{Client, PolicyBundle};
use qid_core::state::SharedState;
use qid_core::tenant::{RealmId, TenantId};
use qid_core::{MemoryCache, QidResult, SharedCache};
use qid_crypto::jwk::{generate_eddsa, generate_es256};
use qid_crypto::{
    KeyProtector, Keyring, PassphraseProtector, parse_encrypted_key, serialize_encrypted_key,
};
use qid_diagnostics::{CheckItem, CheckStatus, build_check_report, check_storage_saas_with_repo};
use qid_http::middleware::request_id_layer;
use qid_oauth::{
    routes as oauth_routes, signed_routes as signed_oauth_routes,
    unsigned_routes as unsigned_oauth_routes,
};
use qid_oidc::routes as oidc_routes;
use qid_policy::NativePolicyEngine;
use qid_proxy::{captive_portal_routes, issue_assertion, pep_decision_routes};
use qid_session::auth_routes_with_push;
use qid_storage::prelude::*;
use qid_storage::{AnyRepository, FileFlushMode};
use serde_json::json;
use std::collections::{BTreeMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::oneshot;
use tracing::{error, info, warn};
use zeroize::{Zeroize, Zeroizing};

type AppState = Arc<SharedState<AnyRepository>>;

struct PrefixedSharedCache {
    prefix: String,
    inner: Arc<dyn SharedCache>,
}

impl PrefixedSharedCache {
    fn new(prefix: &str, inner: Arc<dyn SharedCache>) -> Self {
        Self {
            prefix: prefix.trim_matches(':').to_string(),
            inner,
        }
    }

    fn key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{key}", self.prefix)
        }
    }
}

impl SharedCache for PrefixedSharedCache {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.get(&self.key(key))
    }

    fn set(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) {
        self.inner.set(&self.key(key), value, ttl_seconds);
    }

    fn set_if_absent(&self, key: &str, value: Vec<u8>, ttl_seconds: u64) -> QidResult<bool> {
        self.inner.set_if_absent(&self.key(key), value, ttl_seconds)
    }

    fn delete(&self, key: &str) {
        self.inner.delete(&self.key(key));
    }

    fn exists(&self, key: &str) -> bool {
        self.inner.exists(&self.key(key))
    }
}

#[derive(Parser)]
#[command(name = "qidd")]
#[command(about = "qid identity daemon")]
struct Args {
    /// Path to qid configuration file. May be repeated; later files override earlier files.
    #[arg(short, long, default_value = "/etc/qid/qid.yaml")]
    config: Vec<PathBuf>,
}

async fn http_metrics_layer(
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    let method = req.method().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let start = Instant::now();
    metrics::counter!("qid_http_requests_total", "method" => method.clone(), "route" => route.clone())
        .increment(1);
    let response = next.run(req).await;
    metrics::histogram!("qid_http_request_duration_seconds", "method" => method, "route" => route)
        .record(start.elapsed().as_secs_f64());
    response
}

fn log_and_reject_diagnostic_checks(checks: &[CheckItem], phase: &str) -> anyhow::Result<()> {
    let mut errors = 0usize;
    let mut warnings = 0usize;
    for check in checks {
        match check.status {
            CheckStatus::Error => {
                errors += 1;
                error!(
                    phase,
                    diagnostic = %check.name,
                    message = %check.message,
                    "configuration diagnostic error"
                );
            }
            CheckStatus::Warning => {
                warnings += 1;
                warn!(
                    phase,
                    diagnostic = %check.name,
                    message = %check.message,
                    "configuration diagnostic warning"
                );
            }
            CheckStatus::Ok | CheckStatus::NotApplicable => {}
        }
    }
    if errors > 0 {
        bail!(
            "configuration diagnostics failed during {phase}: {errors} error(s), {warnings} warning(s)"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    qid_observability::init_logging(true);

    let primary_config_path = args
        .config
        .last()
        .context("at least one config path is required")?;
    let config = QidConfig::from_files(&args.config).context("failed to load config")?;
    let plan = qid_core::plan::RuntimePlan::from_config(&config)
        .context("runtime plan validation failed")?;
    let diagnostics = build_check_report(&config, &plan, primary_config_path);
    log_and_reject_diagnostic_checks(&diagnostics.checks, "preflight")?;

    // Start Prometheus metrics exporter if configured.
    if let Err(e) = qid_observability::metrics::init_metrics(&config.observability.metrics.listen) {
        tracing::warn!(error = %e, "failed to start metrics exporter");
    }

    // Initialize storage.
    let storage_url = config.storage.primary.resolve_url_or("sqlite:qid.db");
    warn_when_file_storage_uses_distributed_cache(&config, &storage_url);
    let repo = Arc::new(
        AnyRepository::connect_with_file_flush_mode(&storage_url, file_flush_mode(&config)?)
            .await
            .context("failed to connect to storage")?,
    );
    seed_configured_realms_and_clients(&repo, &config, primary_config_path)
        .await
        .context("failed to seed configured realms and clients")?;
    let storage_diagnostics = match check_storage_saas_with_repo(&config, repo.as_ref()).await {
        Ok(checks) => checks,
        Err(message) => vec![CheckItem {
            name: "storage.saas".to_string(),
            status: CheckStatus::Error,
            message,
        }],
    };
    log_and_reject_diagnostic_checks(&storage_diagnostics, "storage")?;

    // Initialize signing key.
    let state_dir = state_dir(primary_config_path);
    let signing_material = initialize_signing_material(&config, &state_dir)
        .context("failed to initialize signing key")?;

    // Build shared state.
    let mut shared_state = SharedState::new_with_pep_assertion_signers(
        config.clone(),
        repo.clone(),
        signing_material.signer.clone(),
        signing_material.pep_assertion_signers,
        signing_material.jwks,
    )?;
    shared_state = shared_state.with_shared_cache(
        build_shared_cache(&config).context("failed to initialize shared cache")?,
    );
    if matches!(config.profile, DeploymentProfile::Workload) {
        let workload_ca =
            load_or_generate_workload_ca(&state_dir).context("failed to initialize workload CA")?;
        shared_state =
            shared_state.with_workload_ca(workload_ca.certificate_pem, workload_ca.private_key_pem);
    }
    let state: AppState = Arc::new(shared_state);

    let network_aaa_shutdown = start_network_aaa_listeners(&config, repo.clone())
        .await
        .context("failed to start network-aaa listeners")?;

    info!(listen = %state.plan.listen, "starting qidd");

    // Load a default policy engine if none is configured.
    let _policy_engine = NativePolicyEngine::new();

    let paths = &config.server.paths;
    let oauth_router = if config.server.http_message_signatures.enabled {
        let sig_config = qid_http::middleware::HttpMessageSignatureConfig {
            shared_secret: config
                .server
                .http_message_signatures
                .shared_secret
                .clone()
                .unwrap_or_default()
                .into_bytes(),
            key_id: config.server.http_message_signatures.key_id.clone(),
            keys: config
                .server
                .http_message_signatures
                .keys
                .iter()
                .map(|key| qid_http::middleware::HttpMessageSignatureKey {
                    key_id: key.key_id.clone(),
                    shared_secret: key.shared_secret.clone().into_bytes(),
                })
                .collect(),
            max_age_seconds: config.server.http_message_signatures.max_age_seconds,
            require_content_digest: config.server.http_message_signatures.require_content_digest,
        };
        signed_oauth_routes::<AnyRepository>(paths)
            .route_layer(axum::middleware::from_fn_with_state(
                sig_config,
                qid_http::middleware::http_message_signatures_layer,
            ))
            .merge(unsigned_oauth_routes::<AnyRepository>(paths))
    } else {
        oauth_routes::<AnyRepository>(paths)
    };

    let mut app = Router::<AppState>::new()
        .route(&paths.health, get(health_handler))
        .route(&paths.ready, get(ready_handler))
        .route(&paths.jwks, get(jwks_handler))
        .merge(oidc_routes::<AnyRepository>(paths))
        .merge(oauth_router)
        .merge(qid_admin::admin_routes::<AnyRepository>(paths))
        .merge(auth_routes_with_push::<AnyRepository>(paths))
        .merge(qid_session::totp_api::totp_routes::<AnyRepository>(paths))
        .merge(qid_directory::directory_routes::<AnyRepository>())
        .merge(qid_risk::risk_routes::<AnyRepository>())
        .merge(qid_iga::iga_routes::<AnyRepository>())
        .merge(captive_portal_routes::<AnyRepository>(paths));

    app = merge_optional_protocol_routes(app, &config, &state);

    if matches!(config.profile, DeploymentProfile::Vc) {
        app = app.merge(qid_vc::vc_routes::<AnyRepository>());
    }

    let app = app
        .layer(axum::middleware::from_fn(request_id_layer))
        .layer(axum::middleware::from_fn(http_metrics_layer))
        .layer(axum::middleware::from_fn(qid_http::csrf_protection_layer))
        .layer(axum::middleware::from_fn(qid_http::csp_headers_layer))
        .layer(axum::middleware::from_fn(
            qid_http::zero_rtt_rejection_layer,
        ))
        .layer(axum::middleware::from_fn(qid_http::hsts_layer))
        .layer(axum::middleware::from_fn(
            qid_http::security_headers_middleware,
        ))
        .layer(qid_http::cors_layer(&config.server.cors))
        .with_state(state.clone());

    let addr: std::net::SocketAddr =
        state
            .plan
            .listen
            .parse()
            .map_err(|e| qid_core::error::QidError::Config {
                message: format!("invalid listen address {}: {e}", state.plan.listen),
            })?;
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        qid_core::error::QidError::Internal {
            message: format!("failed to bind to {addr}: {e}"),
        }
    })?;

    let shutdown = async move {
        shutdown_signal().await;
        for sender in network_aaa_shutdown {
            let _ = sender.send(());
        }
    };

    if let Some(tls) = &config.server.tls {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert, &tls.key)
            .await
            .context("failed to load TLS configuration")?;
        let std_listener = listener.into_std().context("failed to convert listener")?;
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            info!("initiating graceful shutdown (TLS)");
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
        info!(tls = true, "listening with TLS");
        axum_server::from_tcp_rustls(std_listener, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("server error: {e}"),
            })?;
    } else {
        info!(tls = false, "listening without TLS");
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.await;
                info!("initiating graceful shutdown");
            })
            .await
            .map_err(|e| qid_core::error::QidError::Internal {
                message: format!("server error: {e}"),
            })?;
    }

    repo.flush()
        .await
        .context("failed to flush storage during shutdown")?;

    Ok(())
}

fn build_shared_cache(config: &QidConfig) -> anyhow::Result<Arc<dyn SharedCache>> {
    let cache_config = &config.ops.cache;
    let inner: Arc<dyn SharedCache> = match cache_config.kind.as_str() {
        "disabled" => Arc::new(MemoryCache::new()),
        "redis" | "valkey" => {
            let endpoint = cache_config
                .endpoints
                .first()
                .context("ops.cache endpoints must not be empty")?;
            Arc::new(
                qid_core::redis_cache::RedisCache::new(endpoint).with_context(|| {
                    format!("failed to connect shared cache endpoint {endpoint}")
                })?,
            )
        }
        other => bail!("unsupported ops.cache.kind: {other}"),
    };
    Ok(Arc::new(PrefixedSharedCache::new(
        &cache_config.key_prefix,
        inner,
    )))
}

fn file_flush_mode(config: &QidConfig) -> anyhow::Result<FileFlushMode> {
    match config.storage.file.flush_interval_ms()? {
        Some(interval_ms) => Ok(FileFlushMode::Interval(std::time::Duration::from_millis(
            interval_ms,
        ))),
        None => Ok(FileFlushMode::Immediate),
    }
}

fn warn_when_file_storage_uses_distributed_cache(config: &QidConfig, storage_url: &str) {
    if !file_storage_uses_distributed_cache(config, storage_url) {
        return;
    }
    let cache_kind = config.ops.cache.kind.as_str();
    let storage_type = config.storage.primary.r#type.as_str();
    tracing::warn!(
        storage_type,
        cache_kind,
        "file storage with distributed cache is not multi-process safe; use SQL storage for multi-instance deployments"
    );
}

fn file_storage_uses_distributed_cache(config: &QidConfig, storage_url: &str) -> bool {
    let cache_kind = config.ops.cache.kind.as_str();
    if !matches!(cache_kind, "redis" | "valkey") {
        return false;
    }
    let storage_type = config.storage.primary.r#type.as_str();
    storage_type == "file"
        || (!storage_url.starts_with("sqlite:") && !storage_url.starts_with("postgres:"))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        shutdown_signal_unix().await;
    }

    #[cfg(not(unix))]
    {
        shutdown_signal_portable().await;
    }
}

#[cfg(unix)]
async fn shutdown_signal_unix() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {
            info!("received SIGINT (Ctrl+C), shutting down");
        }
        _ = sigterm_stream.recv() => {
            info!("received SIGTERM, shutting down");
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal_portable() {
    if tokio::signal::ctrl_c().await.is_ok() {
        info!("received interrupt signal, shutting down");
    }
}

async fn start_network_aaa_listeners(
    config: &QidConfig,
    repo: Arc<AnyRepository>,
) -> anyhow::Result<Vec<oneshot::Sender<()>>> {
    if !matches!(config.profile, DeploymentProfile::NetworkAaa) {
        return Ok(Vec::new());
    }

    let mut shutdown_senders = Vec::new();
    for realm in &config.realms {
        let network_aaa = &realm.protocols.network_aaa;
        if !network_aaa.radius {
            continue;
        }
        let shared_secret = network_aaa
            .shared_secret
            .as_deref()
            .context("network-aaa shared_secret is required")?
            .as_bytes()
            .to_vec();
        let authorizer = build_radius_authorizer(repo.clone(), &realm.id, network_aaa.eap_tls)
            .await
            .with_context(|| format!("failed to build RADIUS authorizer for realm {}", realm.id))?;

        let auth_bind = parse_network_bind(
            network_aaa.radius_authentication_bind.as_deref(),
            "radius_authentication_bind",
            &realm.id,
        )?;
        let auth_socket = tokio::net::UdpSocket::bind(auth_bind)
            .await
            .with_context(|| {
                format!(
                    "failed to bind RADIUS authentication listener for realm {}",
                    realm.id
                )
            })?;
        let (auth_tx, auth_rx) = oneshot::channel();
        shutdown_senders.push(auth_tx);
        let auth_secret = shared_secret.clone();
        let auth_realm = realm.id.clone();
        tokio::spawn(async move {
            info!(realm = %auth_realm, bind = %auth_bind, "starting RADIUS authentication listener");
            if let Err(error) = qid_network::server::run_radius_server_with_socket(
                auth_socket,
                auth_secret,
                authorizer,
                auth_rx,
            )
            .await
            {
                tracing::error!(realm = %auth_realm, error = %error, "RADIUS authentication listener stopped");
            }
        });

        if network_aaa.accounting {
            let accounting_bind = parse_network_bind(
                network_aaa.accounting_bind.as_deref(),
                "accounting_bind",
                &realm.id,
            )?;
            let accounting_socket = tokio::net::UdpSocket::bind(accounting_bind)
                .await
                .with_context(|| {
                    format!(
                        "failed to bind RADIUS accounting listener for realm {}",
                        realm.id
                    )
                })?;
            let (accounting_tx, accounting_rx) = oneshot::channel();
            shutdown_senders.push(accounting_tx);
            let accounting_secret = shared_secret.clone();
            let accounting_realm = realm.id.clone();
            tokio::spawn(async move {
                info!(realm = %accounting_realm, bind = %accounting_bind, "starting RADIUS accounting listener");
                if let Err(error) = qid_network::server::run_radius_accounting_server_with_socket(
                    accounting_socket,
                    accounting_secret,
                    accounting_rx,
                )
                .await
                {
                    tracing::error!(realm = %accounting_realm, error = %error, "RADIUS accounting listener stopped");
                }
            });
        }

        if network_aaa.coa {
            let coa_bind =
                parse_network_bind(network_aaa.coa_bind.as_deref(), "coa_bind", &realm.id)?;
            let coa_socket = tokio::net::UdpSocket::bind(coa_bind)
                .await
                .with_context(|| {
                    format!("failed to bind RADIUS CoA listener for realm {}", realm.id)
                })?;
            let (coa_tx, coa_rx) = oneshot::channel();
            shutdown_senders.push(coa_tx);
            let coa_secret = shared_secret.clone();
            let coa_realm = realm.id.clone();
            tokio::spawn(async move {
                info!(realm = %coa_realm, bind = %coa_bind, "starting RADIUS CoA listener");
                if let Err(error) = qid_network::server::run_radius_coa_server_with_socket(
                    coa_socket, coa_secret, coa_rx,
                )
                .await
                {
                    tracing::error!(realm = %coa_realm, error = %error, "RADIUS CoA listener stopped");
                }
            });
        }

        if network_aaa.radius_tls {
            let tls_bind = network_aaa
                .radius_tls_bind
                .clone()
                .context("network-aaa radius_tls_bind is required")?;
            let tls_listener = tokio::net::TcpListener::bind(&tls_bind)
                .await
                .with_context(|| {
                    format!("failed to bind RADIUS/TLS listener for realm {}", realm.id)
                })?;
            let certificate_der = read_network_aaa_material(
                network_aaa.radius_tls_certificate_path.as_deref(),
                "radius_tls_certificate_path",
                &realm.id,
            )
            .await?;
            let private_key_der = read_network_aaa_material(
                network_aaa.radius_tls_private_key_path.as_deref(),
                "radius_tls_private_key_path",
                &realm.id,
            )
            .await?;
            let client_ca_certificate_der = Some(
                read_network_aaa_material(
                    network_aaa.radius_tls_client_ca_path.as_deref(),
                    "radius_tls_client_ca_path",
                    &realm.id,
                )
                .await?,
            );
            let (tls_tx, tls_rx) = oneshot::channel();
            shutdown_senders.push(tls_tx);
            let tls_realm = realm.id.clone();
            let tls_config = qid_network::radius_tls::RadiusTlsServerConfig {
                bind_address: tls_bind.clone(),
                certificate_der,
                private_key_der,
                client_ca_certificate_der,
                shared_secret,
            };
            qid_network::radius_tls::validate_radius_tls_server_config(&tls_config).with_context(
                || format!("invalid RADIUS/TLS configuration for realm {}", realm.id),
            )?;
            tokio::spawn(async move {
                info!(realm = %tls_realm, bind = %tls_bind, "starting RADIUS/TLS listener");
                if let Err(error) =
                    qid_network::radius_tls::run_radius_over_tls_server_with_listener(
                        tls_config,
                        tls_listener,
                        tls_rx,
                    )
                    .await
                {
                    tracing::error!(realm = %tls_realm, error = %error, "RADIUS/TLS listener stopped");
                }
            });
        }
    }

    Ok(shutdown_senders)
}

async fn build_radius_authorizer(
    repo: Arc<AnyRepository>,
    realm_id: &str,
    require_eap_tls: bool,
) -> anyhow::Result<qid_network::server::RadiusAccessAuthorizer> {
    let realm = RealmId::from(realm_id);
    let users = repo.list_users(&realm).await?;
    let mut allowed_subjects = HashSet::new();
    for user in users {
        allowed_subjects.insert(user.id);
        if let Some(email) = user.email {
            allowed_subjects.insert(email);
        }
    }
    Ok(Arc::new(move |user_name, request| {
        if require_eap_tls
            && !request
                .attributes
                .iter()
                .any(|attr| attr.kind == qid_network::server::attrs::EAP_MESSAGE)
        {
            return qid_network::server::RadiusAccessDecision::Reject {
                reply_message: "EAP-TLS evidence is required".to_string(),
            };
        }
        if allowed_subjects.contains(user_name) {
            qid_network::server::RadiusAccessDecision::Accept {
                reply_message: "access accepted by directory authority".to_string(),
                session_timeout_seconds: Some(3600),
            }
        } else {
            qid_network::server::RadiusAccessDecision::Reject {
                reply_message: "subject is not present in directory authority".to_string(),
            }
        }
    }))
}

fn parse_network_bind(
    value: Option<&str>,
    field: &str,
    realm_id: &str,
) -> anyhow::Result<std::net::SocketAddr> {
    let value =
        value.with_context(|| format!("network-aaa {field} is required for realm {realm_id}"))?;
    value.parse().with_context(|| {
        format!("network-aaa {field} is not a valid socket address for realm {realm_id}: {value}")
    })
}

async fn read_network_aaa_material(
    path: Option<&str>,
    field: &str,
    realm_id: &str,
) -> anyhow::Result<Vec<u8>> {
    let path =
        path.with_context(|| format!("network-aaa {field} is required for realm {realm_id}"))?;
    tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read network-aaa {field} for realm {realm_id}: {path}"))
}

fn merge_optional_protocol_routes(
    mut app: Router<AppState>,
    config: &QidConfig,
    state: &AppState,
) -> Router<AppState> {
    let paths = &config.server.paths;
    let surfaces = optional_protocol_route_surfaces(config);
    app = app.merge(qid_resource::device_routes::<AnyRepository>());
    if matches!(config.profile, DeploymentProfile::Workload) {
        app = app.merge(qid_resource::workload_routes::<AnyRepository>());
        app = app.merge(qid_resource::spiffe_routes::<AnyRepository>(paths));
    }

    if surfaces.proxy {
        app = app
            .route(&paths.assertion, get(issue_assertion::<AnyRepository>))
            .merge(pep_decision_routes::<AnyRepository>(paths));
    }
    if surfaces.saml {
        app = app.merge(qid_saml::saml_routes::<AnyRepository>());
    }
    if surfaces.scim {
        let mut scim_base_paths = config
            .realms
            .iter()
            .filter(|realm| realm.protocols.scim.enabled)
            .map(|realm| realm.protocols.scim.base_path.clone())
            .collect::<Vec<_>>();
        scim_base_paths.sort();
        scim_base_paths.dedup();
        for scim_base_path in scim_base_paths {
            let scim_router = qid_scim::scim_routes_at::<AnyRepository>(&scim_base_path).layer(
                middleware::from_fn_with_state(state.clone(), scim_resource_server_auth),
            );
            app = app.merge(scim_router);
        }
    }
    if surfaces.fedcm {
        app = app.merge(qid_resource::fedcm_routes::<AnyRepository>());
    }
    if surfaces.federation {
        app = app.merge(qid_federation::federation_routes::<AnyRepository>());
    }
    if surfaces.par {
        app = app.merge(qid_resource::par_routes::<AnyRepository>(paths));
    }
    if surfaces.ssf {
        qid_oidc::shared_signals::install_scim_set_publisher(state.clone());
        app = app.merge(qid_oidc::shared_signals::ssf_routes::<AnyRepository>());
    }
    app
}

async fn scim_resource_server_auth(
    State(state): State<AppState>,
    mut request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    let method = request.method().clone();
    let htu = format!(
        "{}{}",
        state.plan.public_base_url.trim_end_matches('/'),
        request.uri().path()
    );
    let token = qid_oauth::endpoints::extract_bearer_token(request.headers())
        .map_err(qid_http::error_response)?;
    let decoded = qid_oauth::endpoints::decode_access_token(&state, token)
        .await
        .map_err(qid_http::error_response)?;
    qid_oauth::endpoints::enforce_sender_constrained_access_token(
        &state,
        request.headers(),
        &method,
        &htu,
        token,
        &decoded,
    )
    .map_err(qid_http::error_response)?;
    let realm = state
        .config
        .realms
        .iter()
        .find(|realm| realm.id == decoded.realm_id)
        .ok_or_else(|| {
            qid_http::error_response(qid_core::error::QidError::Unauthorized {
                message: "SCIM token realm is not configured".to_string(),
            })
        })?;
    if !realm.protocols.scim.enabled {
        return Err(qid_http::error_response(
            qid_core::error::QidError::Unauthorized {
                message: "SCIM is disabled for token realm".to_string(),
            },
        ));
    }
    let scopes = decoded
        .scope
        .split_whitespace()
        .collect::<std::collections::HashSet<_>>();
    if !scopes.contains("scim") && !scopes.contains("scim.read") && !scopes.contains("scim.write") {
        return Err(qid_http::error_response(
            qid_core::error::QidError::Unauthorized {
                message: "SCIM requires scim scope".to_string(),
            },
        ));
    }
    let write_method = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );
    if write_method && !(scopes.contains("scim") || scopes.contains("scim.write")) {
        return Err(qid_http::error_response(
            qid_core::error::QidError::Unauthorized {
                message: "SCIM write requests require scim.write scope".to_string(),
            },
        ));
    }
    if !(write_method || scopes.contains("scim") || scopes.contains("scim.read")) {
        return Err(qid_http::error_response(
            qid_core::error::QidError::Unauthorized {
                message: "SCIM read requests require scim.read scope".to_string(),
            },
        ));
    }
    let bound_resource_server = realm.protocols.oauth.resource_servers.iter().any(|server| {
        let scope_allowed = server
            .scopes
            .iter()
            .any(|scope| matches!(scope.as_str(), "scim" | "scim.read" | "scim.write"));
        scope_allowed
            && (decoded
                .aud
                .iter()
                .any(|audience| audience == &server.audience)
                || decoded
                    .resource
                    .iter()
                    .any(|resource| server.resources.iter().any(|allowed| allowed == resource)))
    });
    if !bound_resource_server {
        return Err(qid_http::error_response(
            qid_core::error::QidError::Unauthorized {
                message: "SCIM token is not bound to a configured SCIM resource server".to_string(),
            },
        ));
    }
    request
        .extensions_mut()
        .insert(qid_scim::ScimRequestContext {
            realm_id: decoded.realm_id,
        });
    Ok(next.run(request).await)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct OptionalProtocolRouteSurfaces {
    proxy: bool,
    saml: bool,
    scim: bool,
    fedcm: bool,
    federation: bool,
    par: bool,
    ssf: bool,
}

fn optional_protocol_route_surfaces(config: &QidConfig) -> OptionalProtocolRouteSurfaces {
    OptionalProtocolRouteSurfaces {
        proxy: config
            .realms
            .iter()
            .any(|realm| realm.pep_registrations.enabled),
        saml: config
            .realms
            .iter()
            .any(|realm| realm.protocols.saml.enabled),
        scim: config
            .realms
            .iter()
            .any(|realm| realm.protocols.scim.enabled),
        fedcm: config
            .realms
            .iter()
            .any(|realm| realm.protocols.fedcm.enabled),
        federation: config
            .realms
            .iter()
            .any(|realm| realm.protocols.federation.enabled),
        par: config
            .realms
            .iter()
            .any(|realm| realm.protocols.oauth.par.enabled),
        ssf: matches!(config.profile, DeploymentProfile::EdgePep)
            || config
                .realms
                .iter()
                .any(|realm| realm.pep_registrations.enabled),
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn ready_handler() -> &'static str {
    "ready"
}

async fn jwks_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.jwks.clone())
}

async fn seed_configured_realms_and_clients(
    repo: &AnyRepository,
    config: &QidConfig,
    config_path: &Path,
) -> anyhow::Result<()> {
    let existing_realms = repo
        .list_realms()
        .await
        .context("failed to list configured realms")?;
    for realm in &config.realms {
        match existing_realms
            .iter()
            .find(|(realm_id, _)| realm_id == &realm.id)
        {
            Some((_, issuer)) if issuer == &realm.issuer => {}
            Some((_, issuer)) => {
                bail!(
                    "configured realm {} issuer mismatch: storage has {}, config has {}",
                    realm.id,
                    issuer,
                    realm.issuer
                );
            }
            None => {
                repo.create_realm(
                    &TenantId::from("default"),
                    &RealmId::from(realm.id.clone()),
                    &realm.issuer,
                    realm.display_name.as_deref(),
                )
                .await
                .with_context(|| format!("failed to create configured realm {}", realm.id))?;
            }
        }

        for client_config in &realm.clients {
            let expected = static_client_to_model(&realm.id, client_config);
            match repo
                .get_client_by_client_id(&RealmId::from(realm.id.clone()), &expected.client_id)
                .await
                .with_context(|| {
                    format!(
                        "failed to read configured client {} in realm {}",
                        expected.client_id, realm.id
                    )
                })? {
                Some(existing) if client_matches_static_config(&existing, &expected) => {}
                Some(existing) => {
                    bail!(
                        "configured client {} in realm {} differs from storage record {}",
                        expected.client_id,
                        realm.id,
                        existing.id
                    );
                }
                None => {
                    repo.create_client(&expected).await.with_context(|| {
                        format!(
                            "failed to create configured client {} in realm {}",
                            expected.client_id, realm.id
                        )
                    })?;
                }
            }
        }

        for bundle_config in &realm.policy.bundles {
            let compiled_json = read_policy_bundle_source(config_path, &bundle_config.source)
                .await
                .with_context(|| {
                    format!(
                        "failed to read configured policy bundle {} in realm {}",
                        bundle_config.name, realm.id
                    )
                })?;
            let source_hash = stable_source_hash(&compiled_json);
            let existing = repo
                .list_policy_bundles(&RealmId::from(realm.id.clone()))
                .await
                .with_context(|| format!("failed to list policy bundles in realm {}", realm.id))?
                .into_iter()
                .find(|bundle| bundle.name == bundle_config.name);
            match existing {
                Some(bundle)
                    if bundle.source_hash == source_hash
                        && bundle.compiled_json == compiled_json => {}
                Some(bundle) => {
                    bail!(
                        "configured policy bundle {} in realm {} differs from storage record {}",
                        bundle_config.name,
                        realm.id,
                        bundle.id
                    );
                }
                None => {
                    repo.create_policy_bundle(&PolicyBundle {
                        id: format!("{}:{}", realm.id, bundle_config.name),
                        realm_id: realm.id.clone(),
                        name: bundle_config.name.clone(),
                        source_hash,
                        compiled_json,
                        version: 1,
                        active: bundle_config.mode == "enforce",
                    })
                    .await
                    .with_context(|| {
                        format!(
                            "failed to create configured policy bundle {} in realm {}",
                            bundle_config.name, realm.id
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

async fn read_policy_bundle_source(
    config_path: &Path,
    source: &str,
) -> anyhow::Result<serde_json::Value> {
    if source.starts_with("http://") || source.starts_with("https://") {
        bail!("remote policy bundle sources are not supported at startup: {source}");
    }
    let path = if let Some(path) = source.strip_prefix("file://") {
        PathBuf::from(path)
    } else {
        let path = PathBuf::from(source);
        if path.is_absolute() {
            path
        } else {
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
        }
    };
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read policy bundle {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse policy bundle {}", path.display()))
}

fn stable_source_hash(value: &serde_json::Value) -> String {
    let mut hasher = DefaultHasher::new();
    value.to_string().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn static_client_to_model(realm_id: &str, config: &StaticClientConfig) -> Client {
    Client {
        id: config
            .id
            .clone()
            .unwrap_or_else(|| format!("{realm_id}:{}", config.client_id)),
        realm_id: realm_id.to_string(),
        client_id: config.client_id.clone(),
        client_type: config.client_type.clone(),
        token_endpoint_auth_method: config.token_endpoint_auth_method.clone(),
        client_secret_hash: config.client_secret_hash.clone().or_else(|| {
            config
                .client_secret
                .as_deref()
                .map(qid_core::util::client_secret_hash)
        }),
        mtls_certificate_thumbprints: config.mtls_certificate_thumbprints.clone(),
        jwks: config.jwks.clone(),
        redirect_uris: config.redirect_uris.clone(),
        grant_types: config.grant_types.clone(),
        client_name: None,
        client_uri: None,
        logo_uri: None,
        contacts: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        default_max_age: None,
        require_auth_time: false,
        sector_identifier_uri: None,
        subject_type: None,
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        backchannel_client_notification_endpoint: None,
    }
}

fn client_matches_static_config(existing: &Client, expected: &Client) -> bool {
    existing.realm_id == expected.realm_id
        && existing.client_id == expected.client_id
        && existing.client_type == expected.client_type
        && existing.token_endpoint_auth_method == expected.token_endpoint_auth_method
        && existing.client_secret_hash == expected.client_secret_hash
        && existing.mtls_certificate_thumbprints == expected.mtls_certificate_thumbprints
        && existing.jwks == expected.jwks
        && existing.redirect_uris == expected.redirect_uris
        && existing.grant_types == expected.grant_types
}

fn state_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("qid-state")
}

struct SigningMaterial {
    signer: Arc<dyn Signer>,
    pep_assertion_signers: BTreeMap<String, Arc<dyn Signer>>,
    jwks: serde_json::Value,
}

struct WorkloadCaMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

fn load_or_generate_workload_ca(state_dir: &Path) -> anyhow::Result<WorkloadCaMaterial> {
    std::fs::create_dir_all(state_dir)?;
    let cert_path = state_dir.join("workload-ca.pem");
    let key_path = state_dir.join("workload-ca-key.pem");
    if cert_path.exists() && key_path.exists() {
        return Ok(WorkloadCaMaterial {
            certificate_pem: std::fs::read_to_string(cert_path)
                .context("failed to read workload CA certificate")?,
            private_key_pem: std::fs::read_to_string(key_path)
                .context("failed to read workload CA private key")?,
        });
    }
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("failed to generate workload CA key")?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "qid workload CA");
        dn
    };
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let cert = params
        .self_signed(&key_pair)
        .context("failed to generate workload CA certificate")?;
    let certificate_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();
    std::fs::write(&cert_path, &certificate_pem)
        .context("failed to write workload CA certificate")?;
    std::fs::write(&key_path, &private_key_pem)
        .context("failed to write workload CA private key")?;
    Ok(WorkloadCaMaterial {
        certificate_pem,
        private_key_pem,
    })
}

fn initialize_signing_material(
    config: &QidConfig,
    state_dir: &Path,
) -> anyhow::Result<SigningMaterial> {
    let key_protector = key_protector_from_config(config, state_dir)
        .context("failed to initialize signing key protector")?;
    if config.crypto.keyrings.is_empty() {
        let keyring = load_or_generate_local_keyring(
            state_dir,
            "default",
            &config.crypto.default_alg,
            key_protector.as_ref(),
        )
        .context("failed to initialize local signing key")?;
        let signer: Arc<dyn Signer> =
            Arc::new(keyring.active_signer().context("no active signer")?.clone());
        let jwks = serde_json::to_value(keyring.jwks()).unwrap_or_else(|_| json!({ "keys": [] }));
        return Ok(SigningMaterial {
            signer,
            pep_assertion_signers: BTreeMap::new(),
            jwks,
        });
    }

    let primary_index = config
        .crypto
        .keyrings
        .iter()
        .position(|keyring| {
            keyring
                .purposes
                .iter()
                .any(|purpose| purpose == "oidc_token")
        })
        .unwrap_or(0);
    let mut primary_signer: Option<Arc<dyn Signer>> = None;
    let mut pep_assertion_signers: BTreeMap<String, Arc<dyn Signer>> = BTreeMap::new();
    let mut jwks = Vec::new();

    for (idx, configured) in config.crypto.keyrings.iter().enumerate() {
        if configured.signer.r#type != "local" {
            anyhow::bail!(
                "remote signer {} for keyring {} is configured but no remote signer transport is available",
                configured.signer.r#type,
                configured.name
            );
        }

        let keyring = load_or_generate_local_keyring(
            state_dir,
            &configured.name,
            &config.crypto.default_alg,
            key_protector.as_ref(),
        )
        .context("failed to initialize local signing key")?;
        let signer: Arc<dyn Signer> =
            Arc::new(keyring.active_signer().context("no active signer")?.clone());
        if idx == primary_index {
            primary_signer = Some(signer.clone());
        }
        if configured.purposes.len() == 1
            && is_pep_assertion_purpose(&configured.purposes[0])
            && let Some(realm_id) = configured.realm_id.as_deref()
        {
            pep_assertion_signers.insert(realm_id.to_string(), signer.clone());
        }
        let kr_jwks = keyring.jwks();
        append_keyring_jwks(&mut jwks, &kr_jwks)?;
    }

    Ok(SigningMaterial {
        signer: primary_signer.context("no primary signing key")?,
        pep_assertion_signers,
        jwks: json!({ "keys": jwks }),
    })
}

fn is_pep_assertion_purpose(purpose: &str) -> bool {
    matches!(purpose, "pep_assertion")
}

fn append_keyring_jwks(
    jwks: &mut Vec<serde_json::Value>,
    keyring_jwks: &qid_crypto::jwk::JwkSet,
) -> anyhow::Result<()> {
    let value = serde_json::to_value(keyring_jwks)?;
    let keys = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .context("keyring JWKS must contain keys array")?;
    jwks.extend(keys.iter().cloned());
    Ok(())
}

fn load_or_generate_local_keyring(
    state_dir: &Path,
    name: &str,
    algorithm: &str,
    key_protector: Option<&PassphraseProtector>,
) -> anyhow::Result<Keyring> {
    std::fs::create_dir_all(state_dir)?;
    let (private_path, public_path) = signing_key_paths(state_dir, name, algorithm);
    let encrypted_path = encrypted_key_path(&private_path);

    let mut keyring = Keyring::new(name);
    if encrypted_path.exists() {
        let protector = key_protector.with_context(|| {
            format!(
                "encrypted signing key {} requires QID_KEY_PASSPHRASE or crypto.key_passphrase_file",
                encrypted_path.display()
            )
        })?;
        let encrypted = parse_encrypted_key(&std::fs::read_to_string(&encrypted_path)?)
            .context("failed to parse encrypted signing key")?;
        if encrypted.alg != algorithm {
            anyhow::bail!(
                "encrypted signing key {} algorithm {} does not match configured algorithm {}",
                encrypted_path.display(),
                encrypted.alg,
                algorithm
            );
        }
        let private_pem = protector
            .unseal(&encrypted)
            .context("failed to decrypt signing key")?;
        load_local_key(&mut keyring, name, algorithm, &private_pem)?;
    } else if private_path.exists() {
        let private_pem = Zeroizing::new(std::fs::read_to_string(&private_path)?);
        if let Some(protector) = key_protector {
            let encrypted = protector
                .seal(&private_pem, name, algorithm)
                .context("failed to encrypt existing signing key")?;
            std::fs::write(&encrypted_path, serialize_encrypted_key(&encrypted)?)
                .context("failed to write encrypted signing key")?;
            let backup_path = backup_key_path(&private_path);
            std::fs::rename(&private_path, &backup_path)
                .context("failed to move plaintext signing key to backup")?;
            tracing::warn!(
                plaintext_key = %private_path.display(),
                encrypted_key = %encrypted_path.display(),
                backup_key = %backup_path.display(),
                "migrated plaintext signing key to encrypted storage"
            );
        }
        load_local_key(&mut keyring, name, algorithm, &private_pem)?;
    } else {
        let mut generated = match algorithm {
            "ES256" => generate_es256(name)?,
            "EdDSA" => generate_eddsa(name)?,
            other => anyhow::bail!("local signer algorithm {other} is not supported"),
        };
        if let Some(protector) = key_protector {
            let encrypted = protector
                .seal(&generated.private_pem, name, algorithm)
                .context("failed to encrypt generated signing key")?;
            std::fs::write(&encrypted_path, serialize_encrypted_key(&encrypted)?)
                .context("failed to write encrypted signing key")?;
        } else {
            std::fs::write(&private_path, &generated.private_pem)?;
        }
        std::fs::write(&public_path, &generated.public_pem)?;
        load_local_key(&mut keyring, name, algorithm, &generated.private_pem)?;
        generated.private_pem.zeroize();
    }
    load_successor_keyring_key(state_dir, name, algorithm, key_protector, &mut keyring)?;
    Ok(keyring)
}

fn load_successor_keyring_key(
    state_dir: &Path,
    name: &str,
    algorithm: &str,
    key_protector: Option<&PassphraseProtector>,
    keyring: &mut Keyring,
) -> anyhow::Result<()> {
    let safe_name = safe_keyring_file_component(name);
    let safe_algorithm = safe_keyring_file_component(algorithm);
    let prefix = format!("signing-key-{safe_name}-{safe_algorithm}-");
    let suffix = ".pem.enc";
    let successor_paths = std::fs::read_dir(state_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(suffix))
        })
        .collect::<Vec<_>>();
    if successor_paths.is_empty() {
        return Ok(());
    }
    if successor_paths.len() > 1 {
        anyhow::bail!(
            "multiple successor signing keys found for keyring {name}; keep exactly one successor file"
        );
    }
    let successor_path = &successor_paths[0];
    let protector = key_protector.with_context(|| {
        format!(
            "successor signing key {} requires QID_KEY_PASSPHRASE or crypto.key_passphrase_file",
            successor_path.display()
        )
    })?;
    let encrypted = parse_encrypted_key(&std::fs::read_to_string(successor_path)?)
        .context("failed to parse encrypted successor signing key")?;
    if encrypted.alg != algorithm {
        anyhow::bail!(
            "successor signing key {} algorithm {} does not match configured algorithm {}",
            successor_path.display(),
            encrypted.alg,
            algorithm
        );
    }
    if encrypted.kid == keyring.active_kid() {
        return Ok(());
    }
    let private_pem = protector
        .unseal(&encrypted)
        .context("failed to decrypt successor signing key")?;
    load_local_successor_key(keyring, &encrypted.kid, algorithm, &private_pem)?;
    tracing::info!(
        keyring = name,
        kid = %encrypted.kid,
        "loaded successor signing key"
    );
    Ok(())
}

fn key_protector_from_config(
    config: &QidConfig,
    state_dir: &Path,
) -> anyhow::Result<Option<PassphraseProtector>> {
    if let Ok(passphrase) = std::env::var("QID_KEY_PASSPHRASE")
        && !passphrase.is_empty()
    {
        return Ok(Some(PassphraseProtector::new(passphrase.into_bytes())?));
    }
    let Some(path) = config.crypto.key_passphrase_file.as_deref() else {
        return Ok(None);
    };
    let path = resolve_config_relative_path(state_dir, path);
    let passphrase = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read key passphrase file {}", path.display()))?;
    let passphrase = passphrase
        .trim_end_matches(['\r', '\n'])
        .as_bytes()
        .to_vec();
    Ok(Some(PassphraseProtector::new(passphrase)?))
}

fn resolve_config_relative_path(state_dir: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        return path;
    }
    state_dir
        .parent()
        .map(|parent| parent.join(&path))
        .unwrap_or(path)
}

fn load_local_key(
    keyring: &mut Keyring,
    kid: &str,
    algorithm: &str,
    private_pem: &str,
) -> anyhow::Result<()> {
    match algorithm {
        "ES256" => {
            keyring.load_es256(kid, private_pem)?;
            Ok(())
        }
        "EdDSA" => {
            keyring.load_eddsa(kid, private_pem)?;
            Ok(())
        }
        other => anyhow::bail!("local signer algorithm {other} is not supported"),
    }
}

fn load_local_successor_key(
    keyring: &mut Keyring,
    kid: &str,
    algorithm: &str,
    private_pem: &str,
) -> anyhow::Result<()> {
    match algorithm {
        "ES256" => {
            keyring.load_next_es256(kid, private_pem)?;
            Ok(())
        }
        "EdDSA" => {
            keyring.load_next_eddsa(kid, private_pem)?;
            Ok(())
        }
        other => anyhow::bail!("local signer algorithm {other} is not supported"),
    }
}

fn signing_key_paths(state_dir: &Path, name: &str, algorithm: &str) -> (PathBuf, PathBuf) {
    if name == "default" && algorithm == "ES256" {
        return (
            state_dir.join("signing-key.pem"),
            state_dir.join("signing-key.pub.pem"),
        );
    }
    let safe_name = safe_keyring_file_component(name);
    let safe_algorithm = safe_keyring_file_component(algorithm);
    (
        state_dir.join(format!("signing-key-{safe_name}-{safe_algorithm}.pem")),
        state_dir.join(format!("signing-key-{safe_name}-{safe_algorithm}.pub.pem")),
    )
}

fn encrypted_key_path(private_path: &Path) -> PathBuf {
    let mut path = private_path.as_os_str().to_os_string();
    path.push(".enc");
    PathBuf::from(path)
}

fn backup_key_path(private_path: &Path) -> PathBuf {
    let mut path = private_path.as_os_str().to_os_string();
    path.push(".bak");
    PathBuf::from(path)
}

fn safe_keyring_file_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "default".to_string()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qid_core::config::{
        AdminConfig, AuthenticationConfig, CorsConfig, CryptoConfig, DeploymentProfile,
        KeyringConfig, ObservabilityConfig, OpsConfig, PepRegistrationsConfig, ProtocolConfig,
        RealmConfig, RotationConfig, ServerConfig, ServerPaths, SignerConfig, StaticClientConfig,
        StorageConfig,
    };
    use qid_core::models::{ClientType, User};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn minimal_config() -> QidConfig {
        QidConfig {
            include: Vec::new(),
            profile: DeploymentProfile::Oidc,
            server: ServerConfig {
                listen: "127.0.0.1:0".to_string(),
                public_base_url: "https://id.example.com".to_string(),
                tls: None,
                http_message_signatures: Default::default(),
                cors: CorsConfig::default(),
                paths: ServerPaths::default(),
            },
            admin: AdminConfig::default(),
            storage: StorageConfig::default(),
            crypto: CryptoConfig::default(),
            realms: vec![RealmConfig {
                id: "corp".to_string(),
                issuer: "https://id.example.com/realms/corp".to_string(),
                display_name: None,
                tenant_id: None,
                clients: Vec::new(),
                protocols: ProtocolConfig::default(),
                authentication: AuthenticationConfig::default(),
                sessions: Default::default(),
                pep_registrations: PepRegistrationsConfig::default(),
                policy: Default::default(),
            }],
            observability: ObservabilityConfig::default(),
            ops: OpsConfig::default(),
        }
    }

    fn test_state_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("qid-qidd-{name}-{suffix}"))
    }

    #[test]
    fn file_storage_distributed_cache_warning_detection() {
        let mut config = minimal_config();
        config.ops.cache.kind = "redis".to_string();
        config.ops.cache.endpoints = vec!["redis://127.0.0.1:6379".to_string()];
        config.storage.primary.r#type = "file".to_string();

        assert!(file_storage_uses_distributed_cache(
            &config,
            "/var/lib/qid/store.json"
        ));

        config.storage.primary.r#type = "sqlite".to_string();
        assert!(!file_storage_uses_distributed_cache(
            &config,
            "sqlite:/var/lib/qid/qid.db"
        ));

        config.ops.cache.kind = "disabled".to_string();
        assert!(!file_storage_uses_distributed_cache(
            &config,
            "/var/lib/qid/store.json"
        ));
    }

    fn network_aaa_config(auth_bind: String) -> QidConfig {
        let mut config = minimal_config();
        config.profile = DeploymentProfile::NetworkAaa;
        let network_aaa = &mut config.realms[0].protocols.network_aaa;
        network_aaa.radius = true;
        network_aaa.radius_authentication_bind = Some(auth_bind);
        network_aaa.shared_secret = Some("0123456789abcdef".to_string());
        config
    }

    async fn test_repo(name: &str) -> (PathBuf, Arc<AnyRepository>) {
        let state_dir = test_state_dir(name);
        let store_path = state_dir.join("store.json");
        let repo = Arc::new(
            AnyRepository::connect(store_path.to_str().expect("valid store path"))
                .await
                .expect("repository should initialize"),
        );
        (state_dir, repo)
    }

    fn free_udp_bind() -> Option<String> {
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("free UDP port: {error}"),
        };
        Some(socket.local_addr().expect("local UDP address").to_string())
    }

    #[test]
    fn default_local_signer_writes_es256_key_path() {
        let config = minimal_config();
        let state_dir = test_state_dir("default");

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");

        assert!(state_dir.join("signing-key.pem").exists());
        assert_eq!(material.signer.algorithm(), "ES256");
        assert_eq!(material.jwks["keys"][0]["kid"], "default");
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn configured_local_eddsa_keyring_is_used() {
        let mut config = minimal_config();
        config.crypto.default_alg = "EdDSA".to_string();
        config.crypto.keyrings = vec![KeyringConfig {
            name: "corp-main".to_string(),
            realm_id: Some("corp".to_string()),
            purposes: vec!["oidc_token".to_string()],
            signer: SignerConfig::default(),
            rotation: RotationConfig::default(),
        }];
        let state_dir = test_state_dir("eddsa");

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");

        assert!(state_dir.join("signing-key-corp-main-EdDSA.pem").exists());
        assert_eq!(material.signer.algorithm(), "EdDSA");
        assert_eq!(material.jwks["keys"][0]["kid"], "corp-main");
        assert_eq!(material.jwks["keys"][0]["alg"], "EdDSA");
        assert!(material.pep_assertion_signers.is_empty());
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn configured_pep_assertion_keyring_is_loaded_as_realm_signer_and_published() {
        let mut config = minimal_config();
        config.crypto.default_alg = "EdDSA".to_string();
        config.crypto.keyrings = vec![
            KeyringConfig {
                name: "corp-main".to_string(),
                realm_id: Some("corp".to_string()),
                purposes: vec!["oidc_token".to_string()],
                signer: SignerConfig::default(),
                rotation: RotationConfig::default(),
            },
            KeyringConfig {
                name: "corp-pep-assertion".to_string(),
                realm_id: Some("corp".to_string()),
                purposes: vec!["pep_assertion".to_string()],
                signer: SignerConfig::default(),
                rotation: RotationConfig::default(),
            },
        ];
        let state_dir = test_state_dir("pep-assertion");

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");

        assert_eq!(material.signer.algorithm(), "EdDSA");
        assert!(material.pep_assertion_signers.contains_key("corp"));
        assert_eq!(
            material
                .pep_assertion_signers
                .get("corp")
                .expect("PEP signer")
                .algorithm(),
            "EdDSA"
        );
        let kids = material.jwks["keys"]
            .as_array()
            .expect("jwks keys")
            .iter()
            .filter_map(|key| key.get("kid").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();
        assert!(kids.contains(&"corp-main"));
        assert!(kids.contains(&"corp-pep-assertion"));
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn passphrase_config_writes_encrypted_local_signing_key() {
        let mut config = minimal_config();
        let state_dir = test_state_dir("encrypted-generate");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let passphrase_path = state_dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "test-passphrase\n").expect("passphrase");
        config.crypto.key_passphrase_file = Some(passphrase_path.display().to_string());

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");

        assert_eq!(material.signer.algorithm(), "ES256");
        assert!(state_dir.join("signing-key.pem.enc").exists());
        assert!(!state_dir.join("signing-key.pem").exists());
        assert!(state_dir.join("signing-key.pub.pem").exists());
        let encrypted =
            std::fs::read_to_string(state_dir.join("signing-key.pem.enc")).expect("encrypted key");
        assert!(!encrypted.contains("PRIVATE KEY"));
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn encrypted_successor_key_is_published_for_jwks_overlap() {
        let mut config = minimal_config();
        config.crypto.keyrings = vec![KeyringConfig {
            name: "corp-main".to_string(),
            realm_id: Some("corp".to_string()),
            purposes: vec!["oidc_token".to_string()],
            signer: SignerConfig::default(),
            rotation: RotationConfig::default(),
        }];
        let state_dir = test_state_dir("encrypted-successor");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let passphrase_path = state_dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "test-passphrase\n").expect("passphrase");
        config.crypto.key_passphrase_file = Some(passphrase_path.display().to_string());

        let protector = PassphraseProtector::new(b"test-passphrase".to_vec()).expect("protector");
        let successor = generate_es256("corp-main-next").expect("successor key");
        let encrypted = protector
            .seal(&successor.private_pem, &successor.kid, "ES256")
            .expect("encrypted successor");
        std::fs::write(
            state_dir.join("signing-key-corp-main-ES256-corp-main-next.pem.enc"),
            serialize_encrypted_key(&encrypted).expect("successor serialization"),
        )
        .expect("successor key file");

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");
        let kids = material.jwks["keys"]
            .as_array()
            .expect("jwks keys")
            .iter()
            .filter_map(|key| key.get("kid").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>();

        assert_eq!(material.signer.algorithm(), "ES256");
        assert!(kids.contains(&"corp-main"));
        assert!(kids.contains(&"corp-main-next"));
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn passphrase_config_migrates_plaintext_local_signing_key() {
        let mut config = minimal_config();
        let state_dir = test_state_dir("encrypted-migrate");
        std::fs::create_dir_all(&state_dir).expect("state dir");
        let passphrase_path = state_dir.join("passphrase.txt");
        std::fs::write(&passphrase_path, "test-passphrase\n").expect("passphrase");
        let generated = generate_es256("default").expect("generated key");
        std::fs::write(state_dir.join("signing-key.pem"), &generated.private_pem)
            .expect("plaintext key");
        std::fs::write(state_dir.join("signing-key.pub.pem"), &generated.public_pem)
            .expect("public key");
        config.crypto.key_passphrase_file = Some(passphrase_path.display().to_string());

        let material =
            initialize_signing_material(&config, &state_dir).expect("signing material failed");

        assert_eq!(material.signer.algorithm(), "ES256");
        assert!(state_dir.join("signing-key.pem.enc").exists());
        assert!(state_dir.join("signing-key.pem.bak").exists());
        assert!(!state_dir.join("signing-key.pem").exists());
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn remote_signer_configuration_fails_closed_at_startup() {
        let mut config = minimal_config();
        config.crypto.keyrings = vec![KeyringConfig {
            name: "corp-main".to_string(),
            realm_id: Some("corp".to_string()),
            purposes: vec!["oidc_token".to_string()],
            signer: SignerConfig {
                r#type: "kms".to_string(),
                uri: Some("kms://alias/qid-corp".to_string()),
                public_jwk: Some(serde_json::json!({
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "y": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "kid": "corp-main",
                    "use": "sig",
                    "alg": "ES256"
                })),
            },
            rotation: RotationConfig::default(),
        }];
        let state_dir = test_state_dir("remote");

        let err = match initialize_signing_material(&config, &state_dir) {
            Ok(_) => panic!("remote signer configuration should fail closed"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("no remote signer transport"));
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[test]
    fn optional_protocol_route_surfaces_follow_realm_capabilities() {
        let mut config = minimal_config();

        assert_eq!(
            optional_protocol_route_surfaces(&config),
            OptionalProtocolRouteSurfaces::default()
        );

        config.realms[0].pep_registrations.enabled = true;
        config.realms[0].protocols.saml.enabled = true;
        config.realms[0].protocols.scim.enabled = true;
        config.realms[0].protocols.scim.cursor_secret =
            Some("0123456789abcdef0123456789abcdef".to_string());
        config.realms[0].protocols.fedcm.enabled = true;
        config.realms[0].protocols.federation.enabled = true;
        config.realms[0].protocols.oauth.par.enabled = true;

        assert_eq!(
            optional_protocol_route_surfaces(&config),
            OptionalProtocolRouteSurfaces {
                proxy: true,
                saml: true,
                scim: true,
                fedcm: true,
                federation: true,
                par: true,
                ssf: true,
            }
        );
    }

    #[tokio::test]
    async fn configured_realms_and_static_clients_are_seeded() {
        let mut config = minimal_config();
        config.realms[0].clients = vec![StaticClientConfig {
            client_id: "web".to_string(),
            id: Some("client-web".to_string()),
            client_type: ClientType::Public,
            token_endpoint_auth_method: "none".to_string(),
            client_secret: None,
            client_secret_hash: None,
            mtls_certificate_thumbprints: Vec::new(),
            jwks: qid_core::models::default_client_jwks(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
        }];
        let state_dir = test_state_dir("seed");
        let store_path = state_dir.join("store.json");
        let repo = AnyRepository::connect(store_path.to_str().expect("valid store path"))
            .await
            .expect("repository should initialize");

        let config_path = state_dir.join("qid.yaml");
        seed_configured_realms_and_clients(&repo, &config, &config_path)
            .await
            .expect("configured seed should succeed");
        seed_configured_realms_and_clients(&repo, &config, &config_path)
            .await
            .expect("configured seed should be idempotent");

        let issuer = repo
            .get_realm_issuer(&RealmId::from("corp"))
            .await
            .expect("realm lookup should succeed");
        assert_eq!(
            issuer.as_deref(),
            Some("https://id.example.com/realms/corp")
        );
        let client = repo
            .get_client_by_client_id(&RealmId::from("corp"), "web")
            .await
            .expect("client lookup should succeed")
            .expect("client should be seeded");
        assert_eq!(client.id, "client-web");
        assert_eq!(
            client.redirect_uris,
            vec!["https://app.example.com/callback"]
        );
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn configured_policy_bundles_are_seeded_from_config_sources() {
        let mut config = minimal_config();
        let state_dir = test_state_dir("policy-seed");
        std::fs::create_dir_all(state_dir.join("policies")).expect("policy directory");
        std::fs::write(
            state_dir.join("policies/authenticated-read.json"),
            serde_json::json!({
                "version": "1",
                "default_decision": "deny",
                "rules": [{
                    "name": "allow-qpx-e2e",
                    "type": "allow",
                    "action": "forward.direct",
                    "resource_host": "*"
                }]
            })
            .to_string(),
        )
        .expect("policy file");
        config.realms[0].policy.bundles = vec![qid_core::config::PolicyBundleConfig {
            name: "authenticated-read".to_string(),
            source: "policies/authenticated-read.json".to_string(),
            mode: "enforce".to_string(),
        }];

        let store_path = state_dir.join("store.json");
        let repo = AnyRepository::connect(store_path.to_str().expect("valid store path"))
            .await
            .expect("repository should initialize");
        let config_path = state_dir.join("qid.yaml");

        seed_configured_realms_and_clients(&repo, &config, &config_path)
            .await
            .expect("configured seed should succeed");
        seed_configured_realms_and_clients(&repo, &config, &config_path)
            .await
            .expect("configured seed should be idempotent");

        let bundle = repo
            .get_active_policy_bundle(&RealmId::from("corp"))
            .await
            .expect("policy lookup should succeed")
            .expect("policy bundle should be seeded");
        assert_eq!(bundle.name, "authenticated-read");
        assert_eq!(bundle.compiled_json["rules"][0]["name"], "allow-qpx-e2e");
        assert_eq!(bundle.version, 1);
        assert!(bundle.active);
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn network_aaa_listener_bind_failure_fails_startup() {
        let config = network_aaa_config("192.0.2.1:1812".to_string());
        let (state_dir, repo) = test_repo("network-aaa-bind-failure").await;

        let err = start_network_aaa_listeners(&config, repo)
            .await
            .expect_err("bind conflict must fail startup");
        assert!(
            err.to_string()
                .contains("failed to bind RADIUS authentication listener"),
            "{err}"
        );
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn network_aaa_listener_shutdown_releases_udp_bind() {
        let Some(bind) = free_udp_bind() else {
            return;
        };
        let config = network_aaa_config(bind.clone());
        let (state_dir, repo) = test_repo("network-aaa-shutdown").await;

        let senders = start_network_aaa_listeners(&config, repo)
            .await
            .expect("network-aaa listener should start");
        assert_eq!(senders.len(), 1);
        for sender in senders {
            let _ = sender.send(());
        }

        let mut released = false;
        for _ in 0..20 {
            if tokio::net::UdpSocket::bind(&bind).await.is_ok() {
                released = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(released, "network-aaa shutdown did not release {bind}");
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn network_aaa_listener_missing_config_fails_startup() {
        let bind = "127.0.0.1:1812".to_string();
        let mut config = network_aaa_config(bind);
        config.realms[0].protocols.network_aaa.shared_secret = None;
        let (state_dir, repo) = test_repo("network-aaa-missing-config").await;

        let err = start_network_aaa_listeners(&config, repo)
            .await
            .expect_err("missing shared secret must fail startup");
        assert!(err.to_string().contains("shared_secret"), "{err}");
        std::fs::remove_dir_all(&state_dir).ok();
    }

    #[tokio::test]
    async fn network_aaa_authorizer_uses_stored_directory_users() {
        let (state_dir, repo) = test_repo("network-aaa-authorizer").await;
        repo.create_user(&User {
            id: "user-alice".to_string(),
            realm_id: "corp".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            display_name: Some("Alice".to_string()),
            failed_login_attempts: 0,
            locked_until: None,
            org: None,
        })
        .await
        .expect("user should be stored");

        let authorizer = build_radius_authorizer(repo, "corp", false)
            .await
            .expect("authorizer should build");
        let request = qid_network::RadiusPacket {
            code: qid_network::RadiusCode::AccessRequest,
            identifier: 1,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        };
        assert!(matches!(
            authorizer("alice@example.com", &request),
            qid_network::server::RadiusAccessDecision::Accept { .. }
        ));
        assert!(matches!(
            authorizer("mallory@example.com", &request),
            qid_network::server::RadiusAccessDecision::Reject { .. }
        ));
        std::fs::remove_dir_all(&state_dir).ok();
    }
}
