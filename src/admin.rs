use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tracing::{info, warn};

use crate::{config::Config, server};

#[derive(Clone)]
struct AdminState {
    config_path: Arc<PathBuf>,
    token: Arc<Option<Vec<u8>>>,
    runtime: Arc<RwLock<RuntimeState>>,
    write_lock: Arc<Mutex<()>>,
    commands: mpsc::Sender<Command>,
}

#[derive(Default)]
struct RuntimeState {
    running: bool,
    generation: u64,
    started_at: Option<Instant>,
    listen: Option<String>,
    users: usize,
    udp_enabled: bool,
    obfs: bool,
    up_mbps: u64,
    down_mbps: u64,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    running: bool,
    generation: u64,
    uptime_secs: u64,
    listen: Option<String>,
    users: usize,
    udp_enabled: bool,
    obfs: bool,
    up_mbps: u64,
    down_mbps: u64,
    last_error: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct MutationResponse {
    accepted: bool,
    message: &'static str,
}

#[derive(Clone, Copy)]
enum Command {
    Reload,
}

pub async fn run(config_path: PathBuf, listen: SocketAddr, token: Option<String>) -> Result<()> {
    if !listen.ip().is_loopback() && token.as_deref().is_none_or(str::is_empty) {
        bail!("an admin token is required when the WebUI listens outside loopback");
    }
    let (commands, mut command_rx) = mpsc::channel(4);
    let state = AdminState {
        config_path: Arc::new(config_path.clone()),
        token: Arc::new(token.map(String::into_bytes)),
        runtime: Arc::new(RwLock::new(RuntimeState::default())),
        write_lock: Arc::new(Mutex::new(())),
        commands,
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind management WebUI on {listen}"))?;
    let app = router(state.clone());
    let admin_task = tokio::spawn(async move { axum::serve(listener, app).await });
    info!(%listen, "management WebUI listening");

    let mut generation = 0_u64;
    loop {
        let config = match Config::load(&config_path) {
            Ok(config) => config,
            Err(error) => {
                let mut runtime = state.runtime.write().await;
                runtime.running = false;
                runtime.last_error = Some(error.to_string());
                drop(runtime);
                tokio::select! {
                    command = command_rx.recv() => {
                        if command.is_none() {
                            bail!("management command channel closed");
                        }
                        continue;
                    }
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        };
        generation = generation.saturating_add(1);
        {
            let mut runtime = state.runtime.write().await;
            runtime.running = true;
            runtime.generation = generation;
            runtime.started_at = Some(Instant::now());
            runtime.listen = Some(config.listen.to_string());
            runtime.users = config.users.len();
            runtime.udp_enabled = config.udp.enabled;
            runtime.obfs = config.obfs.is_some();
            runtime.up_mbps = config.bandwidth.up_mbps;
            runtime.down_mbps = config.bandwidth.down_mbps;
            runtime.last_error = None;
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut server_task = tokio::spawn(server::run_until(config, async move {
            let _ = shutdown_rx.await;
        }));
        tokio::select! {
            command = command_rx.recv() => {
                if command.is_none() {
                    bail!("management command channel closed");
                }
                let _ = shutdown_tx.send(());
                finish_server(&mut server_task, &state).await;
            }
            result = &mut server_task => {
                record_server_result(result, &state).await;
                tokio::select! {
                    command = command_rx.recv() => {
                        if command.is_none() {
                            bail!("management command channel closed");
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        admin_task.abort();
                        return Ok(());
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                let _ = shutdown_tx.send(());
                finish_server(&mut server_task, &state).await;
                admin_task.abort();
                return Ok(());
            }
        }
    }
}

async fn finish_server(task: &mut tokio::task::JoinHandle<Result<()>>, state: &AdminState) {
    record_server_result(task.await, state).await;
}

async fn record_server_result(
    result: Result<Result<()>, tokio::task::JoinError>,
    state: &AdminState,
) {
    let error = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(error) => Some(error.to_string()),
    };
    let mut runtime = state.runtime.write().await;
    runtime.running = false;
    runtime.last_error = error.clone();
    if let Some(error) = error {
        warn!(%error, "HY2 server stopped");
    }
}

fn router(state: AdminState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/v1/health", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/reload", post(reload))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    (
        [
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("cache-control", "no-store"),
        ],
        Html(include_str!("../web/index.html")),
    )
}

async fn styles() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE.as_str(), "text/css; charset=utf-8"),
            (header::CACHE_CONTROL.as_str(), "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
        ],
        include_str!("../web/app.css"),
    )
}

async fn script() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE.as_str(),
                "text/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL.as_str(), "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS.as_str(), "nosniff"),
        ],
        include_str!("../web/app.js"),
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn status(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult<Json<StatusResponse>> {
    authorize(&state, &headers)?;
    let runtime = state.runtime.read().await;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        running: runtime.running,
        generation: runtime.generation,
        uptime_secs: runtime
            .started_at
            .map_or(0, |started| started.elapsed().as_secs()),
        listen: runtime.listen.clone(),
        users: runtime.users,
        udp_enabled: runtime.udp_enabled,
        obfs: runtime.obfs,
        up_mbps: runtime.up_mbps,
        down_mbps: runtime.down_mbps,
        last_error: runtime.last_error.clone(),
    }))
}

async fn get_config(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult<Json<Config>> {
    authorize(&state, &headers)?;
    let path = Arc::clone(&state.config_path);
    let config = tokio::task::spawn_blocking(move || Config::load(&path))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::bad_request)?;
    Ok(Json(config))
}

async fn put_config(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(config): Json<Config>,
) -> ApiResult<Json<MutationResponse>> {
    authorize(&state, &headers)?;
    config.validate().map_err(ApiError::bad_request)?;
    let _guard = state.write_lock.lock().await;
    let path = Arc::clone(&state.config_path);
    tokio::task::spawn_blocking(move || config.save_atomic(&path))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    state
        .commands
        .send(Command::Reload)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(MutationResponse {
        accepted: true,
        message: "configuration saved; HY2 service is reloading",
    }))
}

async fn reload(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult<Json<MutationResponse>> {
    authorize(&state, &headers)?;
    Config::load(&state.config_path).map_err(ApiError::bad_request)?;
    state
        .commands
        .send(Command::Reload)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(MutationResponse {
        accepted: true,
        message: "HY2 service is reloading",
    }))
}

fn authorize(state: &AdminState, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = state.token.as_ref() else {
        return Ok(());
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if bool::from(provided.as_bytes().ct_eq(expected)) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid admin token",
        ))
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error.to_string())
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
