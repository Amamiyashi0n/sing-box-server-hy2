use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{OriginalUri, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tracing::{info, warn};

use crate::{config::Config, server, sublink::SublinkService};

const ADMIN_USERNAME: &str = "admin";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
struct AdminState {
    config_path: Arc<PathBuf>,
    token: Arc<Option<Vec<u8>>>,
    credentials_path: Arc<PathBuf>,
    runtime: Arc<RwLock<RuntimeState>>,
    write_lock: Arc<Mutex<()>>,
    commands: mpsc::Sender<Command>,
    sublink: Arc<SublinkService>,
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

pub async fn run(
    config_path: PathBuf,
    listen: SocketAddr,
    token: Option<String>,
    credentials_path: PathBuf,
) -> Result<()> {
    load_credentials(&credentials_path)?;
    let (commands, mut command_rx) = mpsc::channel(4);
    let state = AdminState {
        config_path: Arc::new(config_path.clone()),
        token: Arc::new(token.map(String::into_bytes)),
        credentials_path: Arc::new(credentials_path),
        runtime: Arc::new(RwLock::new(RuntimeState::default())),
        write_lock: Arc::new(Mutex::new(())),
        commands,
        sublink: Arc::new(SublinkService::default()),
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
        .route("/singbox", get(sublink_singbox))
        .route("/clash", get(sublink_clash))
        .route("/surge", get(sublink_surge))
        .route("/xray", get(sublink_xray))
        .route("/shorten-v2", get(sublink_shorten))
        .route("/resolve", get(sublink_resolve))
        .route("/subconverter", get(sublink_subconverter))
        .route("/{prefix}/{code}", get(sublink_redirect))
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
    authorize(&state, &headers).await?;
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
    authorize(&state, &headers).await?;
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
    authorize(&state, &headers).await?;
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
    authorize(&state, &headers).await?;
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

async fn sublink_singbox(state: State<AdminState>, uri: OriginalUri) -> Response {
    sublink_convert("singbox", state, uri)
}

async fn sublink_clash(state: State<AdminState>, uri: OriginalUri) -> Response {
    sublink_convert("clash", state, uri)
}

async fn sublink_surge(state: State<AdminState>, uri: OriginalUri) -> Response {
    sublink_convert("surge", state, uri)
}

async fn sublink_xray(state: State<AdminState>, uri: OriginalUri) -> Response {
    sublink_convert("xray", state, uri)
}

fn sublink_convert(
    format: &str,
    State(state): State<AdminState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(input) = uri_parameter(&uri, "config") else {
        return sublink_error(StatusCode::BAD_REQUEST, "missing config parameter");
    };
    match state.sublink.convert(format, &input) {
        Ok(output) => (
            [
                (header::CONTENT_TYPE, output.content_type),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            output.body,
        )
            .into_response(),
        Err(error) => sublink_error(StatusCode::BAD_REQUEST, error),
    }
}

async fn sublink_shorten(
    State(state): State<AdminState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(url) = uri_parameter(&uri, "url") else {
        return sublink_error(StatusCode::BAD_REQUEST, "missing URL parameter");
    };
    let requested = uri_parameter(&uri, "shortCode");
    match state.sublink.shorten(&url, requested.as_deref()).await {
        Ok(code) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], code).into_response(),
        Err(error) => sublink_error(sublink_status(&error), error),
    }
}

async fn sublink_redirect(
    State(state): State<AdminState>,
    AxumPath((prefix, code)): AxumPath<(String, String)>,
) -> Response {
    match state.sublink.redirect(&prefix, &code).await {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)], "").into_response(),
        Err(error) => sublink_error(sublink_status(&error), error),
    }
}

async fn sublink_resolve(
    State(state): State<AdminState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(url) = uri_parameter(&uri, "url") else {
        return sublink_error(StatusCode::BAD_REQUEST, "missing URL parameter");
    };
    match state.sublink.resolve(&url).await {
        Ok(body) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(error) => sublink_error(sublink_status(&error), error),
    }
}

async fn sublink_subconverter() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "[common]\n; Rust core keeps this endpoint local and dependency-free.\n",
    )
}

fn uri_parameter(uri: &http::Uri, name: &str) -> Option<String> {
    url::form_urlencoded::parse(uri.query()?.as_bytes())
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.into_owned())
}

fn sublink_status(error: &anyhow::Error) -> StatusCode {
    let message = error.to_string();
    if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("disabled") {
        StatusCode::NOT_IMPLEMENTED
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn sublink_error(status: StatusCode, error: impl std::fmt::Display) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        error.to_string(),
    )
        .into_response()
}

async fn authorize(state: &AdminState, headers: &HeaderMap) -> ApiResult<()> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let valid_token = match (state.token.as_ref(), authorization.strip_prefix("Bearer ")) {
        (Some(expected), Some(provided)) => bool::from(provided.as_bytes().ct_eq(expected)),
        _ => false,
    };
    if valid_token {
        return Ok(());
    }
    if let Some((username, password)) = decode_basic_credentials(authorization) {
        let contents = tokio::fs::read_to_string(state.credentials_path.as_ref())
            .await
            .map_err(ApiError::internal)?;
        let credentials: AdminCredentials =
            toml::from_str(&contents).map_err(ApiError::internal)?;
        if bool::from(username.as_slice().ct_eq(credentials.username.as_bytes()))
            & bool::from(password.as_slice().ct_eq(credentials.password.as_bytes()))
        {
            return Ok(());
        }
    }
    Err(ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid username or password",
    ))
}

fn decode_basic_credentials(authorization: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let encoded = authorization.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    Some((
        decoded[..separator].to_vec(),
        decoded[separator + 1..].to_vec(),
    ))
}

pub fn load_or_create_credentials(path: &Path) -> Result<(AdminCredentials, bool)> {
    match load_credentials(path) {
        Ok(credentials) => Ok((credentials, false)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            let credentials = generated_credentials()?;
            write_credentials(path, &credentials)?;
            Ok((credentials, true))
        }
        Err(error) => Err(error),
    }
}

pub fn reset_credentials(path: &Path) -> Result<AdminCredentials> {
    let credentials = generated_credentials()?;
    write_credentials(path, &credentials)?;
    Ok(credentials)
}

fn load_credentials(path: &Path) -> Result<AdminCredentials> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read admin credentials {}", path.display()))?;
    let credentials: AdminCredentials = toml::from_str(&contents)
        .with_context(|| format!("parse admin credentials {}", path.display()))?;
    if credentials.username != ADMIN_USERNAME || credentials.password.is_empty() {
        bail!("admin credentials must use username {ADMIN_USERNAME} and a non-empty password");
    }
    Ok(credentials)
}

fn generated_credentials() -> Result<AdminCredentials> {
    let mut random = [0_u8; 24];
    getrandom::fill(&mut random).context("generate admin password")?;
    let password = random
        .iter()
        .fold(String::with_capacity(48), |mut output, byte| {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
            output
        });
    Ok(AdminCredentials {
        username: ADMIN_USERNAME.to_owned(),
        password,
    })
}

fn write_credentials(path: &Path, credentials: &AdminCredentials) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create admin credential directory {}", parent.display()))?;
    }
    let temporary = path.with_extension("tmp");
    let contents = toml::to_string(credentials).context("serialize admin credentials")?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("write admin credentials {}", temporary.display()))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)
        .with_context(|| format!("replace admin credentials {}", path.display()))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_resets_admin_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.toml");
        let (initial, created) = load_or_create_credentials(&path).unwrap();
        assert!(created);
        assert_eq!(initial.username, ADMIN_USERNAME);
        assert_eq!(initial.password.len(), 48);

        let (loaded, created) = load_or_create_credentials(&path).unwrap();
        assert!(!created);
        assert_eq!(loaded.password, initial.password);

        let reset = reset_credentials(&path).unwrap();
        assert_ne!(reset.password, initial.password);
        assert_eq!(load_credentials(&path).unwrap().password, reset.password);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn decodes_basic_credentials() {
        let (username, password) = decode_basic_credentials("Basic YWRtaW46cGFzc3dvcmQ=").unwrap();
        assert_eq!(username, b"admin");
        assert_eq!(password, b"password");
    }
}
