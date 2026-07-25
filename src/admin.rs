use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{OriginalUri, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use blake2::{
    Blake2b512, Blake2bMac512, Digest,
    digest::{KeyInit, Mac},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tracing::{info, warn};

use crate::{config::Config, server, sublink::SublinkService};

pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
const ADMIN_SESSION_COOKIE: &str = "sing_box_ser_mini_session";
const ADMIN_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCredentialsFile {
    users: Vec<AdminCredentials>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AdminCredentialsDocument {
    Multiple(AdminCredentialsFile),
    Legacy(AdminCredentials),
}

#[derive(Clone)]
struct AdminState {
    config_path: Arc<PathBuf>,
    token: Arc<Option<Vec<u8>>>,
    credentials_path: Arc<PathBuf>,
    runtime: Arc<RwLock<RuntimeState>>,
    write_lock: Arc<Mutex<()>>,
    credentials_lock: Arc<Mutex<()>>,
    commands: mpsc::Sender<Command>,
    sublink: Arc<SublinkService>,
    webui_listen: Arc<String>,
}

#[derive(Default)]
struct RuntimeState {
    running: bool,
    generation: u64,
    started_at: Option<Instant>,
    listen: Option<String>,
    service_address: Option<String>,
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
    service_address: Option<String>,
    webui_listen: String,
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

#[derive(Serialize)]
struct AdminUsersResponse {
    users: Vec<String>,
}

#[derive(Deserialize)]
struct AddAdminUserRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangeAdminPasswordRequest {
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    username: String,
    expires_at: u64,
}

#[derive(Deserialize, Serialize)]
struct SessionClaims {
    username: String,
    expires_at: u64,
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
        credentials_lock: Arc::new(Mutex::new(())),
        commands,
        sublink: Arc::new(SublinkService::with_persistence(
            config_path.with_file_name("hy2-short-links.toml"),
        )?),
        webui_listen: Arc::new(listen.to_string()),
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
            runtime.service_address = Some(
                config
                    .share
                    .as_ref()
                    .map(|share| {
                        if share.server.trim().is_empty() {
                            format!("[{}]:{}", share.ipv6_server, share.port)
                        } else {
                            format!("{}:{}", share.server, share.port)
                        }
                    })
                    .unwrap_or_else(|| config.listen.to_string()),
            );
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
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/status", get(status))
        .route("/api/v1/config", get(get_config).put(put_config))
        .route("/api/v1/reload", post(reload))
        .route(
            "/api/v1/admin-users",
            get(list_admin_users).post(add_admin_user),
        )
        .route(
            "/api/v1/admin-users/{username}",
            axum::routing::put(change_admin_password).delete(delete_admin_user),
        )
        .route("/singbox", get(sublink_singbox))
        .route("/clash", get(sublink_clash))
        .route("/surge", get(sublink_surge))
        .route("/xray", get(sublink_xray))
        .route("/shorten-v2", get(sublink_shorten))
        .route("/shorten-auto", get(sublink_shorten_auto))
        .route("/shorten-hy2", get(sublink_shorten_hy2))
        .route("/sub/{code}", get(sublink_auto))
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

async fn login(
    State(state): State<AdminState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<(HeaderMap, Json<LoginResponse>)> {
    let credentials = load_credentials(&state.credentials_path).map_err(ApiError::internal)?;
    let Some(user) = credentials.users.iter().find(|user| {
        bool::from(request.username.as_bytes().ct_eq(user.username.as_bytes()))
            & bool::from(request.password.as_bytes().ct_eq(user.password.as_bytes()))
    }) else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid username or password",
        ));
    };
    let expires_at = unix_time().saturating_add(ADMIN_SESSION_TTL_SECS);
    let token = issue_session_token(user, expires_at).map_err(ApiError::internal)?;
    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}={token}; Max-Age={ADMIN_SESSION_TTL_SECS}; Path=/; HttpOnly; SameSite=Strict"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        cookie.parse().map_err(ApiError::internal)?,
    );
    Ok((
        headers,
        Json(LoginResponse {
            username: user.username.clone(),
            expires_at,
        }),
    ))
}

async fn logout() -> (HeaderMap, Json<MutationResponse>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        format!("{ADMIN_SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")
            .parse()
            .expect("static logout cookie is valid"),
    );
    (
        headers,
        Json(MutationResponse {
            accepted: true,
            message: "logged out",
        }),
    )
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
        service_address: runtime.service_address.clone(),
        webui_listen: state.webui_listen.as_ref().clone(),
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

async fn list_admin_users(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminUsersResponse>> {
    authorize(&state, &headers).await?;
    let credentials = load_credentials(&state.credentials_path).map_err(ApiError::internal)?;
    Ok(Json(AdminUsersResponse {
        users: credentials
            .users
            .into_iter()
            .map(|user| user.username)
            .collect(),
    }))
}

async fn add_admin_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(request): Json<AddAdminUserRequest>,
) -> ApiResult<Json<MutationResponse>> {
    authorize(&state, &headers).await?;
    let username = request.username.trim().to_owned();
    let user = AdminCredentials {
        username,
        password: request.password,
    };
    ensure_admin_user(&user).map_err(ApiError::bad_request)?;
    let _guard = state.credentials_lock.lock().await;
    let mut credentials = load_credentials(&state.credentials_path).map_err(ApiError::internal)?;
    if credentials
        .users
        .iter()
        .any(|existing| existing.username == user.username)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "admin username already exists",
        ));
    }
    credentials.users.push(user);
    write_credentials(&state.credentials_path, &credentials).map_err(ApiError::internal)?;
    Ok(Json(MutationResponse {
        accepted: true,
        message: "admin user added",
    }))
}

async fn change_admin_password(
    State(state): State<AdminState>,
    AxumPath(username): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<ChangeAdminPasswordRequest>,
) -> ApiResult<Json<MutationResponse>> {
    authorize(&state, &headers).await?;
    let _guard = state.credentials_lock.lock().await;
    let mut credentials = load_credentials(&state.credentials_path).map_err(ApiError::internal)?;
    let Some(user) = credentials
        .users
        .iter_mut()
        .find(|user| user.username == username)
    else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "admin user not found"));
    };
    user.password = request.password;
    ensure_admin_user(user).map_err(ApiError::bad_request)?;
    write_credentials(&state.credentials_path, &credentials).map_err(ApiError::internal)?;
    Ok(Json(MutationResponse {
        accepted: true,
        message: "admin password changed",
    }))
}

async fn delete_admin_user(
    State(state): State<AdminState>,
    AxumPath(username): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<MutationResponse>> {
    authorize(&state, &headers).await?;
    let _guard = state.credentials_lock.lock().await;
    let mut credentials = load_credentials(&state.credentials_path).map_err(ApiError::internal)?;
    if credentials.users.len() <= 1 {
        return Err(ApiError::bad_request(
            "the last admin user cannot be deleted",
        ));
    }
    let previous = credentials.users.len();
    credentials.users.retain(|user| user.username != username);
    if credentials.users.len() == previous {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "admin user not found"));
    }
    write_credentials(&state.credentials_path, &credentials).map_err(ApiError::internal)?;
    Ok(Json(MutationResponse {
        accepted: true,
        message: "admin user deleted",
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
    let selected_rules = uri_parameter(&uri, "selectedRules");
    let ad_block = uri_parameter(&uri, "adblock")
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let whitelist = uri_parameter(&uri, "whitelist");
    let blacklist = uri_parameter(&uri, "blacklist");
    match state.sublink.convert_with_custom_rules(
        format,
        &input,
        selected_rules.as_deref(),
        ad_block,
        whitelist.as_deref(),
        blacklist.as_deref(),
    ) {
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

async fn sublink_shorten_hy2(
    State(state): State<AdminState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(url) = uri_parameter(&uri, "url") else {
        return sublink_error(StatusCode::BAD_REQUEST, "missing URL parameter");
    };
    match state.sublink.shorten_hy2(&url).await {
        Ok(code) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], code).into_response(),
        Err(error) => sublink_error(sublink_status(&error), error),
    }
}

async fn sublink_shorten_auto(
    State(state): State<AdminState>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(url) = uri_parameter(&uri, "url") else {
        return sublink_error(StatusCode::BAD_REQUEST, "missing URL parameter");
    };
    match state.sublink.shorten_auto(&url).await {
        Ok(code) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], code).into_response(),
        Err(error) => sublink_error(sublink_status(&error), error),
    }
}

async fn sublink_auto(
    State(state): State<AdminState>,
    headers: HeaderMap,
    AxumPath(code): AxumPath<String>,
) -> Response {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    match state.sublink.auto(&code, user_agent, accept).await {
        Ok(output) => (
            [
                (header::CONTENT_TYPE, output.content_type),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            output.body,
        )
            .into_response(),
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
    let contents = tokio::fs::read_to_string(state.credentials_path.as_ref())
        .await
        .map_err(ApiError::internal)?;
    let credentials = parse_credentials(&contents).map_err(ApiError::internal)?;
    if session_cookie(headers)
        .is_some_and(|token| validate_session_token(token, &credentials, unix_time()).is_some())
    {
        return Ok(());
    }
    if let Some((username, password)) = decode_basic_credentials(authorization) {
        if credentials.users.iter().any(|user| {
            bool::from(username.as_slice().ct_eq(user.username.as_bytes()))
                & bool::from(password.as_slice().ct_eq(user.password.as_bytes()))
        }) {
            return Ok(());
        }
    }
    Err(ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid username or password",
    ))
}

fn issue_session_token(user: &AdminCredentials, expires_at: u64) -> Result<String> {
    let claims = serde_json::to_vec(&SessionClaims {
        username: user.username.clone(),
        expires_at,
    })
    .context("serialize admin session")?;
    let signature = session_signature(&user.password, &claims)?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(claims),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn validate_session_token(
    token: &str,
    credentials: &AdminCredentialsFile,
    now: u64,
) -> Option<String> {
    let (claims, signature) = token.split_once('.')?;
    let claims = URL_SAFE_NO_PAD.decode(claims).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let claims_document: SessionClaims = serde_json::from_slice(&claims).ok()?;
    if claims_document.expires_at <= now {
        return None;
    }
    let user = credentials
        .users
        .iter()
        .find(|user| user.username == claims_document.username)?;
    let expected = session_signature(&user.password, &claims).ok()?;
    if !bool::from(signature.as_slice().ct_eq(expected.as_slice())) {
        return None;
    }
    Some(claims_document.username)
}

fn session_signature(password: &str, claims: &[u8]) -> Result<Vec<u8>> {
    let key = Blake2b512::digest(password.as_bytes());
    let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(key.as_slice())
        .map_err(|_| anyhow::anyhow!("initialize admin session signer"))?;
    Mac::update(&mut mac, claims);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == ADMIN_SESSION_COOKIE).then_some(value))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

pub fn load_or_create_credentials(path: &Path, username: &str) -> Result<(AdminCredentials, bool)> {
    match load_credentials(path) {
        Ok(credentials) => Ok((credentials.users[0].clone(), false)),
        Err(error) if is_not_found(&error) => {
            let credentials = generated_credentials(username)?;
            write_credentials(
                path,
                &AdminCredentialsFile {
                    users: vec![credentials.clone()],
                },
            )?;
            Ok((credentials, true))
        }
        Err(error) => Err(error),
    }
}

pub fn reset_credentials(path: &Path, username: &str) -> Result<AdminCredentials> {
    let credentials = generated_credentials(username)?;
    let mut file = match load_credentials(path) {
        Ok(file) => file,
        Err(error) if is_not_found(&error) => AdminCredentialsFile { users: Vec::new() },
        Err(error) => return Err(error),
    };
    if let Some(existing) = file
        .users
        .iter_mut()
        .find(|user| user.username == credentials.username)
    {
        existing.password.clone_from(&credentials.password);
    } else {
        file.users.push(credentials.clone());
    }
    write_credentials(path, &file)?;
    Ok(credentials)
}

fn load_credentials(path: &Path) -> Result<AdminCredentialsFile> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read admin credentials {}", path.display()))?;
    parse_credentials(&contents)
        .with_context(|| format!("parse admin credentials {}", path.display()))
}

fn parse_credentials(contents: &str) -> Result<AdminCredentialsFile> {
    let document: AdminCredentialsDocument = toml::from_str(contents)?;
    let credentials = match document {
        AdminCredentialsDocument::Multiple(credentials) => credentials,
        AdminCredentialsDocument::Legacy(user) => AdminCredentialsFile { users: vec![user] },
    };
    ensure_credentials(&credentials)?;
    Ok(credentials)
}

fn generated_credentials(username: &str) -> Result<AdminCredentials> {
    let username = username.trim();
    if username.is_empty() {
        bail!("admin username must not be empty");
    }
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
        username: username.to_owned(),
        password,
    })
}

fn ensure_admin_user(user: &AdminCredentials) -> Result<()> {
    if user.username.trim().is_empty()
        || user.username.len() > 64
        || user.username.contains(':')
        || user.username.chars().any(char::is_control)
    {
        bail!("admin username must be 1-64 characters without colons or control characters");
    }
    if user.password.is_empty() || user.password.len() > 256 {
        bail!("admin password must be 1-256 characters");
    }
    Ok(())
}

fn ensure_credentials(credentials: &AdminCredentialsFile) -> Result<()> {
    if credentials.users.is_empty() {
        bail!("at least one admin user is required");
    }
    for user in &credentials.users {
        ensure_admin_user(user)?;
    }
    for (index, user) in credentials.users.iter().enumerate() {
        if credentials.users[..index]
            .iter()
            .any(|existing| existing.username == user.username)
        {
            bail!("duplicate admin username {}", user.username);
        }
    }
    Ok(())
}

fn write_credentials(path: &Path, credentials: &AdminCredentialsFile) -> Result<()> {
    ensure_credentials(credentials)?;
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

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
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
        let (initial, created) = load_or_create_credentials(&path, DEFAULT_ADMIN_USERNAME).unwrap();
        assert!(created);
        assert_eq!(initial.username, DEFAULT_ADMIN_USERNAME);
        assert_eq!(initial.password.len(), 48);

        let (loaded, created) = load_or_create_credentials(&path, DEFAULT_ADMIN_USERNAME).unwrap();
        assert!(!created);
        assert_eq!(loaded.password, initial.password);

        let reset = reset_credentials(&path, "operator").unwrap();
        assert_eq!(reset.username, "operator");
        assert_ne!(reset.password, initial.password);
        let users = load_credentials(&path).unwrap().users;
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, DEFAULT_ADMIN_USERNAME);
        assert_eq!(users[0].password, initial.password);
        assert_eq!(users[1].password, reset.password);

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
    fn reads_legacy_single_user_credentials() {
        let credentials =
            parse_credentials("username = \"legacy\"\npassword = \"legacy-password\"\n").unwrap();
        assert_eq!(credentials.users.len(), 1);
        assert_eq!(credentials.users[0].username, "legacy");
    }

    #[test]
    fn decodes_basic_credentials() {
        let (username, password) = decode_basic_credentials("Basic YWRtaW46cGFzc3dvcmQ=").unwrap();
        assert_eq!(username, b"admin");
        assert_eq!(password, b"password");
    }

    #[test]
    fn signs_and_expires_admin_sessions() {
        let user = AdminCredentials {
            username: "operator".to_owned(),
            password: "secret".to_owned(),
        };
        let credentials = AdminCredentialsFile {
            users: vec![user.clone()],
        };
        let token = issue_session_token(&user, 86_500).unwrap();
        assert_eq!(
            validate_session_token(&token, &credentials, 100),
            Some("operator".to_owned())
        );
        assert_eq!(validate_session_token(&token, &credentials, 86_500), None);

        let changed = AdminCredentialsFile {
            users: vec![AdminCredentials {
                username: "operator".to_owned(),
                password: "changed".to_owned(),
            }],
        };
        assert_eq!(validate_session_token(&token, &changed, 100), None);

        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            validate_session_token(std::str::from_utf8(&tampered).unwrap(), &credentials, 100),
            None
        );
    }
}
