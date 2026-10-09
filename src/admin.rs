//! Bearer-protected management. OAuth callbacks use their one-time state
//! instead of a custom Authorization header, as required by the browser flow.
use crate::accounts::{AccountError, oauth_login_client};
use crate::gateway::{AppState, error};
use crate::oauth::{BrowserLogin, LoginCancellation, OAuthLogin};
use crate::oauth_contract::OAuthError;
use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::JsonRejection},
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LOGIN_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_LOGINS: usize = 256;
// Fixed 0.160.0 login/src/server.rs:77–80: the CLI Hydra redirect allow-list.
// Never stop an existing owner's listener to obtain these ports.
const BROWSER_CALLBACK_PORTS: [u16; 2] = [1455, 1457];

struct CallbackServer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}
impl Drop for CallbackServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
async fn bind_browser_callback(ports: [u16; 2]) -> std::io::Result<tokio::net::TcpListener> {
    let mut last = None;
    for port in ports {
        match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last = Some(error),
        }
    }
    Err(last.expect("the fixed callback port list is nonempty"))
}
fn callback_server(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    lifetime: Duration,
) -> CallbackServer {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let callback_router = Router::new()
        .route("/auth/callback", get(callback))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, callback_router)
            .with_graceful_shutdown(async move {
                tokio::select! {
                    _ = stopped => {},
                    _ = tokio::time::sleep(lifetime) => {},
                }
            })
            .await;
    });
    CallbackServer { stop: Some(stop) }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Completing,
    Completed,
    Cancelled,
    Failed,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completing => "completing",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}
struct Job {
    account: String,
    proxy: Option<String>,
    created: Instant,
    phase: Phase,
    cancellation: LoginCancellation,
    browser: Option<BrowserLogin>,
    callback_state: Option<String>,
    callback_server: Option<CallbackServer>,
    error: Option<&'static str>,
}
#[derive(Default)]
pub struct AdminState {
    jobs: Mutex<HashMap<String, Job>>,
    pub(crate) codex2api: crate::codex2api::Management,
}
impl AdminState {
    pub fn new() -> Self {
        Self::default()
    }
    fn prune(jobs: &mut HashMap<String, Job>) {
        jobs.retain(|_, job| {
            if job.created.elapsed() > LOGIN_TTL {
                job.cancellation.cancel();
                false
            } else {
                true
            }
        });
    }
}
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(crate::codex2api::router())
        .route("/admin", get(page))
        .route("/admin/api/accounts", get(accounts))
        .route("/admin/api/settings", get(settings).patch(update_settings))
        .route("/admin/api/facts", get(facts))
        .route(
            "/admin/api/telemetry/deliveries",
            get(deliveries).delete(clear_deliveries),
        )
        .route("/admin/api/accounts/{id}", patch(update).delete(delete))
        .route("/admin/api/oauth/device", post(device))
        .route("/admin/api/oauth/browser", post(browser))
        .route("/admin/api/oauth/{job}", get(login_status).delete(cancel))
        .route("/auth/callback", get(callback))
}
#[expect(
    clippy::result_large_err,
    reason = "Preserve the native Axum Response at this HTTP boundary"
)]
fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if crate::admission::admin_authorized(headers, &state.config.client_api_key) {
        Ok(())
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "admin_auth_required",
            "Administrator authentication required",
            "需要管理员认证",
        ))
    }
}
fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "admin_unavailable",
        "Management state unavailable",
        "管理状态暂不可用",
    )
}
fn account_error(value: AccountError) -> Response {
    let (status, code, en, zh) = match value {
        AccountError::NotEnabled => (
            StatusCode::NOT_FOUND,
            "account_not_found",
            "Account not found",
            "账号不存在",
        ),
        AccountError::Deleting => (
            StatusCode::CONFLICT,
            "account_deleting",
            "Account is draining deletion",
            "账号正在排空删除",
        ),
        AccountError::DuplicateOAuthAccount => (
            StatusCode::CONFLICT,
            "duplicate_oauth_account",
            "OAuth account already exists",
            "OAuth 账号已经存在",
        ),
        AccountError::InvalidConfiguration => (
            StatusCode::BAD_REQUEST,
            "invalid_account_settings",
            "Account settings are invalid",
            "账号设置无效",
        ),
        _ => (
            StatusCode::CONFLICT,
            "account_operation_failed",
            "Account operation failed",
            "账号操作失败",
        ),
    };
    error(status, code, en, zh)
}
#[expect(
    clippy::result_large_err,
    reason = "Preserve the native Axum Response at this HTTP boundary"
)]
fn json_input<T>(value: Result<Json<T>, JsonRejection>) -> Result<T, Response> {
    value.map(|v| v.0).map_err(|_| {
        error(
            StatusCode::BAD_REQUEST,
            "invalid_admin_request",
            "Management JSON is invalid",
            "管理请求 JSON 无效",
        )
    })
}
async fn accounts(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    match state.accounts.all() {
        Ok(accounts) => {
            let mut rows = Vec::new();
            for account in accounts {
                let availability = match account.availability() {
                    Ok(v) => v,
                    Err(_) => return unavailable(),
                };
                rows.push(json!({"id":account.id(),"workspace_account_id":account.workspace_account_id(),
                    "created_at_unix_ms":account.created_at_unix_ms(),"proxy_configured":account.proxy().is_some(),
                    "enabled":availability.enabled,"auth_invalid":availability.auth_invalid,"quota_cooldown_until_unix_ms":availability.quota_cooldown_until_unix_ms,"deleting":availability.deleting,"active_requests":availability.active_requests,
                    "max_concurrent_requests":availability.max_concurrent_requests,"resting":availability.resting,"quota_cooldown":availability.quota_cooldown}));
            }
            Json(json!({"accounts":rows})).into_response()
        }
        Err(_) => unavailable(),
    }
}
fn settings_value(s: &crate::config::SchedulingConfig) -> Value {
    json!({"max_sessions_by_account_age":s.max_sessions_by_account_age,"idle_timeout_secs":s.idle_timeout_secs,
        "startup_spacing_secs":s.startup_spacing_secs,"rest_interval_minutes":s.rest_interval_minutes,
        "rest_percent":s.rest_percent,"rest_duration_minutes":s.rest_duration_minutes})
}
async fn settings(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r;
    }
    Json(settings_value(&state.scheduling())).into_response()
}
async fn update_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Result<Json<Value>, JsonRejection>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r;
    }
    let input = match json_input(input) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut merged = settings_value(&state.scheduling());
    let Some(object) = input.as_object() else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_settings",
            "Scheduling settings must be a JSON object",
            "调度设置必须是 JSON 对象",
        );
    };
    for (key, value) in object {
        merged
            .as_object_mut()
            .expect("settings object")
            .insert(key.clone(), value.clone());
    }
    let next = match serde_json::from_value(merged) {
        Ok(v) => v,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_settings",
                "Scheduling settings are invalid",
                "调度设置无效",
            );
        }
    };
    match state.set_scheduling(next) {
        Ok(()) => Json(settings_value(&state.scheduling())).into_response(),
        Err(e) => crate::gateway::protocol_error(e),
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFilter {
    account_id: Option<String>,
}
async fn facts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filter): Query<AccountFilter>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r;
    }
    let facts = state
        .facts
        .snapshot()
        .into_iter()
        .filter(|fact| {
            filter
                .account_id
                .as_deref()
                .is_none_or(|id| fact.account_id == id)
        })
        .collect::<Vec<_>>();
    Json(json!({"facts":facts})).into_response()
}

#[expect(
    clippy::result_large_err,
    reason = "Preserve the native Axum Response at this HTTP boundary"
)]
fn delivery_accounts(
    state: &AppState,
    filter: &AccountFilter,
) -> Result<Vec<Arc<crate::accounts::Account>>, Response> {
    let accounts = state.accounts.all().map_err(|_| unavailable())?;
    if let Some(id) = &filter.account_id {
        let account = accounts
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or_else(|| account_error(AccountError::NotEnabled))?;
        Ok(vec![account])
    } else {
        Ok(accounts)
    }
}
async fn deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filter): Query<AccountFilter>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r;
    }
    let accounts = match delivery_accounts(&state, &filter) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut result = Vec::new();
    for account in accounts {
        match state.metrics.delivery_list(&account).await {
            Ok(entries) => result.push(json!({"account_id":account.id(),"deliveries":entries})),
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "telemetry_queue_unavailable",
                    "Metric delivery queue unavailable",
                    "指标交付队列暂不可用",
                );
            }
        }
    }
    Json(json!({"accounts":result})).into_response()
}
async fn clear_deliveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(filter): Query<AccountFilter>,
) -> Response {
    if let Err(r) = authorize(&state, &headers) {
        return r;
    }
    let accounts = match delivery_accounts(&state, &filter) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut result = Vec::new();
    for account in accounts {
        match state.metrics.clear_delivery(&account).await {
            Ok(report) => result.push(json!({"account_id":account.id(),"cleared":report})),
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "telemetry_queue_unavailable",
                    "Metric delivery queue unavailable",
                    "指标交付队列暂不可用",
                );
            }
        }
    }
    Json(json!({"accounts":result,"business_facts_unchanged":true})).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    enabled: Option<bool>,
    max_concurrent_requests: Option<usize>,
    rest_seconds: Option<u64>,
}
async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    input: Result<Json<Update>, JsonRejection>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let input = match json_input(input) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if input.enabled.is_none()
        && input.max_concurrent_requests.is_none()
        && input.rest_seconds.is_none()
        || input
            .max_concurrent_requests
            .is_some_and(|n| n == 0 || n > 65536)
        || input.rest_seconds.is_some_and(|n| n > 86400)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_account_settings",
            "Account settings are invalid",
            "账号设置无效",
        );
    }
    let result = (|| {
        if let Some(value) = input.enabled {
            state.accounts.set_enabled(&id, value)?;
        }
        if let Some(value) = input.max_concurrent_requests {
            state.accounts.set_capacity(&id, value)?;
        }
        if let Some(value) = input.rest_seconds {
            state.accounts.rest(&id, Duration::from_secs(value))?;
        }
        Ok::<_, AccountError>(())
    })();
    match result {
        Ok(()) => Json(json!({"updated":true})).into_response(),
        Err(e) => account_error(e),
    }
}
async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    match state.accounts.delete_draining(&id) {
        Ok(drained) => Json(json!({"deleted":drained,"draining":!drained})).into_response(),
        Err(e) => account_error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    proxy: Option<String>,
}
#[expect(
    clippy::result_large_err,
    reason = "Preserve the native Axum Response at this HTTP boundary"
)]
fn login(state: &AppState, proxy: Option<&str>, account: &str) -> Result<OAuthLogin, Response> {
    let client = oauth_login_client(proxy).map_err(account_error)?;
    if let Some(proxy) = proxy {
        let url = url::Url::parse(proxy)
            .map_err(|_| account_error(AccountError::InvalidConfiguration))?;
        if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(account_error(AccountError::InvalidConfiguration));
        }
    }
    OAuthLogin::new(
        &state
            .config
            .state_dir
            .join("accounts")
            .join(account)
            .join("home"),
        client,
        &state.config.oauth_issuer,
        None,
        state.config.allow_insecure_http,
    )
    .map_err(|_| account_error(AccountError::PrivateState))
}
async fn device(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Result<Json<Begin>, JsonRejection>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let input = match json_input(input) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let account = uuid::Uuid::new_v4().simple().to_string();
    let job_id = uuid::Uuid::new_v4().to_string();
    {
        let Ok(mut jobs) = state.admin.jobs.lock() else {
            return unavailable();
        };
        AdminState::prune(&mut jobs);
        if jobs.len() >= MAX_LOGINS {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "login_capacity",
                "Too many login attempts",
                "登录任务数量已满",
            );
        }
    }
    let login = match login(&state, input.proxy.as_deref(), &account) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let attempt = match login.begin_device().await {
        Ok(v) => v,
        Err(_) => {
            return error(
                StatusCode::BAD_GATEWAY,
                "oauth_device_failed",
                "Device authorization request failed",
                "设备授权请求失败",
            );
        }
    };
    let reply = json!({"job_id":job_id,"account_id":account,"verification_url":attempt.verification_url,"user_code":attempt.user_code,"expires_in_seconds":900});
    {
        let Ok(mut jobs) = state.admin.jobs.lock() else {
            return unavailable();
        };
        AdminState::prune(&mut jobs);
        if jobs.len() >= MAX_LOGINS {
            attempt.cancellation().cancel();
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "login_capacity",
                "Too many login attempts",
                "登录任务数量已满",
            );
        }
        jobs.insert(
            job_id.clone(),
            Job {
                account,
                proxy: input.proxy,
                created: Instant::now(),
                phase: Phase::Pending,
                cancellation: attempt.cancellation(),
                browser: None,
                callback_state: None,
                callback_server: None,
                error: None,
            },
        );
    }
    let completion_account = reply["account_id"]
        .as_str()
        .expect("local generated account")
        .to_owned();
    tokio::spawn(async move {
        let result = attempt.complete().await;
        finish(&state, &job_id, &completion_account, result);
    });
    Json(reply).into_response()
}
async fn browser(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Result<Json<Begin>, JsonRejection>,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let input = match json_input(input) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let account = uuid::Uuid::new_v4().simple().to_string();
    let id = uuid::Uuid::new_v4().to_string();
    let login = match login(&state, input.proxy.as_deref(), &account) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let listener = match bind_browser_callback(BROWSER_CALLBACK_PORTS).await {
        Ok(v) => v,
        Err(_) => {
            return error(
                StatusCode::CONFLICT,
                "oauth_callback_port_busy",
                "OAuth callback ports 1455 and 1457 are busy; use Device Code",
                "OAuth 回调端口 1455 和 1457 已占用，请使用 Device Code",
            );
        }
    };
    let redirect = format!(
        "http://127.0.0.1:{}/auth/callback",
        listener
            .local_addr()
            .expect("bound callback listener")
            .port()
    );
    let attempt = match login.begin_browser(&redirect) {
        Ok(v) => v,
        Err(_) => return account_error(AccountError::InvalidConfiguration),
    };
    let url = match url::Url::parse(&attempt.auth_url) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let nonce = match url.query_pairs().find(|(name, _)| name == "state") {
        Some((_, v)) => v.into_owned(),
        None => return unavailable(),
    };
    let result = json!({"job_id":id,"account_id":account,"authorization_url":attempt.auth_url,"expires_in_seconds":900});
    let Ok(mut jobs) = state.admin.jobs.lock() else {
        return unavailable();
    };
    AdminState::prune(&mut jobs);
    if jobs.len() >= MAX_LOGINS {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "login_capacity",
            "Too many login attempts",
            "登录任务数量已满",
        );
    }
    jobs.insert(
        id,
        Job {
            account,
            proxy: input.proxy,
            created: Instant::now(),
            phase: Phase::Pending,
            cancellation: attempt.cancellation(),
            browser: Some(attempt),
            callback_state: Some(nonce),
            callback_server: Some(callback_server(listener, state.clone(), LOGIN_TTL)),
            error: None,
        },
    );
    Json(result).into_response()
}
fn finish(state: &AppState, id: &str, account: &str, result: Result<(), OAuthError>) {
    let Ok(mut jobs) = state.admin.jobs.lock() else {
        return;
    };
    let Some(job) = jobs.get_mut(id) else {
        let _ = std::fs::remove_file(
            state
                .config
                .state_dir
                .join("accounts")
                .join(account)
                .join("home/auth.json"),
        );
        return;
    };
    if job.cancellation.is_cancelled() || job.created.elapsed() >= LOGIN_TTL {
        job.phase = Phase::Cancelled;
        job.error = Some("oauth_cancelled");
    } else {
        match result {
            Ok(()) => match state
                .accounts
                .add_from_home(&job.account, job.proxy.clone())
            {
                Ok(_) => {
                    job.phase = Phase::Completed;
                    job.error = None;
                }
                Err(AccountError::DuplicateOAuthAccount) => {
                    job.phase = Phase::Failed;
                    job.error = Some("duplicate_oauth_account");
                }
                Err(_) => {
                    job.phase = Phase::Failed;
                    job.error = Some("oauth_account_registration_failed");
                }
            },
            Err(OAuthError::Cancelled) => {
                job.phase = Phase::Cancelled;
                job.error = Some("oauth_cancelled");
            }
            Err(OAuthError::Expired) => {
                job.phase = Phase::Failed;
                job.error = Some("oauth_expired");
            }
            Err(_) => {
                job.phase = Phase::Failed;
                job.error = Some("oauth_login_failed");
            }
        }
    }
    if job.phase != Phase::Completed {
        let _ = std::fs::remove_file(
            state
                .config
                .state_dir
                .join("accounts")
                .join(&job.account)
                .join("home/auth.json"),
        );
    }
    // Graceful shutdown retains the current callback response while closing
    // admission to new callback connections.
    job.callback_server = None;
}
async fn login_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Ok(mut jobs) = state.admin.jobs.lock() else {
        return unavailable();
    };
    AdminState::prune(&mut jobs);
    let Some(job) = jobs.get(&id) else {
        return error(
            StatusCode::NOT_FOUND,
            "login_not_found",
            "Login attempt not found or expired",
            "登录任务不存在或已到期",
        );
    };
    Json(json!({"job_id":id,"account_id":job.account,"status":job.phase.name(),"error_code":job.error,
        "expires_in_seconds":LOGIN_TTL.saturating_sub(job.created.elapsed()).as_secs()})).into_response()
}
async fn cancel(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&state, &headers) {
        return response;
    }
    let Ok(mut jobs) = state.admin.jobs.lock() else {
        return unavailable();
    };
    AdminState::prune(&mut jobs);
    let Some(job) = jobs.get_mut(&id) else {
        return error(
            StatusCode::NOT_FOUND,
            "login_not_found",
            "Login attempt not found",
            "登录任务不存在",
        );
    };
    if job.phase == Phase::Completed {
        return error(
            StatusCode::CONFLICT,
            "login_already_completed",
            "Login has already completed",
            "登录已经完成",
        );
    }
    job.cancellation.cancel();
    job.phase = Phase::Cancelled;
    job.browser = None;
    job.callback_server = None;
    job.error = Some("oauth_cancelled");
    Json(json!({"cancelled":true})).into_response()
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(state): State<Arc<AppState>>,
    Query(callback): Query<Callback>,
) -> Response {
    let (id, account, attempt) = {
        let Ok(mut jobs) = state.admin.jobs.lock() else {
            return unavailable();
        };
        AdminState::prune(&mut jobs);
        let Some((id, job)) = jobs.iter_mut().find(|(_, job)| {
            job.callback_state.as_deref() == Some(callback.state.as_str())
                && job.phase == Phase::Pending
        }) else {
            return error(
                StatusCode::BAD_REQUEST,
                "oauth_state_mismatch",
                "OAuth callback state is invalid or already consumed",
                "OAuth 回调状态无效或已经使用",
            );
        };
        if callback.error.is_some() {
            job.cancellation.cancel();
            job.phase = Phase::Failed;
            job.error = Some("oauth_authority_rejected");
            job.browser = None;
            job.callback_server = None;
            return error(
                StatusCode::BAD_REQUEST,
                "oauth_authority_rejected",
                "OAuth authority rejected the login",
                "OAuth 授权方拒绝登录",
            );
        }
        let Some(attempt) = job.browser.take() else {
            return error(
                StatusCode::BAD_REQUEST,
                "oauth_state_mismatch",
                "OAuth callback is invalid",
                "OAuth 回调无效",
            );
        };
        job.phase = Phase::Completing;
        (id.clone(), job.account.clone(), attempt)
    };
    let result = attempt
        .complete(&callback.state, callback.code.as_deref().unwrap_or(""))
        .await;
    finish(&state, &id, &account, result);
    let Ok(jobs) = state.admin.jobs.lock() else {
        return unavailable();
    };
    if jobs
        .get(&id)
        .is_some_and(|job| job.phase == Phase::Completed)
    {
        Html("<html lang=\"zh\"><meta charset=\"utf-8\"><p>登录完成 / Login completed. Return to the management page.</p></html>").into_response()
    } else {
        error(
            StatusCode::BAD_REQUEST,
            "oauth_login_failed",
            "OAuth login did not complete",
            "OAuth 登录未完成",
        )
    }
}
async fn page() -> Html<&'static str> {
    Html(PAGE)
}
const PAGE: &str = r#"<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>right-codex</title>
<style>body{font:15px system-ui;max-width:960px;margin:48px auto;padding:0 24px;color:#243328;background:#f6f7f3}h1{font-size:28px}input,button{padding:10px;margin:4px;border:1px solid #c3ccc2;border-radius:6px}button{background:#234b39;color:white;cursor:pointer}table{width:100%;border-collapse:collapse;margin-top:24px}td,th{text-align:left;padding:12px;border-bottom:1px solid #d5dcd1}#notice{white-space:pre-wrap}small{color:#607061}</style>
<h1>right-codex</h1><p>账号管理 / OAuth accounts</p><input id="key" type="password" placeholder="管理员密码 / Admin password"><button onclick="save()">连接 / Connect</button><hr><details open><summary>全局调度 / Scheduling</summary><p><label>加入账号后的 0–1、1–2、2–4、4–24、24+ 小时会话上限 / Sessions by account age<br><input id="bands" size="38" placeholder="2,4,8,16,32"></label></p><label>空闲回收秒数 / Idle seconds <input id="idle" type="number" min="1"></label><label>新会话启动间隔秒数 / Startup spacing <input id="spacing" type="number" min="0"></label><br><label>休息周期分钟 / Rest every minutes <input id="restEvery" type="number" min="0"></label><label>休息账号百分比 / Rest percent <input id="restPercent" type="number" min="0" max="100"></label><label>休息时长分钟 / Rest duration <input id="restFor" type="number" min="0"></label><button onclick="saveSettings()">保存设置 / Save settings</button><small>设置影响新会话准入；正在交付的请求继续完成。 / Existing requests drain normally.</small></details><hr><input id="proxy" placeholder="可选代理 / Optional proxy"><button onclick="begin('device')">Device Code</button><button onclick="begin('browser')">浏览器登录 / Browser PKCE</button><small>浏览器登录需在网关宿主机打开；远程使用 Device Code。 / Use Device Code when managing remotely.</small><p id="notice"></p><table><thead><tr><th>账号 / Account</th><th>状态 / State</th><th>操作 / Actions</th></tr></thead><tbody id="rows"></tbody></table><details><summary>HTTP / WS 调用事实 / Network facts</summary><select id="factAccount"><option value="">全部账号 / All accounts</option></select><button onclick="loadFacts()">刷新 / Refresh</button><pre id="facts" style="overflow:auto;max-height:360px"></pre></details><details><summary>遥测交付 / Metric deliveries</summary><button onclick="loadDeliveries()">刷新 / Refresh</button><button onclick="clearDeliveries()">清空当前账号筛选的交付 / Clear selected deliveries</button><pre id="deliveries" style="overflow:auto;max-height:280px"></pre></details>
<script>
let token=sessionStorage.getItem('codexAdmin')||'';document.getElementById('key').value=token;let activeJob=null;
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});const v=await r.json();if(!r.ok)throw new Error(v.error?.message||r.status);return v}
function note(v){document.getElementById('notice').textContent=v}async function save(){token=document.getElementById('key').value;sessionStorage.setItem('codexAdmin',token);await load();await loadSettings()}
async function load(){try{const v=await api('/admin/api/accounts');const rows=document.getElementById('rows');rows.replaceChildren();const select=document.getElementById('factAccount');const previous=select.value;select.replaceChildren();const all=document.createElement('option');all.value='';all.textContent='全部账号 / All accounts';select.append(all);for(const a of v.accounts){const o=document.createElement('option');o.value=a.id;o.textContent=a.id;select.append(o)}select.value=previous;for(const a of v.accounts){const row=document.createElement('tr');const name=document.createElement('td');name.textContent=a.id+' / '+a.workspace_account_id;const state=document.createElement('td');state.textContent=a.deleting?'排空中 / Draining':a.auth_invalid?'凭据失效 / Credential invalid':a.enabled?'启用 / Enabled':'停用 / Disabled';if(a.resting)state.textContent+=' · 休息中 / Resting';if(a.quota_cooldown){state.textContent+=' · 额度冷却 / Quota cooldown';if(a.quota_cooldown_until_unix_ms)state.textContent+=' · '+new Date(a.quota_cooldown_until_unix_ms).toLocaleString()}const actions=document.createElement('td');for(const [text,run]of [[a.enabled?'停用 / Disable':'启用 / Enable',()=>api('/admin/api/accounts/'+a.id,'PATCH',{enabled:!a.enabled})],['休息 5 分钟 / Rest 5 min',()=>api('/admin/api/accounts/'+a.id,'PATCH',{rest_seconds:300})],['删除 / Delete',()=>api('/admin/api/accounts/'+a.id,'DELETE')]]){const b=document.createElement('button');b.textContent=text;if(a.auth_invalid&&text==='启用 / Enable'){b.disabled=true;b.title='需更新 OAuth 凭据 / Updated OAuth credentials required'}b.onclick=async()=>{try{await run();await load()}catch(e){note(e.message)}};actions.append(b)}const capacity=document.createElement('input');capacity.type='number';capacity.min='1';capacity.max='65536';capacity.value=a.max_concurrent_requests;capacity.setAttribute('aria-label','账号 '+a.id+' 的并发请求上限 / Concurrent request limit');const apply=document.createElement('button');apply.textContent='保存容量 / Save capacity';apply.onclick=async()=>{try{await api('/admin/api/accounts/'+a.id,'PATCH',{max_concurrent_requests:Number(capacity.value)});note('容量已保存 / Capacity saved');await load()}catch(e){note(e.message)}};actions.append(capacity,apply);row.append(name,state,actions);rows.append(row)}}catch(e){note(e.message)}}
async function begin(mode){try{const proxy=document.getElementById('proxy').value.trim()||null;const v=await api('/admin/api/oauth/'+mode,'POST',{proxy});activeJob=v.job_id;note(mode==='device'?v.verification_url+'\n'+v.user_code:v.authorization_url);if(mode==='browser')window.open(v.authorization_url,'_blank','noopener');const cancel=document.createElement('button');cancel.textContent='取消授权 / Cancel login';cancel.onclick=()=>api('/admin/api/oauth/'+v.job_id,'DELETE');document.getElementById('notice').append(cancel);poll(v.job_id)}catch(e){note(e.message)}}
async function poll(id){try{const v=await api('/admin/api/oauth/'+id);if(v.status==='pending'||v.status==='completing')setTimeout(()=>poll(id),1500);else{note(v.status+(v.error_code?' / '+v.error_code:''));await load()}}catch(e){note(e.message)}}async function loadSettings(){try{const s=await api('/admin/api/settings');document.getElementById('bands').value=s.max_sessions_by_account_age.join(',');for(const [id,key]of [['idle','idle_timeout_secs'],['spacing','startup_spacing_secs'],['restEvery','rest_interval_minutes'],['restPercent','rest_percent'],['restFor','rest_duration_minutes']])document.getElementById(id).value=s[key]}catch(e){note(e.message)}}
async function saveSettings(){try{const s={max_sessions_by_account_age:document.getElementById('bands').value.split(',').map(Number)};for(const [id,key]of [['idle','idle_timeout_secs'],['spacing','startup_spacing_secs'],['restEvery','rest_interval_minutes'],['restPercent','rest_percent'],['restFor','rest_duration_minutes']])s[key]=Number(document.getElementById(id).value);await api('/admin/api/settings','PATCH',s);note('设置已保存 / Settings saved');await loadSettings()}catch(e){note(e.message)}}
async function loadFacts(){try{const id=document.getElementById('factAccount').value;const v=await api('/admin/api/facts'+(id?'?account_id='+encodeURIComponent(id):''));document.getElementById('facts').textContent=JSON.stringify(v.facts,null,2)}catch(e){note(e.message)}}async function loadDeliveries(){try{const id=document.getElementById('factAccount').value;const v=await api('/admin/api/telemetry/deliveries'+(id?'?account_id='+encodeURIComponent(id):''));document.getElementById('deliveries').textContent=JSON.stringify(v.accounts,null,2)}catch(e){note(e.message)}}
async function clearDeliveries(){try{const id=document.getElementById('factAccount').value;await api('/admin/api/telemetry/deliveries'+(id?'?account_id='+encodeURIComponent(id):''),'DELETE');note('交付记录已清空 / Deliveries cleared');await loadDeliveries()}catch(e){note(e.message)}}if(token){load();loadSettings()}
</script></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accounts::AccountPool, config::GatewayConfig};

    #[tokio::test]
    async fn callback_binding_uses_fallback_without_stopping_existing_owner() {
        let existing = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied = existing.local_addr().unwrap().port();
        assert!(bind_browser_callback([occupied, occupied]).await.is_err());
        let fallback = bind_browser_callback([occupied, 0]).await.unwrap();
        assert_ne!(fallback.local_addr().unwrap().port(), occupied);
        let connect = tokio::net::TcpStream::connect(existing.local_addr().unwrap());
        let (connection, accepted) = tokio::join!(connect, existing.accept());
        assert!(connection.is_ok());
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn callback_listener_expires_and_explicit_drop_closes_without_oauth_request() {
        let directory = tempfile::TempDir::new().unwrap();
        let config: GatewayConfig = serde_json::from_value(json!({
            "listen":"127.0.0.1:18184",
            "state_dir":directory.path().join("state"),
            "client_api_key":"private-admin-fixture",
            "accounts":[]
        }))
        .unwrap();
        let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let _expiring = callback_server(listener, state.clone(), Duration::from_millis(20));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(tokio::net::TcpStream::connect(address).await.is_err());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stopping = callback_server(listener, state.clone(), LOGIN_TTL);
        drop(stopping);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert!(state.accounts.all().unwrap().is_empty());
        assert!(state.facts.snapshot().is_empty());
        assert_eq!(
            std::fs::read_dir(config.state_dir.join("accounts"))
                .unwrap()
                .count(),
            0
        );
    }
}
