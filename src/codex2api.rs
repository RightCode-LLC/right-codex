//! Codex2API's three management endpoints. OAuth wire behavior remains owned
//! by our pinned native adapter; this module does not start a callback server.
use crate::{
    accounts::{AccountError, oauth_login_client},
    gateway::AppState,
    oauth::{BrowserLogin, OAuthLogin},
};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(15 * 60);
const MAX_JOBS: usize = 256;
const MAX_SAFE_ID: u64 = 9_007_199_254_740_991;
const DEFAULT_REDIRECT: &str = "http://localhost:1455/auth/callback";

#[derive(Default)]
pub(crate) struct Management {
    jobs: Mutex<HashMap<String, Job>>,
    ids: Mutex<()>,
}
struct Job {
    created: Instant,
    state: String,
    proxy: Option<String>,
    staging: String,
    phase: Phase,
}
enum Phase {
    Pending(Box<BrowserLogin>),
    Completing([u8; 32]),
    Finished([u8; 32], Result<Value, Failure>),
    ImportPending([u8; 32], Import),
}
enum Import {
    Staged {
        name: String,
    },
    Registered {
        account: String,
        email: String,
        plan: String,
        name: String,
        created: bool,
    },
}
enum Work {
    Exchange(Box<BrowserLogin>, Import),
    Import(Import),
}
#[derive(Clone, Copy, Debug)]
struct Failure(StatusCode, &'static str, &'static str);
impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(json!({"code":self.1,"error":self.2}))).into_response();
        if self.1 == "oauth_exchange_in_progress" {
            response
                .headers_mut()
                .insert("retry-after", "1".parse().expect("static header"));
        }
        response
    }
}
type ResultOf<T> = Result<T, Failure>;
fn invalid() -> Failure {
    Failure(
        StatusCode::BAD_REQUEST,
        "invalid_admin_request",
        "Invalid management request / 管理请求无效",
    )
}
fn unavailable() -> Failure {
    Failure(
        StatusCode::SERVICE_UNAVAILABLE,
        "admin_unavailable",
        "Management storage unavailable / 管理存储暂不可用",
    )
}
fn account_error(error: AccountError) -> Failure {
    match error {
        AccountError::Deleting => Failure(
            StatusCode::CONFLICT,
            "account_deleting",
            "Account is draining deletion / 账号正在排空删除",
        ),
        AccountError::ProPlanRequired => Failure(
            StatusCode::BAD_REQUEST,
            "pro_oauth_required",
            "A ChatGPT Pro OAuth account is required / 仅接入 ChatGPT Pro OAuth 账号",
        ),
        AccountError::InvalidProfile
        | AccountError::InvalidTokens
        | AccountError::IdentityChanged => Failure(
            StatusCode::BAD_GATEWAY,
            "invalid_oauth_identity",
            "OAuth identity or profile is invalid / OAuth 身份或资料无效",
        ),
        AccountError::InvalidConfiguration | AccountError::ClientBuild => invalid(),
        _ => unavailable(),
    }
}
fn authorize(headers: &HeaderMap, state: &AppState) -> ResultOf<()> {
    if !headers.contains_key("x-admin-key")
        && headers.get_all("authorization").iter().count() == 1
        && crate::admission::admin_authorized(headers, &state.config.client_api_key)
    {
        return Ok(());
    }
    let mut values = headers.get_all("x-admin-key").iter();
    let key = values.next().and_then(|v| v.to_str().ok());
    if values.next().is_none()
        && !state.config.client_api_key.is_empty()
        && key.is_some_and(|v| {
            Sha256::digest(v.as_bytes()) == Sha256::digest(state.config.client_api_key.as_bytes())
        })
    {
        Ok(())
    } else {
        Err(Failure(
            StatusCode::UNAUTHORIZED,
            "admin_auth_required",
            "Administrator authentication required / 需要管理员认证",
        ))
    }
}
pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/admin/oauth/generate-auth-url", post(generate))
        .route("/api/admin/oauth/exchange-code", post(exchange))
        .route("/api/admin/accounts", get(accounts))
        .layer(DefaultBodyLimit::max(32 * 1024))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Generate {
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}
fn proxy(value: Option<&str>) -> ResultOf<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 4096 {
        return Err(invalid());
    }
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid());
    }
    Ok(Some(url.to_string()))
}
fn redirect(value: Option<&str>) -> ResultOf<String> {
    let value = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_REDIRECT);
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "http"
        || !matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
        || !matches!(url.port(), Some(1455 | 1457))
        || url.path() != "/auth/callback"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    Ok(url.into())
}
fn cleanup(state: &AppState, staging: &str) {
    // Only UUID staging IDs created by this module reach this function. Never
    // remove a registered home: upsert-new retains that home as its owner.
    let _ = std::fs::remove_dir_all(state.config.state_dir.join("accounts").join(staging));
}
fn prune(state: &AppState, jobs: &mut HashMap<String, Job>) {
    jobs.retain(|_, job| {
        if job.created.elapsed() < TTL || matches!(job.phase, Phase::Completing(_)) {
            return true;
        }
        if matches!(
            job.phase,
            Phase::Pending(_) | Phase::ImportPending(_, Import::Staged { .. })
        ) {
            cleanup(state, &job.staging);
        }
        false
    });
}
async fn generate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Result<Json<Generate>, JsonRejection>,
) -> ResultOf<Json<Value>> {
    authorize(&headers, &state)?;
    let input = input.map_err(|_| invalid())?.0;
    let proxy = proxy(input.proxy_url.as_deref())?;
    let redirect = redirect(input.redirect_uri.as_deref())?;
    let mut jobs = state
        .admin
        .codex2api
        .jobs
        .lock()
        .map_err(|_| unavailable())?;
    prune(&state, &mut jobs);
    if jobs.len() >= MAX_JOBS {
        return Err(Failure(
            StatusCode::TOO_MANY_REQUESTS,
            "login_capacity",
            "Too many OAuth sessions / OAuth 会话数量已满",
        ));
    }
    let staging = uuid::Uuid::new_v4().simple().to_string();
    let home = state
        .config
        .state_dir
        .join("accounts")
        .join(&staging)
        .join("home");
    let login = OAuthLogin::new(
        &home,
        oauth_login_client(proxy.as_deref()).map_err(account_error)?,
        &state.config.oauth_issuer,
        None,
        state.config.allow_insecure_http,
    )
    .map_err(|_| unavailable())?;
    let attempt = match login.begin_browser(&redirect) {
        Ok(attempt) => attempt,
        Err(_) => {
            cleanup(&state, &staging);
            return Err(invalid());
        }
    };
    let url = url::Url::parse(&attempt.auth_url).map_err(|_| unavailable())?;
    let nonce = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(unavailable)?;
    let session = uuid::Uuid::new_v4().simple().to_string();
    let reply = json!({"auth_url":attempt.auth_url,"session_id":session,"expires_in_seconds":TTL.as_secs()});
    jobs.insert(
        session,
        Job {
            created: Instant::now(),
            state: nonce,
            proxy,
            staging,
            phase: Phase::Pending(Box::new(attempt)),
        },
    );
    // Expire abandoned sessions even when no further management request comes
    // in. A weak reference does not keep a stopped gateway alive.
    let weak = Arc::downgrade(&state);
    tokio::spawn(async move {
        tokio::time::sleep(TTL).await;
        if let Some(state) = weak.upgrade()
            && let Ok(mut jobs) = state.admin.codex2api.jobs.lock()
        {
            prune(&state, &mut jobs);
        }
    });
    Ok(Json(reply))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    session_id: String,
    code: String,
    state: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    proxy_url: Option<String>,
}
async fn exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Result<Json<Exchange>, JsonRejection>,
) -> ResultOf<Json<Value>> {
    authorize(&headers, &state)?;
    let input = input.map_err(|_| invalid())?.0;
    if input.session_id.is_empty()
        || input.session_id.len() > 128
        || input.state.is_empty()
        || input.state.len() > 128
        || input.code.is_empty()
        || input.code.len() > 16384
        || input.code.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let name = input.name.as_deref().unwrap_or("").trim().to_owned();
    if name.len() > 512 || name.chars().any(char::is_control) {
        return Err(invalid());
    }
    let supplied_proxy = input
        .proxy_url
        .as_deref()
        .map(|v| proxy(Some(v)))
        .transpose()?;
    let digest: [u8; 32] = Sha256::digest(input.code.as_bytes()).into();
    let (work, staging, session_proxy) = {
        let mut jobs = state
            .admin
            .codex2api
            .jobs
            .lock()
            .map_err(|_| unavailable())?;
        prune(&state, &mut jobs);
        let job = jobs.get_mut(&input.session_id).ok_or(Failure(
            StatusCode::BAD_REQUEST,
            "oauth_session_expired",
            "OAuth session not found or expired / OAuth 会话不存在或已到期",
        ))?;
        if job.state != input.state {
            return Err(Failure(
                StatusCode::BAD_REQUEST,
                "oauth_state_mismatch",
                "OAuth state does not match / OAuth state 不匹配",
            ));
        }
        if supplied_proxy.as_ref().is_some_and(|v| v != &job.proxy) {
            return Err(Failure(
                StatusCode::BAD_REQUEST,
                "oauth_proxy_mismatch",
                "Proxy must match the authorization session / 代理须与授权会话一致",
            ));
        }
        match &job.phase {
            Phase::Completing(hash) if hash == &digest => {
                return Err(Failure(
                    StatusCode::CONFLICT,
                    "oauth_exchange_in_progress",
                    "OAuth exchange is in progress / OAuth 正在兑换",
                ));
            }
            Phase::Finished(hash, result) if hash == &digest => return result.clone().map(Json),
            Phase::ImportPending(hash, _) if hash == &digest => {}
            Phase::Completing(_) | Phase::Finished(_, _) | Phase::ImportPending(_, _) => {
                return Err(Failure(
                    StatusCode::CONFLICT,
                    "oauth_session_consumed",
                    "OAuth session has already been consumed / OAuth 会话已经使用",
                ));
            }
            Phase::Pending(_) => {}
        }
        let work = match std::mem::replace(&mut job.phase, Phase::Completing(digest)) {
            Phase::Pending(attempt) => Work::Exchange(attempt, Import::Staged { name }),
            Phase::ImportPending(_, import) => Work::Import(import),
            _ => unreachable!(),
        };
        (work, job.staging.clone(), job.proxy.clone())
    };
    // Client disconnect must not cancel a one-time code exchange. Storage
    // retries operate on the private staged credential, never on its code.
    tokio::spawn(async move {
        let prepared = match work {
            Work::Exchange(attempt, import) => match attempt.complete(&input.state, &input.code).await {
                Ok(()) => Ok(import),
                Err(_) => {
                    cleanup(&state, &staging);
                    Err(Failure(StatusCode::BAD_GATEWAY, "oauth_exchange_failed",
                        "OAuth exchange failed; start a new authorization / OAuth 兑换失败，请重新授权"))
                }
            },
            Work::Import(import) => Ok(import),
        };
        let mut retry = None;
        let result = match prepared {
            Ok(mut import) => {
                let result = complete_import(&state, &staging, session_proxy, &mut import);
                if result.as_ref().is_err_and(|error| error.0 == StatusCode::SERVICE_UNAVAILABLE) {
                    retry = Some(import);
                } else if result.is_err() && matches!(import, Import::Staged { .. }) {
                    cleanup(&state, &staging);
                }
                result
            },
            Err(error) => Err(error),
        };
        if let Ok(mut jobs) = state.admin.codex2api.jobs.lock()
            && let Some(job) = jobs.get_mut(&input.session_id) {
            job.phase = match retry {
                Some(import) => Phase::ImportPending(digest, import),
                None => Phase::Finished(digest, result.clone()),
            };
        }
        result.map(Json)
    }).await.map_err(|_| unavailable())?
}
fn complete_import(
    state: &AppState,
    staging: &str,
    proxy: Option<String>,
    import: &mut Import,
) -> ResultOf<Value> {
    if let Import::Staged { name } = import {
        let (account, created) = state
            .accounts
            .upsert_from_home(staging, proxy)
            .map_err(account_error)?;
        if !created {
            cleanup(state, staging);
        }
        let (email, plan) = account.oauth_profile().map_err(account_error)?;
        *import = Import::Registered {
            account: account.id().to_owned(),
            name: if name.is_empty() {
                email.clone()
            } else {
                name.clone()
            },
            email,
            plan,
            created,
        };
    }
    let Import::Registered {
        account,
        email,
        plan,
        name,
        created,
    } = import
    else {
        unreachable!()
    };
    let mut aliases = aliases(state)?;
    let id = aliases.1.ensure(account, name)?;
    aliases
        .1
        .accounts
        .get_mut(account)
        .expect("assigned alias")
        .name = name.clone();
    aliases.1.save(&state.config.state_dir)?;
    Ok(
        json!({"id":id,"email":email,"plan_type":plan,"updated":!*created,
        "message":if *created {"Account added / 账号已新增"} else {"Account updated / 账号已更新"}}),
    )
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alias {
    id: u64,
    name: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Aliases {
    accounts: BTreeMap<String, Alias>,
}
impl Aliases {
    fn read(root: &Path) -> ResultOf<Self> {
        let path = root.join("codex2api-ids.json");
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Ok(m) if m.is_file() && !m.file_type().is_symlink() && m.len() <= 16 * 1024 * 1024 => {}
            _ => return Err(unavailable()),
        }
        let result: Self = serde_json::from_slice(&std::fs::read(path).map_err(|_| unavailable())?)
            .map_err(|_| unavailable())?;
        let mut ids = HashSet::new();
        if result
            .accounts
            .values()
            .any(|a| a.id == 0 || a.id > MAX_SAFE_ID || !ids.insert(a.id))
        {
            return Err(unavailable());
        }
        Ok(result)
    }
    fn ensure(&mut self, key: &str, name: &str) -> ResultOf<u64> {
        if let Some(a) = self.accounts.get(key) {
            return Ok(a.id);
        }
        let id = self
            .accounts
            .values()
            .map(|a| a.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|id| *id <= MAX_SAFE_ID)
            .ok_or_else(unavailable)?;
        self.accounts.insert(
            key.to_owned(),
            Alias {
                id,
                name: name.to_owned(),
            },
        );
        Ok(id)
    }
    fn save(&self, root: &Path) -> ResultOf<()> {
        let raw = serde_json::to_vec(self).map_err(|_| unavailable())?;
        if raw.len() > 16 * 1024 * 1024 {
            return Err(unavailable());
        }
        crate::storage::atomic(&root.join("codex2api-ids.json"), &raw).map_err(|_| unavailable())
    }
}
fn aliases(state: &AppState) -> ResultOf<(std::sync::MutexGuard<'_, ()>, Aliases)> {
    let guard = state
        .admin
        .codex2api
        .ids
        .lock()
        .map_err(|_| unavailable())?;
    Ok((guard, Aliases::read(&state.config.state_dir)?))
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    view: Option<String>,
    channel: Option<String>,
}
async fn accounts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    query: Result<Query<List>, QueryRejection>,
) -> ResultOf<Json<Value>> {
    authorize(&headers, &state)?;
    let query = query.map_err(|_| invalid())?.0;
    if query.view.as_deref().is_some_and(|v| v != "lite")
        || query.channel.as_deref().is_some_and(|v| v != "codex")
    {
        return Err(invalid());
    }
    let all = state.accounts.all().map_err(account_error)?;
    let mut aliases = aliases(&state)?;
    let before = aliases.1.accounts.len();
    let mut rows = Vec::new();
    for account in all {
        let (email, plan_type) = account.oauth_profile().map_err(account_error)?;
        let id = aliases.1.ensure(account.id(), &email)?;
        let availability = account.availability().map_err(account_error)?;
        let enabled = account.admin_enabled().map_err(account_error)?;
        let status = if availability.deleting {
            "deleting"
        } else if availability.auth_invalid {
            "unauthorized"
        } else if !enabled {
            "disabled"
        } else if availability.quota_cooldown {
            "rate_limited"
        } else if availability.resting {
            "paused"
        } else {
            "active"
        };
        rows.push(json!({"id":id,"name":aliases.1.accounts[account.id()].name,"email":email,"plan_type":plan_type,"status":status,"enabled":enabled,"proxy_configured":account.proxy().is_some(),"at_only":false,"agent_identity":false,"openai_responses_api":false,"grok_api":false,"claude_api":false,"antigravity_api":false}));
    }
    if aliases.1.accounts.len() != before {
        aliases.1.save(&state.config.state_dir)?;
    }
    Ok(Json(json!({"accounts":rows})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accounts::AccountPool, config::GatewayConfig};

    #[tokio::test]
    async fn expired_pending_session_is_removed_without_exchange_or_account() {
        let dir = tempfile::tempdir().unwrap();
        let config = GatewayConfig {
            state_dir: dir.path().to_owned(),
            client_api_key: "fixture-admin".into(),
            ..GatewayConfig::default()
        };
        let pool = AccountPool::from_config(&config).unwrap();
        let state = AppState::new(config, pool);
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", "fixture-admin".parse().unwrap());
        let reply = generate(
            State(state.clone()),
            headers,
            Ok(Json(Generate {
                proxy_url: None,
                redirect_uri: None,
            })),
        )
        .await
        .unwrap()
        .0;
        let id = reply["session_id"].as_str().unwrap();
        let mut jobs = state.admin.codex2api.jobs.lock().unwrap();
        let job = jobs.get_mut(id).unwrap();
        let home = dir.path().join("accounts").join(&job.staging);
        assert!(home.is_dir());
        job.created = Instant::now() - TTL - Duration::from_secs(1);
        prune(&state, &mut jobs);
        assert!(!jobs.contains_key(id));
        assert!(!home.exists());
        assert!(state.accounts.all().unwrap().is_empty());
    }

    #[test]
    fn alias_ids_are_durable_monotonic_and_reject_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let mut ids = Aliases::default();
        assert_eq!(ids.ensure("first", "One").unwrap(), 1);
        ids.save(dir.path()).unwrap();
        let mut ids = Aliases::read(dir.path()).unwrap();
        assert_eq!(ids.ensure("first", "Different label").unwrap(), 1);
        assert_eq!(ids.ensure("second", "Two").unwrap(), 2);
        ids.save(dir.path()).unwrap();
        assert_eq!(Aliases::read(dir.path()).unwrap().accounts["second"].id, 2);
        std::fs::write(
            dir.path().join("codex2api-ids.json"),
            br#"{"accounts":{"first":{"id":1,"name":"One"},"second":{"id":1,"name":"Two"}}}"#,
        )
        .unwrap();
        assert!(Aliases::read(dir.path()).is_err());
    }
}
