//! Native OAuth admission, official one-send transport and durable conversation ownership.
use crate::{
    accounts::{Account, AccountLease, AccountPool},
    config::GatewayConfig,
    metadata,
    observability::{AccountTelemetry, NetworkEventKind, SsePollOutcome, TelemetryRegistry},
    protocol::{ProtocolError, V2Completion},
    session::{Session, SessionStore, ToolDelivery},
    telemetry::{
        Attempt, AttemptJournal, FactExporter, FactLedger, FactStore, LedgerPolicy,
        OutboundIdentity, TerminalKind,
    },
    transport::{ObservedTransport, ParserGuard, WireResponse},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    middleware,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use codex_api::{ApiError, Compression, ResponsesClient};
use codex_client::{Provider, RetryConfig};
use codex_http_client::{EncodedJsonBody, RequestBody, RequestCompression, TransportError};
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard};
use uuid::Uuid;

pub struct AppState {
    pub config: GatewayConfig,
    pub accounts: AccountPool,
    pub sessions: SessionStore,
    pub facts: Arc<FactStore>,
    pub ledger: Arc<FactLedger>,
    pub metrics: TelemetryRegistry,
    pub collector: Option<FactExporter>,
    pub admin: Arc<crate::admin::AdminState>,
    pub(crate) scope_dir: PathBuf,
    domain: String,
    live: Mutex<HashMap<String, Live>>,
    starts: Mutex<HashMap<String, Arc<AsyncMutex<Instant>>>>,
    scheduling: std::sync::RwLock<crate::config::SchedulingConfig>,
}
struct Live {
    account: String,
    last: Instant,
}
impl AppState {
    pub(crate) fn namespace(&self, headers: &HeaderMap) -> String {
        crate::admission::local_principal(headers, &self.domain)
    }
    pub fn new(config: GatewayConfig, accounts: AccountPool) -> Arc<Self> {
        Self::try_new(config, accounts).expect("private gateway state")
    }
    pub fn try_new(config: GatewayConfig, accounts: AccountPool) -> anyhow::Result<Arc<Self>> {
        let scope_dir = config.state_dir.join("sessions");
        crate::storage::directory(&scope_dir)?;
        let domain_file = config.state_dir.join("domain.json");
        let domain = if domain_file.exists() {
            let v: Value = serde_json::from_slice(&std::fs::read(&domain_file)?)?;
            let id = v["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid private gateway domain"))?;
            Uuid::parse_str(id)?;
            id.to_owned()
        } else {
            let id = Uuid::new_v4().to_string();
            crate::storage::atomic(&domain_file, &serde_json::to_vec(&json!({"id":id}))?)?;
            id
        };
        let ledger = FactLedger::open(
            config
                .telemetry
                .private_dir
                .clone()
                .unwrap_or_else(|| config.state_dir.join("facts")),
            LedgerPolicy {
                max_batch: config.telemetry.max_batch,
                export_ttl: Duration::from_secs(config.telemetry.ttl_seconds),
                retry_backoff: Duration::from_secs(config.telemetry.retry_backoff_seconds),
                ..LedgerPolicy::default()
            },
        )?;
        let metrics = TelemetryRegistry::new(config.telemetry.clone())?;
        let collector = config
            .telemetry
            .collector_endpoint
            .as_deref()
            .map(|endpoint| {
                FactExporter::new(
                    ledger.clone(),
                    endpoint,
                    config.telemetry.allow_loopback_http,
                )
            })
            .transpose()?;
        let scheduling_file = config.state_dir.join("scheduling.json");
        let scheduling: crate::config::SchedulingConfig = if scheduling_file.exists() {
            serde_json::from_slice(&std::fs::read(scheduling_file)?)?
        } else {
            config.scheduling.clone()
        };
        let mut check = config.clone();
        check.scheduling = scheduling.clone();
        check.validate()?;
        Ok(Arc::new(Self {
            config,
            accounts,
            sessions: SessionStore::with_capacity(4096)?,
            facts: Arc::new(FactStore::default()),
            ledger,
            metrics,
            collector,
            admin: Arc::new(crate::admin::AdminState::default()),
            scope_dir,
            domain,
            live: Mutex::new(HashMap::new()),
            starts: Mutex::new(HashMap::new()),
            scheduling: std::sync::RwLock::new(scheduling),
        }))
    }
    pub fn scheduling(&self) -> crate::config::SchedulingConfig {
        self.scheduling
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| self.config.scheduling.clone())
    }
    pub fn set_scheduling(
        &self,
        scheduling: crate::config::SchedulingConfig,
    ) -> Result<(), ProtocolError> {
        let mut check = self.config.clone();
        check.scheduling = scheduling.clone();
        check
            .validate()
            .map_err(|_| ProtocolError::Invalid("scheduling"))?;
        let mut guard = self
            .scheduling
            .write()
            .map_err(|_| ProtocolError::Invalid("scheduling.lock"))?;
        crate::storage::atomic(
            &self.config.state_dir.join("scheduling.json"),
            &serde_json::to_vec(&scheduling)
                .map_err(|_| ProtocolError::Invalid("scheduling.encode"))?,
        )?;
        *guard = scheduling;
        Ok(())
    }
    pub(crate) async fn reserve(
        &self,
        key: &str,
        account: &Account,
    ) -> Result<bool, ProtocolError> {
        let scheduling = self.scheduling();
        let new = {
            let mut live = self
                .live
                .lock()
                .map_err(|_| ProtocolError::Invalid("schedule.lock"))?;
            let idle = Duration::from_secs(scheduling.idle_timeout_secs);
            live.retain(|k, v| {
                v.last.elapsed() < idle
                    || self.sessions.get(k).is_some_and(|s| s.try_lock().is_err())
            });
            let fresh = live.get(key).is_none_or(|v| v.account != account.id());
            let age = now_ms().saturating_sub(account.created_at_unix_ms()) / 3_600_000;
            let band = match age {
                0 => 0,
                1 => 1,
                2..=3 => 2,
                4..=23 => 3,
                _ => 4,
            };
            let max = scheduling.max_sessions_by_account_age[band];
            if fresh && live.values().filter(|v| v.account == account.id()).count() >= max {
                return Err(ProtocolError::Capacity("account.sessions"));
            }
            if fresh
                && account
                    .availability()
                    .map_err(|_| ProtocolError::Invalid("account.state"))?
                    .resting
            {
                return Err(ProtocolError::Capacity("account.resting"));
            }
            live.insert(
                key.to_owned(),
                Live {
                    account: account.id().into(),
                    last: Instant::now(),
                },
            );
            fresh
        };
        if new {
            let gate = {
                self.starts
                    .lock()
                    .map_err(|_| ProtocolError::Invalid("schedule.lock"))?
                    .entry(account.id().into())
                    .or_insert_with(|| Arc::new(AsyncMutex::new(Instant::now())))
                    .clone()
            };
            let mut gate = gate.lock().await;
            let spacing = Duration::from_secs(scheduling.startup_spacing_secs);
            if *gate > Instant::now() {
                tokio::time::sleep_until((*gate).into()).await;
            }
            *gate = Instant::now() + spacing;
        }
        Ok(new)
    }
}
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/responses",
            post(responses).get(crate::websocket::upgrade),
        )
        .merge(crate::auxiliary::router())
        .route_layer(middleware::from_fn(crate::ingress::decode_json))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::admission::require_oauth_peer,
        ))
        .merge(crate::admin::router())
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(crate::ingress::BODY_LIMIT))
        .with_state(state)
}
async fn health() -> Json<Value> {
    Json(
        json!({"status":"ok","project":"right-codex","codex_version":crate::CODEX_VERSION,"source_commit":crate::CODEX_SOURCE_COMMIT,"runtime":"direct_protocol","qualification":"implementation_under_verification"}),
    )
}
pub(crate) fn error(status: StatusCode, code: &str, english: &str, chinese: &str) -> Response {
    (
        status,
        Json(json!({"error":{"code":code,"message":format!("{english} / {chinese}")}})),
    )
        .into_response()
}
pub(crate) fn protocol_error(reason: ProtocolError) -> Response {
    // Protocol errors contain closed field paths and categories, not bodies or credentials.
    tracing::warn!(reason = %reason, "gateway protocol validation rejected a request");
    if matches!(reason, ProtocolError::Capacity(_)) {
        let mut r = error(
            StatusCode::SERVICE_UNAVAILABLE,
            "session_capacity_exceeded",
            "Gateway conversation capacity exhausted",
            "网关会话容量已满",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, http::HeaderValue::from_static("2"));
        return r;
    }
    error(
        StatusCode::BAD_REQUEST,
        "unsupported_business_request",
        "Request identity or history lacks verified provenance, or request format is invalid",
        "请求身份或历史缺少可信来源，或请求格式无效",
    )
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
/// The client's native turn is a local deduplication key only. It is never an
/// outbound identifier: Session assigns a separate account-owned random turn.
pub(crate) fn logical_turn(namespace: &str, input: &Value, headers: &HeaderMap) -> String {
    let Some(turn) = metadata::classify_request(input, headers)
        .ok()
        .and_then(|m| m.client_turn_id)
    else {
        return Uuid::new_v4().to_string();
    };
    let mut hash = Sha256::new();
    hash.update(namespace.len().to_be_bytes());
    hash.update(namespace.as_bytes());
    hash.update(turn.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes).to_string()
}
pub struct Scope {
    pub key: String,
    pub namespace: String,
    pub session: Arc<AsyncMutex<Session>>,
}
#[expect(
    clippy::result_large_err,
    reason = "Axum boundary retains its native response, without another allocation"
)]
pub(crate) fn scope(
    state: &AppState,
    headers: &HeaderMap,
    input: &Value,
) -> Result<Scope, Response> {
    let meta = metadata::classify_request(input, headers).map_err(|reason| {
        tracing::warn!(shape = %metadata::diagnostic_shape(input, headers), "native metadata validation shape");
        protocol_error(reason)
    })?;
    let thread = meta
        .client_thread_id
        .clone()
        .or_else(|| {
            ["thread-id", "session-id"].iter().find_map(|n| {
                headers
                    .get(*n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            })
        })
        .or_else(|| {
            (meta.kind == metadata::RequestKind::Memory).then(|| Uuid::new_v4().to_string())
        })
        .ok_or_else(|| {
            error(
                StatusCode::BAD_REQUEST,
                "session_required",
                "A native conversation identity is required",
                "需要原生对话身份",
            )
        })?;
    let namespace = crate::admission::local_principal(headers, &state.domain);
    let key = SessionStore::local_key(&namespace, &thread);
    if state
        .sessions
        .get_or_load_scope(&key, &state.scope_dir)
        .map_err(protocol_error)?
        .is_none()
    {
        let parent = match meta.client_parent_thread_id.as_deref() {
            Some(thread) => state
                .sessions
                .scope_owner(
                    &SessionStore::local_key(&namespace, thread),
                    &state.scope_dir,
                )
                .map_err(protocol_error)?,
            None => None,
        };
        let account = parent
            .and_then(|(id, revision)| {
                state
                    .accounts
                    .by_id(&id)
                    .ok()
                    .flatten()
                    .filter(|account| account.revision() == revision)
            })
            .or_else(|| state.accounts.next_enabled().ok().flatten())
            .ok_or_else(no_account)?;
        state
            .sessions
            .get_or_insert(key.clone(), account.id().into(), account.revision().into())
            .ok_or_else(|| protocol_error(ProtocolError::Capacity("session.store")))?;
    }
    Ok(Scope {
        key: key.clone(),
        namespace,
        session: state.sessions.get(&key).ok_or_else(no_account)?,
    })
}
pub(crate) fn persist(state: &AppState, key: &str, session: &Session) -> Result<(), ProtocolError> {
    crate::storage::save(&state.scope_dir, key, session)
}
pub(crate) fn no_account() -> Response {
    let mut r = error(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_available_account",
        "No eligible OAuth account",
        "没有满足条件的 OAuth 账号",
    );
    r.headers_mut()
        .insert(header::RETRY_AFTER, http::HeaderValue::from_static("5"));
    r
}
pub(crate) fn provider(
    state: &AppState,
    _account: &Account,
    base: String,
    mut headers: HeaderMap,
) -> Provider {
    headers.insert(
        "originator",
        http::HeaderValue::from_str(&codex_login::default_client::originator().value)
            .expect("official originator"),
    );
    headers.insert(
        header::USER_AGENT,
        http::HeaderValue::from_str(&codex_login::default_client::get_codex_user_agent())
            .expect("official UA"),
    );
    Provider {
        name: "OpenAI".into(),
        base_url: base,
        query_params: None,
        headers,
        retry: RetryConfig {
            max_attempts: 0,
            base_delay: Duration::from_millis(200),
            retry_429: false,
            retry_5xx: false,
            retry_transport: false,
        },
        stream_idle_timeout: Duration::from_secs(state.config.request_timeout_secs),
    }
}
pub(crate) struct Conversation {
    pub state: Arc<AppState>,
    pub key: String,
    pub namespace: String,
    pub session: OwnedMutexGuard<Session>,
    pub current: Option<String>,
}
impl Drop for Conversation {
    fn drop(&mut self) {
        if let Some(id) = self.current.take() {
            let _ = self.session.mark_unknown(&id);
            let _ = persist(&self.state, &self.key, &self.session);
        }
    }
}
impl Conversation {
    pub(crate) async fn acquire(state: Arc<AppState>, scope: Scope) -> Result<Self, Response> {
        let session = tokio::time::timeout(
            Duration::from_secs(state.config.queue_timeout_secs),
            scope.session.lock_owned(),
        )
        .await
        .map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "conversation_queue_timeout",
                "Conversation request queue expired",
                "对话请求排队超时",
            )
        })?;
        Ok(Self {
            state,
            key: scope.key,
            namespace: scope.namespace,
            session,
            current: None,
        })
    }
    pub(crate) async fn account(
        &mut self,
        excluded: &HashSet<String>,
    ) -> Result<(Arc<Account>, AccountLease), Response> {
        let mut excluded = excluded.clone();
        loop {
            let account = if !excluded.contains(&self.session.account_id) {
                self.state
                    .accounts
                    .by_id(&self.session.account_id)
                    .ok()
                    .flatten()
            } else {
                None
            }
            .or_else(|| {
                self.state
                    .accounts
                    .next_eligible_excluding(&excluded)
                    .ok()
                    .flatten()
            })
            .ok_or_else(no_account)?;
            if self.session.account_id != account.id()
                || self.session.auth_revision != account.revision()
            {
                self.session
                    .switch_account(account.id().into(), account.revision().into())
                    .map_err(protocol_error)?;
                persist(&self.state, &self.key, &self.session).map_err(protocol_error)?;
            }
            let new = match tokio::time::timeout(
                Duration::from_secs(self.state.config.queue_timeout_secs),
                self.state.reserve(&self.key, &account),
            )
            .await
            {
                Ok(Ok(v)) => v,
                _ => {
                    excluded.insert(account.id().into());
                    continue;
                }
            };
            match self.state.accounts.lease(account.id(), new) {
                Ok(Some(lease)) => {
                    // reserve awaited; a serialized OAuth refresh may have
                    // published a newer account snapshot during that wait.
                    if lease.account().revision() != account.revision() {
                        drop(lease);
                        continue;
                    }
                    return Ok((account, lease));
                }
                _ => {
                    excluded.insert(account.id().into());
                }
            }
        }
    }
}
pub(crate) struct Active {
    pub id: String,
    pub account: Arc<Account>,
    pub journal: Arc<Mutex<AttemptJournal>>,
    pub hooks: Arc<AccountTelemetry>,
    pub fact: Option<Attempt>,
    pub _lease: AccountLease,
    pub parser: Option<ParserGuard>,
    pub is_compaction: bool,
    sse_barrier: Arc<SseBarrier>,
    raw_sse_events: u64,
}
#[derive(Default)]
struct SseBarrier {
    observed: AtomicU64,
    changed: Notify,
}
impl Active {
    /// Both parsers consume the same bytes. Wait for the official hook of this
    /// event before closing its attempt, rather than racing the raw-wire tee.
    async fn observe_sse(&mut self) -> bool {
        self.raw_sse_events += 1;
        let target = self.raw_sse_events;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.sse_barrier.changed.notified();
                if self.sse_barrier.observed.load(Ordering::Acquire) >= target {
                    break;
                }
                changed.await;
            }
        })
        .await
        .is_ok()
    }
    pub(crate) fn finish(&mut self, outcome: TerminalKind, label: &str, offered: bool) {
        if let Ok(mut j) = self.journal.lock() {
            let _ = j.finish(outcome, offered);
        }
        if let Some(fact) = self.fact.take() {
            fact.finish(label);
        }
    }
    pub(crate) fn event(&mut self, raw: &str, value: &Value) {
        if let Some(f) = &mut self.fact {
            f.event(value);
        }
        if let Ok(mut j) = self.journal.lock() {
            let _ = j.stream_event(value["type"].as_str().unwrap_or("unknown"), raw.as_bytes());
        }
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        if self.fact.is_some() {
            self.finish(TerminalKind::Unknown, "transport_outcome_unknown", false);
        }
    }
}
pub(crate) struct StartFailure {
    pub response: Response,
    pub status: Option<StatusCode>,
}
/// Both the preflight and committed request use the same protected parent
/// lookup, including a busy parent's actual persisted delivery observations.
#[expect(clippy::result_large_err, reason = "native Axum error boundary")]
pub(crate) fn parent_request_proof(
    conversation: &Conversation,
    input: &Value,
    headers: &HeaderMap,
) -> Result<Option<crate::metadata::ParentMetadataProof>, Response> {
    let meta = metadata::classify_request(input, headers).map_err(protocol_error)?;
    let parent = meta.client_parent_thread_id.as_deref().and_then(|p| {
        conversation
            .state
            .sessions
            .parent_proof_for_response(
                &conversation.namespace,
                p,
                &conversation.session.account_id,
                &conversation.session.auth_revision,
                meta.client_parent_response_id.clone(),
            )
            .or_else(|| {
                conversation.state.sessions.parent_proof_from_file(
                    &conversation.namespace,
                    p,
                    &conversation.session.account_id,
                    &conversation.session.auth_revision,
                    meta.client_parent_response_id.clone(),
                    &conversation.state.scope_dir,
                )
            })
    });
    Ok(parent)
}
#[expect(clippy::result_large_err, reason = "native Axum error boundary")]
pub(crate) fn preflight(
    conversation: &Conversation,
    input: &Value,
    headers: &HeaderMap,
    turn: &str,
) -> Result<(), Response> {
    let parent = parent_request_proof(conversation, input, headers)?;
    conversation
        .session
        .prepare_request_with_parent(input.clone(), headers, turn, parent.as_ref())
        .map(|_| ())
        .map_err(protocol_error)
}
#[expect(
    clippy::result_large_err,
    reason = "Axum boundary retains its native response, without another allocation"
)]
pub(crate) fn prepare(
    conversation: &mut Conversation,
    input: Value,
    headers: &HeaderMap,
    logical_turn: &str,
) -> Result<crate::session::ScopedRequest, Response> {
    let parent = parent_request_proof(conversation, &input, headers)?;
    let prepared = conversation
        .session
        .prepare_request_with_parent(input, headers, logical_turn, parent.as_ref())
        .map_err(protocol_error)?;
    let mut scoped = conversation
        .session
        .commit_request(prepared)
        .map_err(protocol_error)?;
    if scoped.metadata.kind != metadata::RequestKind::Memory {
        scoped
            .outbound_headers
            .extend(codex_api::build_session_headers(
                Some(conversation.session.session_id.clone()),
                Some(conversation.session.thread_id.clone()),
            ));
        scoped.outbound_headers.insert(
            "x-client-request-id",
            http::HeaderValue::from_str(&conversation.session.thread_id)
                .map_err(|_| protocol_error(ProtocolError::Invalid("session.header")))?,
        );
    }
    conversation.current = Some(scoped.attempt_id.clone());
    persist(
        &conversation.state,
        &conversation.key,
        &conversation.session,
    )
    .map_err(protocol_error)?;
    conversation
        .session
        .mark_sending(&scoped.attempt_id)
        .map_err(protocol_error)?;
    persist(
        &conversation.state,
        &conversation.key,
        &conversation.session,
    )
    .map_err(protocol_error)?;
    Ok(scoped)
}
#[expect(
    clippy::result_large_err,
    reason = "Axum boundary retains its native response, without another allocation"
)]
pub(crate) fn observe(
    conversation: &Conversation,
    account: Arc<Account>,
    lease: AccountLease,
    scoped: &crate::session::ScopedRequest,
    endpoint: &str,
    wire_hash: String,
) -> Result<Active, Response> {
    let canonical = metadata::classify_request(&scoped.request.body, &scoped.outbound_headers)
        .map_err(protocol_error)?;
    let turn = canonical
        .client_turn_id
        .ok_or_else(|| protocol_error(ProtocolError::Invalid("outbound.turn")))?;
    let encoded = EncodedJsonBody::encode(&scoped.request.body)
        .map_err(|_| protocol_error(ProtocolError::Invalid("encoding")))?;
    let logical = format!("{:x}", Sha256::digest(encoded.as_bytes()));
    let identity = OutboundIdentity {
        account_id: account.id().into(),
        workspace_account_id: account.workspace_account_id().into(),
        auth_revision: account.revision().into(),
        thread_id: conversation.session.thread_id.clone(),
        turn_id: turn.clone(),
        attempt_id: scoped.attempt_id.clone(),
        endpoint: if endpoint.starts_with('/') {
            endpoint.into()
        } else {
            format!("/{endpoint}")
        },
    };
    let journal = Arc::new(Mutex::new(
        conversation
            .state
            .ledger
            .begin(identity.clone(), &logical, &wire_hash)
            .map_err(|_| protocol_error(ProtocolError::Invalid("ledger")))?,
    ));
    let model = scoped.request.body["model"].as_str().unwrap_or("unknown");
    let hooks = conversation
        .state
        .metrics
        .for_account(&account, identity, model, model)
        .map_err(|_| protocol_error(ProtocolError::Invalid("metrics")))?;
    let j = journal.clone();
    let sse_barrier = Arc::new(SseBarrier::default());
    let barrier = sse_barrier.clone();
    let _ = hooks.set_observer(Arc::new(move |event| {
        if let Ok(mut journal) = j.lock() {
            let _ = journal.observe_hook(&event);
        }
        if matches!(
            event.kind,
            NetworkEventKind::SsePoll {
                outcome: SsePollOutcome::Event(_),
                ..
            }
        ) {
            barrier.observed.fetch_add(1, Ordering::Release);
            barrier.changed.notify_one();
        }
    }));
    let mut fact = conversation.state.facts.start(
        account.id(),
        account.revision(),
        &conversation.session.thread_id,
        &turn,
    );
    let _ = fact.set_attempt_id(&scoped.attempt_id);
    fact.request_hashes(logical, wire_hash);
    Ok(Active {
        id: scoped.attempt_id.clone(),
        account,
        journal,
        hooks,
        fact: Some(fact),
        _lease: lease,
        parser: None,
        is_compaction: scoped.request.is_compaction,
        sse_barrier,
        raw_sse_events: 0,
    })
}
async fn start(
    conversation: &mut Conversation,
    input: Value,
    headers: &HeaderMap,
    turn: &str,
    excluded: &HashSet<String>,
) -> Result<(Active, WireResponse), StartFailure> {
    let make = |response| StartFailure {
        response,
        status: None,
    };
    // Invalid local histories do not reserve a new active conversation slot.
    preflight(conversation, &input, headers, turn).map_err(make)?;
    let (account, lease) = conversation.account(excluded).await.map_err(make)?;
    let route = account
        .responses_route(&conversation.state.config.base_url)
        .await
        .map_err(|e| routing_failure(&conversation.state, &account, e))?;
    let scoped = prepare(conversation, input, headers, turn).map_err(make)?;
    let mut route_headers = HeaderMap::new();
    if let Some(value) = route.account_routing_override {
        route_headers.insert(
            "x-openai-account-routing-override",
            http::HeaderValue::from_str(&value).map_err(|_| make(no_account()))?,
        );
    }
    let provider = provider(&conversation.state, &account, route.base_url, route_headers);
    let mut preview = provider.build_request(http::Method::POST, "/responses");
    preview.body = Some(RequestBody::EncodedJson(
        EncodedJsonBody::encode(&scoped.request.body)
            .map_err(|_| make(protocol_error(ProtocolError::Invalid("encoding"))))?,
    ));
    preview.compression = RequestCompression::Zstd;
    let preview = preview
        .into_prepared()
        .map_err(|_| make(protocol_error(ProtocolError::Invalid("compression"))))?;
    let hash = match preview.body {
        Some(RequestBody::EncodedJson(b)) => format!("{:x}", Sha256::digest(b.as_bytes())),
        _ => unreachable!(),
    };
    let expected_wire = hash.clone();
    let expected_logical = format!(
        "{:x}",
        Sha256::digest(
            EncodedJsonBody::encode(&scoped.request.body)
                .map_err(|_| make(protocol_error(ProtocolError::Invalid("encoding"))))?
                .as_bytes()
        )
    );
    let mut active = observe(
        conversation,
        account.clone(),
        lease,
        &scoped,
        "/responses",
        hash,
    )
    .map_err(make)?;
    let (transport, receiver) = ObservedTransport::new(
        account.client().clone(),
        Duration::from_secs(conversation.state.config.request_timeout_secs),
    );
    let cancel = transport.cancellation();
    let raw_error = transport.http_error();
    let sdk = ResponsesClient::new(transport, provider, account.auth_provider()).with_telemetry(
        Some(active.hooks.request_hook()),
        Some(active.hooks.sse_hook()),
    );
    let sent_at = Instant::now();
    let semantic = match sdk
        .stream(
            scoped.request.body,
            scoped.outbound_headers,
            Compression::Zstd,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            let raw = raw_error.lock().ok().and_then(|mut value| value.take());
            if let Some(source) = &raw
                && crate::upstream_policy::observe_raw_http(
                    &conversation.state.accounts,
                    &account,
                    source,
                )
                .is_err()
            {
                tracing::warn!("upstream account status persistence failed");
            }
            let status = match &e {
                ApiError::Transport(TransportError::Http { status, .. }) => Some(*status),
                ApiError::Api { status, .. } => Some(*status),
                _ => None,
            };
            let request_id = match &e {
                ApiError::Transport(TransportError::Http {
                    headers: Some(h), ..
                }) => h.get("x-request-id").and_then(|v| v.to_str().ok()),
                _ => None,
            };
            if let Some(status) = status {
                if let Some(f) = &mut active.fact {
                    f.response(status.as_u16(), request_id.map(str::to_owned));
                }
                if let Ok(mut j) = active.journal.lock() {
                    let _ = j.http_response(status.as_u16(), request_id, sent_at.elapsed());
                }
            }
            active.finish(
                if status.is_some() {
                    TerminalKind::Failed
                } else {
                    TerminalKind::Unknown
                },
                if status.is_some() {
                    "http_rejected"
                } else {
                    "transport_outcome_unknown"
                },
                false,
            );
            if let Some(source) = raw.as_ref().filter(|v| v.complete) {
                let body_sha = format!("{:x}", Sha256::digest(&source.body));
                let _ = conversation.session.fail_http_attempt(
                    &active.id,
                    source.status.as_u16(),
                    &body_sha,
                );
            } else {
                let _ = conversation.session.mark_unknown(&active.id);
            }
            let _ = persist(
                &conversation.state,
                &conversation.key,
                &conversation.session,
            );
            conversation.current = None;
            return Err(StartFailure {
                response: raw
                    .map(crate::transport::RawHttpError::into_response)
                    .unwrap_or_else(|| upstream_error(e)),
                status,
            });
        }
    };
    let task = tokio::spawn(async move {
        let mut stream = semantic;
        while stream.next().await.is_some() {}
    });
    active.parser = Some(ParserGuard { task, cancel });
    let wire = receiver.await.map_err(|_| {
        make(error(
            StatusCode::BAD_GATEWAY,
            "wire_observer_failed",
            "Source stream observation failed",
            "源流观察失败",
        ))
    })?;
    if wire.logical_sha != expected_logical || wire.wire_sha != expected_wire {
        return Err(make(error(
            StatusCode::BAD_GATEWAY,
            "wire_identity_mismatch",
            "Observed request differs from committed request",
            "实际出站与已提交请求不一致",
        )));
    }
    if let Some(f) = &mut active.fact {
        f.response(
            wire.status.as_u16(),
            wire.headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        );
    }
    if let Ok(mut j) = active.journal.lock() {
        let _ = j.http_response(
            wire.status.as_u16(),
            wire.headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            sent_at.elapsed(),
        );
    }
    if let Some(sticky) = wire
        .headers
        .get("x-codex-turn-state")
        .and_then(|v| v.to_str().ok())
    {
        let _ = conversation.session.set_sticky_from_upstream(
            account.id(),
            account.revision(),
            sticky.to_owned(),
        );
    }
    Ok((active, wire))
}
/// A client request has one source attempt. Only a later client request can
/// select another eligible account; an upstream error never triggers replay.
async fn start_once(
    conversation: &mut Conversation,
    input: Value,
    headers: &HeaderMap,
    turn: &str,
) -> Result<(Active, WireResponse), Response> {
    match start(conversation, input, headers, turn, &HashSet::new()).await {
        Ok((mut active, wire)) => {
            if !wire
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("text/event-stream"))
            {
                active.finish(
                    TerminalKind::Unknown,
                    "invalid_response_content_type",
                    false,
                );
                return Err(error(
                    StatusCode::BAD_GATEWAY,
                    "invalid_upstream_stream",
                    "Upstream did not return SSE",
                    "上游没有返回 SSE",
                ));
            }
            Ok((active, wire))
        }
        Err(failure) => {
            if let Some(id) = conversation.current.take() {
                let _ = conversation.session.mark_unknown(&id);
                if persist(
                    &conversation.state,
                    &conversation.key,
                    &conversation.session,
                )
                .is_err()
                {
                    tracing::warn!("failed request state persistence failed");
                }
            }
            Err(failure.response)
        }
    }
}
pub(crate) fn routing_failure(
    state: &AppState,
    account: &Account,
    error: crate::routing::RoutingError,
) -> StartFailure {
    if let crate::routing::RoutingError::Upstream(source) = error {
        if crate::upstream_policy::observe_raw_http(&state.accounts, account, &source).is_err() {
            tracing::warn!("upstream account status persistence failed");
        }
        return StartFailure {
            status: Some(source.status),
            response: source.into_response(),
        };
    }
    StartFailure {
        status: None,
        response: error_response_for_route(),
    }
}
fn error_response_for_route() -> Response {
    error(
        StatusCode::BAD_GATEWAY,
        "account_route_unavailable",
        "Account route unavailable",
        "账号出口不可用",
    )
}
fn upstream_error(e: ApiError) -> Response {
    if let ApiError::Transport(TransportError::Http {
        status,
        headers,
        body,
        retry_after,
        ..
    }) = e
    {
        return crate::transport::RawHttpError {
            status,
            retry_after,
            headers: headers.unwrap_or_default(),
            body: body.unwrap_or_default().into_bytes(),
            complete: true,
        }
        .into_response();
    }
    error(
        StatusCode::BAD_GATEWAY,
        "upstream_transport_error",
        "Upstream connection failed",
        "上游连接失败",
    )
}
async fn responses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    let Json(input) = match payload {
        Ok(v) => v,
        Err(e) => {
            return error(
                e.status(),
                "invalid_request_json",
                "A valid bounded JSON request is required",
                "需要有效且未超过限制的 JSON 请求",
            );
        }
    };
    let scope = match scope(&state, &headers, &input) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut conversation = match Conversation::acquire(state.clone(), scope).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let logical_turn = logical_turn(&conversation.namespace, &input, &headers);
    let (mut active, wire) =
        match start_once(&mut conversation, input, &headers, &logical_turn).await {
            Ok(started) => started,
            Err(response) => return response,
        };
    let downstream_headers = crate::response_projection::project_response_headers(&wire.headers);
    let stream = async_stream::stream! {
        let mut events=wire.bytes.eventsource();let mut v2=V2Completion::default();
        loop {
            let event=match tokio::time::timeout(Duration::from_secs(state.config.request_timeout_secs),events.next()).await {
                Ok(Some(Ok(e)))=>e,Ok(Some(Err(_)))=>{active.finish(TerminalKind::Unknown,"invalid_upstream_sse",false);yield Ok::<Event,Infallible>(failure_event("invalid_upstream_sse"));return;},_=>{active.finish(TerminalKind::Unknown,"stream_incomplete",false);yield Ok(failure_event("upstream_stream_incomplete"));return;}
            };
            if !active.observe_sse().await {active.finish(TerminalKind::Unknown,"official_sse_observation_incomplete",false);yield Ok(failure_event("official_sse_observation_incomplete"));return;}
            if event.data.is_empty()||event.data=="[DONE]"{continue;}
            let mut value:Value=match serde_json::from_str(&event.data){Ok(v)=>v,Err(_)=>{active.finish(TerminalKind::Unknown,"invalid_upstream_json",false);yield Ok(failure_event("invalid_upstream_json"));return;}};
            active.event(&event.data,&value);
            if crate::upstream_policy::observe_event(&state.accounts,&active.account,&value).is_err() {
                tracing::warn!("upstream account status persistence failed");
            }
            if active.is_compaction&&v2.observe(&value).is_err(){active.finish(TerminalKind::Unknown,"invalid_compaction_response",false);yield Ok(failure_event("invalid_compaction_response"));return;}
            let kind=value["type"].as_str().unwrap_or("").to_owned();let complete=kind=="response.completed";
            if complete&&active.is_compaction&&v2.finish().is_err(){active.finish(TerminalKind::Unknown,"invalid_compaction_response",false);yield Ok(failure_event("invalid_compaction_response"));return;}
            let source_error=matches!(kind.as_str(),"error"|"response.failed");
            if conversation.session.rewrite_event(&mut value).is_err(){
                if source_error { crate::response_projection::sanitize_http_error(&mut value);tracing::warn!("source error identity aliases unavailable"); }
                else {active.finish(TerminalKind::Unknown,"invalid_upstream_identity",false);yield Ok(failure_event("invalid_upstream_identity"));return;}
            }
            match conversation.session.record_delivery(&value){
                Ok(ToolDelivery::AlreadyDelivered) if !source_error=>continue,
                Ok(_)=>{},
                Err(_) if source_error=>{tracing::warn!("source error delivery journal unavailable");},
                Err(_)=>{active.finish(TerminalKind::Unknown,"delivery_state_failed",false);yield Ok(failure_event("delivery_state_failed"));return;}
            }
            let terminal=matches!(kind.as_str(),"response.completed"|"response.incomplete"|"response.failed"|"error");
            if terminal {
                if matches!(kind.as_str(),"error"|"response.failed") {
                    if conversation.session.fail_attempt(&active.id,&value).is_err() { tracing::warn!("failed stream terminal persistence unavailable"); }
                } else if conversation.session.finish_attempt(&active.id,&value).is_err(){active.finish(TerminalKind::Unknown,"invalid_completion",false);yield Ok(failure_event("invalid_completion"));return;}
                let outcome=if complete{TerminalKind::Completed}else if kind=="response.incomplete"{TerminalKind::Incomplete}else{TerminalKind::Failed};
                let label=if complete{"completed"}else if kind=="response.incomplete"{if value["response"]["incomplete_details"]["reason"]=="interrupted"{"interrupted"}else{"response_incomplete"}}else{"response_failed"};
                if persist(&state,&conversation.key,&conversation.session).is_err(){
                    if matches!(kind.as_str(),"error"|"response.failed") { tracing::warn!("failed stream terminal persistence unavailable"); }
                    else {active.finish(TerminalKind::Unknown,"persistence_failed",false);yield Ok(failure_event("persistence_failed"));return;}
                }
                conversation.current=None;if complete {active.hooks.record_verified_completion_usage(&value);}active.finish(outcome,label,true);drop(active);drop(conversation);
                let mut output=Event::default().data(value.to_string());if !event.event.is_empty(){output=output.event(event.event);}yield Ok(output);return;
            }
            if persist(&state,&conversation.key,&conversation.session).is_err(){active.finish(TerminalKind::Unknown,"persistence_failed",false);yield Ok(failure_event("persistence_failed"));return;}
            let mut output=Event::default().data(value.to_string());if !event.event.is_empty(){output=output.event(event.event);}yield Ok(output);
        }
    };
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
        .into_response();
    response.headers_mut().extend(downstream_headers);
    response
}
pub(crate) fn failure_value(code: &str) -> Value {
    json!({"type":"error","error":{"code":code,"message":"Upstream stream could not complete / 上游流未完成"}})
}
fn failure_event(code: &str) -> Event {
    Event::default()
        .event("error")
        .data(failure_value(code).to_string())
}
