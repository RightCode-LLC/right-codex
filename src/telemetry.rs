use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::accounts::Account;

/// First-stage private audit facts. These are not official Analytics events or
/// proof that a client tool executed. No bearer or outbound request body is
/// retained here. Raw usage metadata is size bounded. Remote export is absent.
#[derive(Clone, Serialize)]
pub struct HttpFact {
    pub attempt_id: String,
    pub account_id: String,
    pub auth_revision: String,
    pub thread_id: String,
    pub turn_id: String,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub request_sha256: String,
    pub wire_sha256: String,
    pub status: Option<u16>,
    pub upstream_request_id: Option<String>,
    pub upstream_response_id: Option<String>,
    pub event_count: usize,
    pub usage: Option<Value>,
    pub usage_exceeded_budget: bool,
    pub outcome: String,
}

#[derive(Default)]
pub struct FactStore {
    rows: Mutex<VecDeque<HttpFact>>,
}

impl FactStore {
    fn insert(&self, row: HttpFact) {
        if let Ok(mut rows) = self.rows.lock() {
            if rows.len() == 1024 {
                rows.pop_front();
            }
            rows.push_back(row);
        }
    }

    pub fn snapshot(&self) -> Vec<HttpFact> {
        self.rows
            .lock()
            .map(|rows| rows.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn start(
        self: &Arc<Self>,
        account: &str,
        revision: &str,
        thread: &str,
        turn: &str,
    ) -> Attempt {
        Attempt {
            store: self.clone(),
            started: Instant::now(),
            identity_locked: false,
            row: Some(HttpFact {
                attempt_id: Uuid::new_v4().to_string(),
                account_id: account.to_owned(),
                auth_revision: revision.to_owned(),
                thread_id: thread.to_owned(),
                turn_id: turn.to_owned(),
                started_at_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                duration_ms: 0,
                request_sha256: String::new(),
                wire_sha256: String::new(),
                status: None,
                upstream_request_id: None,
                upstream_response_id: None,
                event_count: 0,
                usage: None,
                usage_exceeded_budget: false,
                outcome: "unknown_or_cancelled".into(),
            }),
        }
    }
}

pub struct Attempt {
    store: Arc<FactStore>,
    started: Instant,
    identity_locked: bool,
    row: Option<HttpFact>,
}

impl Attempt {
    /// Bind the old in-memory diagnostic row to the durable outbound attempt.
    /// This must happen once, before hashes, response status, or events arrive.
    pub fn set_attempt_id(&mut self, attempt_id: &str) -> Result<(), LedgerError> {
        if self.identity_locked || Uuid::parse_str(attempt_id).is_err() {
            return Err(LedgerError::InvalidIdentity);
        }
        let row = self.row.as_mut().ok_or(LedgerError::AlreadyTerminal)?;
        if !row.request_sha256.is_empty()
            || !row.wire_sha256.is_empty()
            || row.status.is_some()
            || row.event_count != 0
        {
            return Err(LedgerError::InvalidIdentity);
        }
        row.attempt_id = attempt_id.to_owned();
        self.identity_locked = true;
        Ok(())
    }

    pub fn request_hashes(&mut self, logical: String, wire: String) {
        if let Some(row) = &mut self.row {
            row.request_sha256 = logical;
            row.wire_sha256 = wire;
        }
    }
    pub fn response(&mut self, status: u16, request_id: Option<String>) {
        if let Some(row) = &mut self.row {
            row.status = Some(status);
            row.upstream_request_id = request_id;
        }
    }
    pub fn event(&mut self, value: &Value) {
        if let Some(row) = &mut self.row {
            row.event_count += 1;
            if matches!(
                value["type"].as_str(),
                Some("response.completed" | "response.incomplete")
            ) {
                row.upstream_response_id = value["response"]["id"]
                    .as_str()
                    .filter(|id| {
                        !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
                    })
                    .map(str::to_owned);
                if let Some(usage) = value["response"]
                    .get("usage")
                    .filter(|usage| !usage.is_null())
                {
                    if serde_json::to_vec(usage).is_ok_and(|bytes| bytes.len() <= 64 * 1024) {
                        row.usage = Some(usage.clone());
                    } else {
                        row.usage_exceeded_budget = true;
                    }
                }
            }
        }
    }
    pub fn finish(mut self, outcome: &str) {
        if let Some(mut row) = self.row.take() {
            row.outcome = outcome.to_owned();
            row.duration_ms = self.started.elapsed().as_millis() as u64;
            self.store.insert(row);
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(mut row) = self.row.take() {
            row.duration_ms = self.started.elapsed().as_millis() as u64;
            self.store.insert(row);
        }
    }
}

/// Identity after the gateway has selected a real OAuth account and built its
/// own outbound request. The original client identifiers never belong here.
/// Neither this type nor the token-bearing account type implements Serialize.
#[derive(Clone)]
pub struct OutboundIdentity {
    pub account_id: String,
    pub workspace_account_id: String,
    pub auth_revision: String,
    pub thread_id: String,
    pub turn_id: String,
    pub attempt_id: String,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct LedgerPolicy {
    pub max_events_per_attempt: usize,
    pub max_batch: usize,
    pub export_ttl: Duration,
    pub retry_backoff: Duration,
}

impl Default for LedgerPolicy {
    fn default() -> Self {
        Self {
            max_events_per_attempt: 4_096,
            max_batch: 128,
            export_ttl: Duration::from_secs(86_400),
            retry_backoff: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("private telemetry storage is unavailable")]
    Storage,
    #[error("telemetry identity is invalid")]
    InvalidIdentity,
    #[error("telemetry event exceeds the configured budget")]
    EventBudget,
    #[error("telemetry attempt is already terminal")]
    AlreadyTerminal,
    #[error("completed response has no observed upstream completion")]
    MissingCompletion,
    #[error("telemetry export destination is invalid")]
    InvalidExportDestination,
    #[error("telemetry export is deferred")]
    ExportDeferred,
    #[error("account is not accepting telemetry export")]
    AccountInactive,
    #[error("telemetry export failed")]
    ExportFailed,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// Hash of a local account slot; never an imported OAuth token or account ID.
    pub account_key: String,
    pub workspace_account_sha256: String,
    pub auth_revision: String,
    pub thread_id: String,
    pub turn_id: String,
    pub attempt_id: String,
    pub endpoint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    Completed,
    /// One-shot SDK endpoint with an observed successful HTTP response.
    HttpCompleted,
    Failed,
    Incomplete,
    Cancelled,
    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkFact {
    Started {
        identity: StoredIdentity,
        request_sha256: String,
        wire_sha256: String,
        at_ms: u64,
    },
    HttpResponse {
        status: u16,
        upstream_request_id: Option<String>,
        duration_ms: u64,
        at_ms: u64,
    },
    WebSocketConnectionUsed {
        connection_id: String,
        reused: bool,
        at_ms: u64,
    },
    StreamEvent {
        ordinal: u64,
        event_kind: String,
        event_sha256: String,
        response_id: Option<String>,
        usage: Option<Value>,
        usage_exceeded_budget: bool,
        at_ms: u64,
    },
    StreamBudgetExceeded {
        at_ms: u64,
    },
    HookObservation {
        source: String,
        detail: String,
        sdk_attempt: Option<u64>,
        status: Option<u16>,
        duration_ms: u64,
        at_ms: u64,
    },
    Terminal {
        outcome: TerminalKind,
        /// The gateway offered a terminal event to its response body. This is
        /// not proof that the remote client consumed it.
        offered_to_client: bool,
        at_ms: u64,
    },
}

impl NetworkFact {
    fn timestamp_ms(&self) -> u64 {
        match self {
            Self::Started { at_ms, .. }
            | Self::HttpResponse { at_ms, .. }
            | Self::WebSocketConnectionUsed { at_ms, .. }
            | Self::StreamEvent { at_ms, .. }
            | Self::StreamBudgetExceeded { at_ms }
            | Self::HookObservation { at_ms, .. }
            | Self::Terminal { at_ms, .. } => *at_ms,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NumberedFact {
    pub fact_id: String,
    pub ordinal: u64,
    pub fact: NetworkFact,
}

#[derive(Clone)]
pub struct AttemptSnapshot {
    pub identity: StoredIdentity,
    pub facts: Vec<NumberedFact>,
    /// A missing terminal after process loss is unknown; no inferred success.
    pub terminal: Option<TerminalKind>,
    pub truncated_tail: bool,
}

pub struct FactLedger {
    root: PathBuf,
    policy: LedgerPolicy,
    guard: Mutex<()>,
}

impl FactLedger {
    pub fn open(root: impl AsRef<Path>, policy: LedgerPolicy) -> Result<Arc<Self>, LedgerError> {
        let root = root.as_ref().to_path_buf();
        private_directory(&root)?;
        if policy.max_events_per_attempt == 0
            || policy.max_events_per_attempt > 65_536
            || policy.max_batch == 0
            || policy.max_batch > 1_024
            || policy.export_ttl.is_zero()
            || policy.retry_backoff.is_zero()
        {
            return Err(LedgerError::EventBudget);
        }
        Ok(Arc::new(Self {
            root,
            policy,
            guard: Mutex::new(()),
        }))
    }

    pub fn begin(
        self: &Arc<Self>,
        identity: OutboundIdentity,
        request_sha256: &str,
        wire_sha256: &str,
    ) -> Result<AttemptJournal, LedgerError> {
        validate_identity(&identity)?;
        if !digest_string(request_sha256) || !digest_string(wire_sha256) {
            return Err(LedgerError::InvalidIdentity);
        }
        let account_key = sha256(identity.account_id.as_bytes());
        let directory = self.account_dir(&account_key)?;
        let path = directory.join(format!("{}.jsonl", identity.attempt_id));
        let file = private_new_file(&path)?;
        let stored = StoredIdentity {
            account_key,
            workspace_account_sha256: sha256(identity.workspace_account_id.as_bytes()),
            auth_revision: identity.auth_revision,
            thread_id: identity.thread_id,
            turn_id: identity.turn_id,
            attempt_id: identity.attempt_id,
            endpoint: identity.endpoint,
        };
        let mut journal = AttemptJournal {
            ledger: Arc::clone(self),
            file,
            identity: stored.clone(),
            next_ordinal: 0,
            event_count: 0,
            saw_completion: false,
            saw_http_success: false,
            terminal: false,
            overflow_recorded: false,
            broken: false,
            bytes_written: 0,
        };
        journal.append(NetworkFact::Started {
            identity: stored,
            request_sha256: request_sha256.to_owned(),
            wire_sha256: wire_sha256.to_owned(),
            at_ms: now_ms(),
        })?;
        Ok(journal)
    }

    pub fn snapshot(&self, account_id: &str) -> Result<Vec<AttemptSnapshot>, LedgerError> {
        let directory = self.root.join(sha256(account_id.as_bytes()));
        if !directory.exists() {
            return Ok(Vec::new());
        }
        ensure_private_directory(&directory)?;
        let mut snapshots = Vec::new();
        for entry in fs::read_dir(directory).map_err(|_| LedgerError::Storage)? {
            let entry = entry.map_err(|_| LedgerError::Storage)?;
            if entry.path().extension().is_some_and(|ext| ext == "jsonl") {
                snapshots.push(read_attempt(&entry.path())?);
            }
        }
        snapshots.sort_by(|left, right| left.identity.attempt_id.cmp(&right.identity.attempt_id));
        Ok(snapshots)
    }

    fn account_dir(&self, key: &str) -> Result<PathBuf, LedgerError> {
        let path = self.root.join(key);
        private_directory(&path)?;
        Ok(path)
    }

    fn ack_dir(&self, account_key: &str) -> Result<PathBuf, LedgerError> {
        let path = self.account_dir(account_key)?.join("delivery-acks");
        private_directory(&path)?;
        Ok(path)
    }
}

pub struct AttemptJournal {
    ledger: Arc<FactLedger>,
    file: File,
    identity: StoredIdentity,
    next_ordinal: u64,
    event_count: usize,
    saw_completion: bool,
    saw_http_success: bool,
    terminal: bool,
    overflow_recorded: bool,
    broken: bool,
    bytes_written: usize,
}

impl AttemptJournal {
    pub fn identity(&self) -> &StoredIdentity {
        &self.identity
    }

    pub fn http_response(
        &mut self,
        status: u16,
        upstream_request_id: Option<&str>,
        duration: Duration,
    ) -> Result<(), LedgerError> {
        if self.terminal || self.broken {
            return Err(LedgerError::AlreadyTerminal);
        }
        self.append(NetworkFact::HttpResponse {
            status,
            upstream_request_id: upstream_request_id.and_then(bounded_label),
            duration_ms: millis(duration),
            at_ms: now_ms(),
        })?;
        self.saw_http_success |= (200..300).contains(&status);
        Ok(())
    }

    /// Link this actual model send to independently recorded connection evidence.
    /// The connection's older handshake is not a fresh HTTP response for this turn.
    pub fn websocket_connection_used(
        &mut self,
        connection_id: &str,
        reused: bool,
    ) -> Result<(), LedgerError> {
        if self.terminal || self.broken {
            return Err(LedgerError::AlreadyTerminal);
        }
        if Uuid::parse_str(connection_id).is_err() {
            return Err(LedgerError::InvalidIdentity);
        }
        self.append(NetworkFact::WebSocketConnectionUsed {
            connection_id: connection_id.into(),
            reused,
            at_ms: now_ms(),
        })
    }

    /// Consume an official SDK telemetry hook only when it belongs to this
    /// exact outbound account/auth revision and gateway attempt. Hook events
    /// carry fixed categories; no raw error or stream payload is serialized.
    pub fn observe_hook(
        &mut self,
        observation: &crate::observability::ObservedNetworkEvent,
    ) -> Result<(), LedgerError> {
        if self.terminal || self.broken {
            return Err(LedgerError::AlreadyTerminal);
        }
        let other = &observation.identity;
        if self.identity.account_key != sha256(other.account_id.as_bytes())
            || self.identity.workspace_account_sha256
                != sha256(other.workspace_account_id.as_bytes())
            || self.identity.auth_revision != other.auth_revision
            || self.identity.thread_id != other.thread_id
            || self.identity.turn_id != other.turn_id
            || self.identity.attempt_id != other.attempt_id
            || self.identity.endpoint != other.endpoint
        {
            return Err(LedgerError::InvalidIdentity);
        }
        use crate::observability::NetworkEventKind;
        let (source, detail, sdk_attempt, status, duration_ms) = match observation.kind {
            NetworkEventKind::Request {
                sdk_attempt,
                status,
                error,
                duration_ms,
            } => (
                "http_request",
                error.map_or("ok", closed_error_label).to_string(),
                Some(sdk_attempt),
                status,
                duration_ms,
            ),
            NetworkEventKind::SsePoll {
                outcome,
                duration_ms,
            } => ("sse_poll", format!("{outcome:?}"), None, None, duration_ms),
            NetworkEventKind::WebsocketRequest {
                status,
                error,
                duration_ms,
                ..
            } => (
                "websocket_request",
                error.map_or("ok", closed_error_label).to_string(),
                None,
                status,
                duration_ms,
            ),
            NetworkEventKind::WebsocketEvent {
                outcome,
                duration_ms,
            } => (
                "websocket_event",
                format!("{outcome:?}"),
                None,
                None,
                duration_ms,
            ),
        };
        self.append(NetworkFact::HookObservation {
            source: source.to_owned(),
            detail,
            sdk_attempt,
            status,
            duration_ms,
            at_ms: now_ms(),
        })
    }

    pub fn stream_event(&mut self, event_kind: &str, raw: &[u8]) -> Result<(), LedgerError> {
        if self.terminal || self.broken {
            return Err(LedgerError::AlreadyTerminal);
        }
        if self.event_count >= self.ledger.policy.max_events_per_attempt {
            if !self.overflow_recorded {
                self.append(NetworkFact::StreamBudgetExceeded { at_ms: now_ms() })?;
                self.overflow_recorded = true;
            }
            return Err(LedgerError::EventBudget);
        }
        let event_kind = bounded_label(event_kind).ok_or(LedgerError::EventBudget)?;
        if raw.len() > 256 * 1024 {
            return Err(LedgerError::EventBudget);
        }
        let (response_id, usage, usage_exceeded_budget) = terminal_observation(&event_kind, raw);
        let observed_completion = event_kind == "response.completed" && response_id.is_some();
        let result = self.append(NetworkFact::StreamEvent {
            ordinal: self.event_count as u64 + 1,
            event_kind,
            event_sha256: sha256(raw),
            response_id,
            usage,
            usage_exceeded_budget,
            at_ms: now_ms(),
        });
        if matches!(result, Err(LedgerError::EventBudget)) && !self.overflow_recorded {
            self.append(NetworkFact::StreamBudgetExceeded { at_ms: now_ms() })?;
            self.overflow_recorded = true;
        }
        result?;
        self.event_count += 1;
        self.saw_completion |= observed_completion;
        Ok(())
    }

    pub fn finish(
        &mut self,
        outcome: TerminalKind,
        offered_to_client: bool,
    ) -> Result<(), LedgerError> {
        if self.terminal || self.broken {
            return Err(LedgerError::AlreadyTerminal);
        }
        if outcome == TerminalKind::Completed && !self.saw_completion {
            return Err(LedgerError::MissingCompletion);
        }
        if outcome == TerminalKind::HttpCompleted && !self.saw_http_success {
            return Err(LedgerError::MissingCompletion);
        }
        self.append(NetworkFact::Terminal {
            outcome,
            offered_to_client,
            at_ms: now_ms(),
        })?;
        self.terminal = true;
        Ok(())
    }

    fn append(&mut self, fact: NetworkFact) -> Result<(), LedgerError> {
        let _guard = self.ledger.guard.lock().map_err(|_| LedgerError::Storage)?;
        let numbered = NumberedFact {
            fact_id: format!("{}:{}", self.identity.attempt_id, self.next_ordinal),
            ordinal: self.next_ordinal,
            fact,
        };
        let bytes = serde_json::to_vec(&numbered).map_err(|_| LedgerError::Storage)?;
        if bytes.len() > 96 * 1024 {
            return Err(LedgerError::EventBudget);
        }
        const MAX_JOURNAL_BYTES: usize = 32 * 1024 * 1024;
        const RESERVED_TERMINAL_BYTES: usize = 1024;
        let limit = if matches!(
            &numbered.fact,
            NetworkFact::Terminal { .. } | NetworkFact::StreamBudgetExceeded { .. }
        ) {
            MAX_JOURNAL_BYTES
        } else {
            MAX_JOURNAL_BYTES - RESERVED_TERMINAL_BYTES
        };
        if self.bytes_written.saturating_add(bytes.len() + 1) > limit {
            return Err(LedgerError::EventBudget);
        }
        if self.file.write_all(&bytes).is_err()
            || self.file.write_all(b"\n").is_err()
            || self.file.sync_data().is_err()
        {
            self.broken = true;
            return Err(LedgerError::Storage);
        }
        self.bytes_written += bytes.len() + 1;
        self.next_ordinal += 1;
        Ok(())
    }
}

fn read_attempt(path: &Path) -> Result<AttemptSnapshot, LedgerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LedgerError::Storage)?;
    if !metadata.file_type().is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err(LedgerError::Storage);
    }
    let bytes = fs::read(path).map_err(|_| LedgerError::Storage)?;
    let mut facts = Vec::new();
    let mut truncated_tail = !bytes.ends_with(b"\n");
    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    for line in bytes[..complete_len].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(fact) = serde_json::from_slice::<NumberedFact>(line) else {
            truncated_tail = true;
            break;
        };
        if fact.ordinal != facts.len() as u64 {
            truncated_tail = true;
            break;
        }
        facts.push(fact);
    }
    let Some(NetworkFact::Started { identity, .. }) = facts.first().map(|fact| &fact.fact) else {
        return Err(LedgerError::Storage);
    };
    let identity = identity.clone();
    if facts
        .iter()
        .any(|fact| fact.fact_id != format!("{}:{}", identity.attempt_id, fact.ordinal))
    {
        return Err(LedgerError::Storage);
    }
    if facts
        .iter()
        .filter(|fact| matches!(&fact.fact, NetworkFact::Terminal { .. }))
        .count()
        > 1
    {
        return Err(LedgerError::Storage);
    }
    let terminal = facts.iter().find_map(|fact| match &fact.fact {
        NetworkFact::Terminal { outcome, .. } => Some(*outcome),
        _ => None,
    });
    Ok(AttemptSnapshot {
        identity,
        facts,
        terminal,
        truncated_tail,
    })
}

#[derive(Clone, Serialize)]
pub struct ExportFact {
    pub fact_id: String,
    pub fact: NetworkFact,
}

#[derive(Serialize)]
struct ExportBatch<'a> {
    account_key: &'a str,
    facts: &'a [ExportFact],
}

pub struct ExportReport {
    pub acknowledged: usize,
    pub expired: usize,
    pub pending: usize,
}

/// Optional private collector export. It is intentionally separate from the
/// official app-server AnalyticsEventsClient: these are observed network facts,
/// not synthetic Codex turn or tool analytics. A collector response is only a
/// batch-level HTTP result, not proof of per-fact acceptance. An unknown result
/// is retried after backoff; collectors must deduplicate by stable `fact_id`
/// because new facts may change the next batch and its idempotency key.
pub struct FactExporter {
    ledger: Arc<FactLedger>,
    endpoint: url::Url,
    clients: Mutex<HashMap<String, reqwest::Client>>,
    retry_after: Mutex<HashMap<String, Instant>>,
    export_guard: tokio::sync::Mutex<()>,
}

impl FactExporter {
    pub fn new(
        ledger: Arc<FactLedger>,
        endpoint: &str,
        allow_loopback_http: bool,
    ) -> Result<Self, LedgerError> {
        let endpoint =
            url::Url::parse(endpoint).map_err(|_| LedgerError::InvalidExportDestination)?;
        let loopback = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (endpoint.scheme() != "https"
            && !(allow_loopback_http && endpoint.scheme() == "http" && loopback))
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
        {
            return Err(LedgerError::InvalidExportDestination);
        }
        Ok(Self {
            ledger,
            endpoint,
            clients: Mutex::new(HashMap::new()),
            retry_after: Mutex::new(HashMap::new()),
            export_guard: tokio::sync::Mutex::new(()),
        })
    }

    /// Export under the current account's live lifecycle and auth revision.
    /// An already active request may drain after disable/delete, matching the
    /// official metrics lifecycle. No new POST begins after it becomes idle.
    pub async fn export_for_account(
        &self,
        account: &Arc<Account>,
    ) -> Result<ExportReport, LedgerError> {
        self.export_account(account.id(), Some(account)).await
    }

    /// Low-level diagnostic export for an isolated ledger. Production must use
    /// `export_for_account` so account disable/delete is checked at send time.
    pub async fn export_once(&self, account_id: &str) -> Result<ExportReport, LedgerError> {
        self.export_account(account_id, None).await
    }

    async fn export_account(
        &self,
        account_id: &str,
        owner: Option<&Account>,
    ) -> Result<ExportReport, LedgerError> {
        let _single_flight = self.export_guard.lock().await;
        if owner
            .is_some_and(|account| account.id() != account_id || !account_allows_export(account))
        {
            return Err(LedgerError::AccountInactive);
        }
        let account_key = sha256(account_id.as_bytes());
        if self
            .retry_after
            .lock()
            .map_err(|_| LedgerError::Storage)?
            .get(&account_key)
            .is_some_and(|at| Instant::now() < *at)
        {
            return Err(LedgerError::ExportDeferred);
        }
        let ack_dir = self.ledger.ack_dir(&account_key)?;
        let mut batch = Vec::new();
        let mut expired = 0;
        let mut pending = 0;
        for attempt in self.ledger.snapshot(account_id)? {
            if owner.is_some_and(|account| {
                attempt.identity.auth_revision != account.revision()
                    || attempt.identity.workspace_account_sha256
                        != sha256(account.workspace_account_id().as_bytes())
            }) {
                // A refreshed credential never adopts its predecessor's
                // transport queue, even when the local account label matches.
                continue;
            }
            for fact in attempt.facts {
                let ack = ack_dir.join(sha256(fact.fact_id.as_bytes()));
                if ack.exists() {
                    if fs::read(&ack).map_err(|_| LedgerError::Storage)? != fact.fact_id.as_bytes()
                    {
                        return Err(LedgerError::Storage);
                    }
                    continue;
                }
                if now_ms().saturating_sub(fact.fact.timestamp_ms())
                    > millis(self.ledger.policy.export_ttl)
                {
                    expired += 1;
                    continue;
                }
                pending += 1;
                if batch.len() < self.ledger.policy.max_batch {
                    batch.push(ExportFact {
                        fact_id: fact.fact_id,
                        fact: fact.fact,
                    });
                }
            }
        }
        if batch.is_empty() {
            return Ok(ExportReport {
                acknowledged: 0,
                expired,
                pending,
            });
        }
        let client = {
            let mut clients = self.clients.lock().map_err(|_| LedgerError::Storage)?;
            if let Some(client) = clients.get(&account_key) {
                client.clone()
            } else {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .pool_max_idle_per_host(0)
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|_| LedgerError::Storage)?;
                clients.insert(account_key.clone(), client.clone());
                client
            }
        };
        let payload = ExportBatch {
            account_key: &account_key,
            facts: &batch,
        };
        if owner.is_some_and(|account| !account_allows_export(account)) {
            return Err(LedgerError::AccountInactive);
        }
        let sent = client
            .post(self.endpoint.clone())
            .header(
                "idempotency-key",
                sha256(
                    batch
                        .iter()
                        .map(|fact| fact.fact_id.as_str())
                        .collect::<Vec<_>>()
                        .join("|")
                        .as_bytes(),
                ),
            )
            .json(&payload)
            .send()
            .await;
        if !sent.is_ok_and(|response| response.status().is_success()) {
            self.retry_after
                .lock()
                .map_err(|_| LedgerError::Storage)?
                .insert(
                    account_key,
                    Instant::now() + self.ledger.policy.retry_backoff,
                );
            return Err(LedgerError::ExportFailed);
        }
        for fact in &batch {
            let ack = ack_dir.join(sha256(fact.fact_id.as_bytes()));
            let temporary = ack_dir.join(format!(
                "{}.tmp-{}",
                sha256(fact.fact_id.as_bytes()),
                Uuid::new_v4()
            ));
            let mut file = private_new_file(&temporary)?;
            file.write_all(fact.fact_id.as_bytes())
                .map_err(|_| LedgerError::Storage)?;
            file.sync_data().map_err(|_| LedgerError::Storage)?;
            fs::rename(&temporary, &ack).map_err(|_| LedgerError::Storage)?;
        }
        File::open(&ack_dir)
            .and_then(|directory| directory.sync_data())
            .map_err(|_| LedgerError::Storage)?;
        Ok(ExportReport {
            acknowledged: batch.len(),
            expired,
            pending: pending - batch.len(),
        })
    }
}

fn account_allows_export(account: &Account) -> bool {
    account
        .availability()
        .is_ok_and(|status| (status.enabled && !status.deleting) || status.active_requests > 0)
}

fn terminal_observation(kind: &str, raw: &[u8]) -> (Option<String>, Option<Value>, bool) {
    if !matches!(kind, "response.completed" | "response.incomplete") || raw.len() > 256 * 1024 {
        return (None, None, false);
    }
    let Ok(value) = serde_json::from_slice::<Value>(raw) else {
        return (None, None, false);
    };
    if value.get("type").and_then(Value::as_str) != Some(kind) {
        return (None, None, false);
    }
    let id = value
        .pointer("/response/id")
        .and_then(Value::as_str)
        .and_then(bounded_label);
    let usage = value
        .pointer("/response/usage")
        .filter(|value| !value.is_null());
    let too_large = usage
        .is_some_and(|usage| serde_json::to_vec(usage).is_ok_and(|bytes| bytes.len() > 64 * 1024));
    let projected = if too_large {
        None
    } else {
        usage.and_then(project_usage_counters)
    };
    (id, projected, too_large)
}

fn closed_error_label(error: crate::observability::NetworkErrorKind) -> &'static str {
    use crate::observability::NetworkErrorKind;
    match error {
        NetworkErrorKind::Policy => "policy",
        NetworkErrorKind::Http => "http",
        NetworkErrorKind::RetryLimit => "retry_limit",
        NetworkErrorKind::Timeout => "timeout",
        NetworkErrorKind::Connection => "connection",
        NetworkErrorKind::Network => "network",
        NetworkErrorKind::Build => "build",
        NetworkErrorKind::ResponseTooLarge => "response_too_large",
        NetworkErrorKind::SseUtf8 => "sse_utf8",
        NetworkErrorKind::SseParser => "sse_parser",
        NetworkErrorKind::WebsocketTransport => "websocket_transport",
        NetworkErrorKind::Api => "api",
    }
}

fn project_usage_counters(usage: &Value) -> Option<Value> {
    let object = usage.as_object()?;
    let mut out = serde_json::Map::new();
    for key in ["input_tokens", "output_tokens", "total_tokens"] {
        if let Some(value) = object.get(key).and_then(Value::as_u64) {
            out.insert(key.to_owned(), Value::from(value));
        }
    }
    for (group, fields) in [
        ("input_tokens_details", &["cached_tokens"][..]),
        ("output_tokens_details", &["reasoning_tokens"][..]),
    ] {
        if let Some(details) = object.get(group).and_then(Value::as_object) {
            let mut projected = serde_json::Map::new();
            for field in fields {
                if let Some(value) = details.get(*field).and_then(Value::as_u64) {
                    projected.insert((*field).to_owned(), Value::from(value));
                }
            }
            if !projected.is_empty() {
                out.insert(group.to_owned(), Value::Object(projected));
            }
        }
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn validate_identity(identity: &OutboundIdentity) -> Result<(), LedgerError> {
    for value in [
        &identity.account_id,
        &identity.workspace_account_id,
        &identity.auth_revision,
        &identity.thread_id,
        &identity.turn_id,
        &identity.attempt_id,
        &identity.endpoint,
    ] {
        if bounded_label(value).is_none() {
            return Err(LedgerError::InvalidIdentity);
        }
    }
    if Uuid::parse_str(&identity.attempt_id).is_err() {
        return Err(LedgerError::InvalidIdentity);
    }
    if !digest_string(&identity.auth_revision) {
        return Err(LedgerError::InvalidIdentity);
    }
    Ok(())
}

fn bounded_label(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn digest_string(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn private_directory(path: &Path) -> Result<(), LedgerError> {
    if path.exists() {
        ensure_private_directory(path)?;
    } else {
        fs::create_dir_all(path).map_err(|_| LedgerError::Storage)?;
        ensure_private_directory(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| LedgerError::Storage)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), LedgerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LedgerError::Storage)?;
    if !metadata.file_type().is_dir() {
        return Err(LedgerError::Storage);
    }
    Ok(())
}

fn private_new_file(path: &Path) -> Result<File, LedgerError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| LedgerError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropped_stream_is_unknown_and_cannot_be_promoted_to_completed() {
        let facts = Arc::new(FactStore::default());
        let attempt = facts.start("a", "revision", "thread", "turn");
        drop(attempt);
        assert_eq!(facts.snapshot()[0].outcome, "unknown_or_cancelled");
        assert!(facts.snapshot()[0].upstream_response_id.is_none());
    }

    #[test]
    fn legacy_diagnostic_attempt_can_share_exact_durable_attempt_id_once() {
        let facts = Arc::new(FactStore::default());
        let mut attempt = facts.start("a", "revision", "thread", "turn");
        let identity = Uuid::new_v4().to_string();
        attempt.set_attempt_id(&identity).unwrap();
        assert!(attempt.set_attempt_id(&Uuid::new_v4().to_string()).is_err());
        attempt.finish("unknown");
        assert_eq!(facts.snapshot()[0].attempt_id, identity);
    }

    #[test]
    fn oversized_usage_is_explicitly_omitted_instead_of_growing_the_fact_store() {
        let facts = Arc::new(FactStore::default());
        let mut attempt = facts.start("a", "revision", "thread", "turn");
        attempt.event(&serde_json::json!({"type":"response.completed","response":{"id":"resp-real","usage":{"unexpected": "x".repeat(65536)}}}));
        attempt.finish("completed");
        let rows = facts.snapshot();
        assert_eq!(rows[0].upstream_response_id.as_deref(), Some("resp-real"));
        assert!(rows[0].usage.is_none());
        assert!(rows[0].usage_exceeded_budget);
    }
}
