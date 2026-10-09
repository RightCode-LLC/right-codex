//! Network observations for one already-selected outbound account and turn.
//!
//! Construct this after the outbound account, auth revision, and request headers
//! have been fixed. Each hook shares that immutable identity snapshot. The
//! callback receives categories only: no bearer, prompt, response body, SSE
//! data, WebSocket payload, or raw error text crosses this boundary.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codex_api::{ApiError, SseTelemetry, WebsocketTelemetry};
use codex_client::{RequestTelemetry, TransportError};
use codex_otel::{MetricsClient, MetricsConfig, SessionTelemetry, TelemetryAuthMode};
use codex_protocol::{ThreadId, protocol::SessionSource};
use eventsource_stream::{Event, EventStreamError};
use http::StatusCode;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use opentelemetry_sdk::resource::{ResourceDetector, TelemetryResourceDetector};
use prost::Message as _;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::error::Elapsed;
use tokio_tungstenite::tungstenite::{Error as WebsocketError, Message};
use url::{Host, Url};
use uuid::Uuid;

use crate::accounts::{Account, create_private_directory};
use crate::config::TelemetryConfig;
pub use crate::telemetry::OutboundIdentity;

const MAX_IDENTITY_LEN: usize = 256;
const MAX_MODEL_LEN: usize = 128;
const MAX_ENDPOINT_LEN: usize = 96;
const MAX_PENDING_FILES: usize = 64;
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_SENDS_PER_FLUSH: usize = 4;
const QUEUE_MAGIC: &[u8; 4] = b"OTM1";
const QUEUE_HEADER_LEN: usize = 4 + 8 + 1 + 4;
static QUEUE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const STATSIG_ENDPOINT: &str = "https://ab.chatgpt.com/otlp/v1/metrics";
const STATSIG_HEADER: &str = "statsig-api-key";
const STATSIG_KEY: &str = "client-MkRuleRQBd6qakfnDYqJVR9JuXcY57Ljly3vi5JVUIO";

// Exact names in the fixed 0.160.0 vendor metrics/config.rs exclusion list.
const STATSIG_DISABLED_METRICS: &[&str] = &[
    "codex.api_request",
    "codex.api_request.duration_ms",
    "codex.conversation.turn.count",
    "exec_server_client_requests_total",
    "codex.responses_api_engine_iapi_ttft.duration_ms",
    "codex.responses_api_engine_service_tbt.duration_ms",
    "codex.responses_api_engine_service_ttft.duration_ms",
    "codex.tool.call",
    "codex.tool.call.duration_ms",
    "codex.turn.cost_microusd",
    "codex.turn.token_usage",
];

/// A 2xx HTTP response acknowledges the export request at the HTTP layer.
/// No server-side deduplication or point-level acceptance is inferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub acked_batches: usize,
    pub unknown_delivery_batches: usize,
    pub withheld_batches: usize,
    pub expired_batches: usize,
    pub captured_batches: usize,
    pub statsig_filtered_metrics: usize,
    pub lost_snapshots: usize,
    pub backoff_active: bool,
    pub disabled_reason: Option<DisabledReason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisabledReason {
    ConfiguredOff,
    VendorDebugDefault,
    RetiredRevision,
    InactiveAccount,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushSummary {
    pub accounts: usize,
    pub acked_batches: usize,
    pub unknown_delivery_batches: usize,
    pub withheld_batches: usize,
    pub expired_batches: usize,
    pub captured_batches: usize,
    pub statsig_filtered_metrics: usize,
    pub lost_snapshots: usize,
    pub disabled_accounts: usize,
    pub failed_accounts: usize,
}

/// Only delivery state for official metric batches. Business facts and their
/// outbound identities live in a separate ledger and are never cleared here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDeliveryState {
    Pending,
    Attempted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetricDelivery {
    pub auth_revision: String,
    pub batch_id: String,
    pub created_ms: u64,
    pub state: MetricDeliveryState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClearDeliveryReport {
    pub pending: usize,
    pub attempted: usize,
    /// Confirmed HTTP batches have already been removed from the queue.
    pub acked: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TelemetryError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("outbound identity does not match selected account revision")]
    AccountMismatch,
    #[error("invalid telemetry policy")]
    InvalidPolicy,
    #[error("telemetry endpoint is invalid for this account")]
    InvalidEndpoint,
    #[error("per-account metric client could not be created")]
    MetricClient,
    #[error("metric snapshot could not be collected")]
    Snapshot,
    #[error("metric snapshot could not be encoded within the batch budget")]
    Encoding,
    #[error("private metric queue is unavailable")]
    Storage,
    #[error("private metric queue is full")]
    QueueFull,
}

#[derive(Clone)]
enum ExportRoute {
    Statsig,
    Custom(Url),
}

impl ExportRoute {
    fn endpoint(&self) -> &str {
        match self {
            Self::Statsig => STATSIG_ENDPOINT,
            Self::Custom(url) => url.as_str(),
        }
    }

    fn encoding(&self) -> u8 {
        match self {
            Self::Statsig => 1,
            Self::Custom(_) => 2,
        }
    }

    fn content_type(&self) -> &'static str {
        match self {
            Self::Statsig => "application/json",
            Self::Custom(_) => "application/x-protobuf",
        }
    }

    fn queue_key(&self) -> String {
        let mut hash = Sha256::new();
        hash.update([self.encoding()]);
        hash.update(self.endpoint().as_bytes());
        format!("{:x}", hash.finalize())
    }
}

struct AccountMetrics {
    metrics: MetricsClient,
    exporter: InMemoryMetricExporter,
    resource: Resource,
    client: reqwest::Client,
    owner: Weak<Account>,
    queue_dir: PathBuf,
    retired: AtomicBool,
    flush_gate: AsyncMutex<FlushControl>,
}

#[derive(Default)]
struct FlushControl {
    next_send_after: Option<Instant>,
}

fn export_disabled_reason(state: &AccountMetrics) -> Option<DisabledReason> {
    if state.retired.load(Ordering::Acquire) {
        return Some(DisabledReason::RetiredRevision);
    }
    let Some(owner) = state.owner.upgrade() else {
        return Some(DisabledReason::RetiredRevision);
    };
    match owner.availability() {
        Ok(availability)
            if (availability.enabled && !availability.deleting)
                || availability.active_requests > 0 =>
        {
            None
        }
        _ => Some(DisabledReason::InactiveAccount),
    }
}

/// Owns one MetricsClient, private queue, and transport per account revision.
/// The registry never installs process-global metrics and never uses a default
/// reqwest client. A route change creates a distinct queue namespace so old
/// payloads cannot be sent to a different endpoint by accident.
pub struct TelemetryRegistry {
    disabled_reason: Option<DisabledReason>,
    route: ExportRoute,
    allow_loopback_http: bool,
    max_batch: usize,
    ttl: Duration,
    backoff: Duration,
    accounts: Mutex<HashMap<(String, String), Arc<AccountMetrics>>>,
}

impl TelemetryRegistry {
    pub fn new(config: TelemetryConfig) -> Result<Self, TelemetryError> {
        if config.max_batch == 0
            || config.max_batch > 1024
            || config.ttl_seconds == 0
            || config.ttl_seconds > 7 * 24 * 60 * 60
            || config.retry_backoff_seconds == 0
            || config.retry_backoff_seconds > 60 * 60
        {
            return Err(TelemetryError::InvalidPolicy);
        }
        let default_route = config.otlp_endpoint.is_none();
        let route = match config.otlp_endpoint {
            Some(endpoint) => {
                let url = Url::parse(&endpoint).map_err(|_| TelemetryError::InvalidEndpoint)?;
                if url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !matches!(url.scheme(), "http" | "https")
                    || (url.scheme() == "http"
                        && (!config.allow_loopback_http || !loopback_host(&url)))
                {
                    return Err(TelemetryError::InvalidEndpoint);
                }
                ExportRoute::Custom(url)
            }
            None => ExportRoute::Statsig,
        };
        let disabled_reason = if !config.official_metrics_enabled {
            Some(DisabledReason::ConfiguredOff)
        } else if default_route && cfg!(debug_assertions) {
            Some(DisabledReason::VendorDebugDefault)
        } else {
            None
        };
        Ok(Self {
            disabled_reason,
            route,
            allow_loopback_http: config.allow_loopback_http,
            max_batch: config.max_batch,
            ttl: Duration::from_secs(config.ttl_seconds),
            backoff: Duration::from_secs(config.retry_backoff_seconds),
            accounts: Mutex::new(HashMap::new()),
        })
    }

    pub fn for_account(
        &self,
        account: &Arc<Account>,
        identity: OutboundIdentity,
        model: &str,
        slug: &str,
    ) -> Result<Arc<AccountTelemetry>, TelemetryError> {
        if identity.account_id != account.id()
            || identity.workspace_account_id != account.workspace_account_id()
            || identity.auth_revision != account.revision()
        {
            return Err(TelemetryError::AccountMismatch);
        }
        let state = self.account_state(account)?;
        AccountTelemetry::new(identity, model, slug, state.metrics.clone()).map_err(Into::into)
    }

    pub async fn flush_account(
        &self,
        account: &Arc<Account>,
    ) -> Result<FlushReport, TelemetryError> {
        let state = self.account_state(account)?;
        self.flush_state(&state).await
    }

    /// Inspect the private queue across process restarts and auth revisions.
    /// Live revision gates serialize this view with metric export.
    pub async fn delivery_list(
        &self,
        account: &Account,
    ) -> Result<Vec<MetricDelivery>, TelemetryError> {
        let states = self.delivery_states(account.id())?;
        let mut guards = Vec::with_capacity(states.len());
        for (_, state) in &states {
            guards.push(state.flush_gate.lock().await);
        }
        let mut deliveries = Vec::new();
        for (revision, directory) in metric_queue_directories(account)? {
            for (extension, status) in [
                ("pending", MetricDeliveryState::Pending),
                ("attempted", MetricDeliveryState::Attempted),
            ] {
                for path in list_queue_files(&directory, extension)? {
                    let batch_id = path
                        .file_stem()
                        .and_then(|name| name.to_str())
                        .ok_or(TelemetryError::Storage)?
                        .to_owned();
                    deliveries.push(MetricDelivery {
                        auth_revision: revision.clone(),
                        batch_id,
                        created_ms: read_created_ms(&path)?,
                        state: status,
                    });
                }
            }
        }
        deliveries.sort_by(|left, right| {
            (left.created_ms, &left.auth_revision, &left.batch_id).cmp(&(
                right.created_ms,
                &right.auth_revision,
                &right.batch_id,
            ))
        });
        Ok(deliveries)
    }

    /// Clear metric transport records for the local account. An in-flight
    /// export finishes under its gate first. New measurements can enqueue
    /// after this call; no business attempt, identity, or response is removed.
    pub async fn clear_delivery(
        &self,
        account: &Account,
    ) -> Result<ClearDeliveryReport, TelemetryError> {
        let states = self.delivery_states(account.id())?;
        let mut guards = Vec::with_capacity(states.len());
        for (_, state) in &states {
            guards.push(state.flush_gate.lock().await);
        }
        let mut report = ClearDeliveryReport::default();
        for (_, directory) in metric_queue_directories(account)? {
            for (extension, count) in [
                ("pending", &mut report.pending),
                ("attempted", &mut report.attempted),
            ] {
                for path in list_queue_files(&directory, extension)? {
                    fs::remove_file(path).map_err(|_| TelemetryError::Storage)?;
                    *count += 1;
                }
            }
            sync_directory(&directory)?;
        }
        Ok(report)
    }

    fn delivery_states(
        &self,
        local_id: &str,
    ) -> Result<Vec<(String, Arc<AccountMetrics>)>, TelemetryError> {
        let accounts = self.accounts.lock().map_err(|_| TelemetryError::Storage)?;
        let mut states = accounts
            .iter()
            .filter(|((account_id, _), _)| account_id == local_id)
            .map(|((_, revision), state)| (revision.clone(), state.clone()))
            .collect::<Vec<_>>();
        states.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(states)
    }

    /// Permanently stop metric POSTs for a deleted or replaced local account.
    /// A temporary disable is enforced by the live account availability check;
    /// it must not call this method because re-enabling the same revision may
    /// resume its previously pending batches.
    /// Existing private queue files remain until their normal TTL expires.
    pub fn retire_account(&self, local_id: &str) -> Result<(), TelemetryError> {
        let accounts = self.accounts.lock().map_err(|_| TelemetryError::Storage)?;
        for ((account_id, _), state) in accounts.iter() {
            if account_id == local_id {
                state.retired.store(true, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Export every account revision registered through for_account or
    /// flush_account. Slots retain only that account's client and private path;
    /// no OAuth bearer or Account object is held by this registry.
    pub async fn export_all(&self) -> Result<FlushSummary, TelemetryError> {
        let states: Vec<Arc<AccountMetrics>> = self
            .accounts
            .lock()
            .map_err(|_| TelemetryError::Storage)?
            .values()
            .cloned()
            .collect();
        let mut summary = FlushSummary {
            accounts: states.len(),
            ..FlushSummary::default()
        };
        for state in states {
            match self.flush_state(&state).await {
                Ok(report) => {
                    summary.acked_batches += report.acked_batches;
                    summary.unknown_delivery_batches += report.unknown_delivery_batches;
                    summary.withheld_batches += report.withheld_batches;
                    summary.expired_batches += report.expired_batches;
                    summary.captured_batches += report.captured_batches;
                    summary.statsig_filtered_metrics += report.statsig_filtered_metrics;
                    summary.lost_snapshots += report.lost_snapshots;
                    summary.disabled_accounts += usize::from(report.disabled_reason.is_some());
                }
                Err(_) => summary.failed_accounts += 1,
            }
        }
        Ok(summary)
    }

    async fn flush_state(&self, state: &AccountMetrics) -> Result<FlushReport, TelemetryError> {
        // Keep the verified owner alive through this flush. A removed account
        // cannot cause directory cleanup or a new queue read after its final
        // strong reference disappears; deletion still changes availability.
        let Some(_owner_guard) = state.owner.upgrade() else {
            return Ok(FlushReport {
                disabled_reason: Some(DisabledReason::RetiredRevision),
                ..FlushReport::default()
            });
        };
        if let Some(reason) = export_disabled_reason(state) {
            let _gate = state.flush_gate.lock().await;
            if state.owner.upgrade().is_none() {
                return Ok(FlushReport {
                    disabled_reason: Some(DisabledReason::RetiredRevision),
                    ..FlushReport::default()
                });
            }
            let mut report = FlushReport {
                disabled_reason: Some(reason),
                ..FlushReport::default()
            };
            cleanup_expired(&state.queue_dir, self.ttl, &mut report)?;
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }
        if let Some(reason) = self.disabled_reason {
            return Ok(FlushReport {
                disabled_reason: Some(reason),
                ..FlushReport::default()
            });
        }
        let mut control = state.flush_gate.lock().await;
        if state.owner.upgrade().is_none() {
            return Ok(FlushReport {
                disabled_reason: Some(DisabledReason::RetiredRevision),
                ..FlushReport::default()
            });
        }
        if let Some(reason) = export_disabled_reason(state) {
            let mut report = FlushReport {
                disabled_reason: Some(reason),
                ..FlushReport::default()
            };
            cleanup_expired(&state.queue_dir, self.ttl, &mut report)?;
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }
        let mut report = FlushReport::default();
        cleanup_expired(&state.queue_dir, self.ttl, &mut report)?;
        if control
            .next_send_after
            .is_some_and(|deadline| deadline > Instant::now())
        {
            report.backoff_active = true;
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }
        control.next_send_after = None;

        // Send older durable entries before taking a delta snapshot. A failed
        // transport attempt stops this flush, leaving new measurements in the
        // manual reader until a later call.
        let send_limit = self.max_batch.min(MAX_SENDS_PER_FLUSH);
        let mut sent = send_pending(state, &self.route, send_limit, &mut report).await?;
        if state.owner.upgrade().is_none() {
            report.disabled_reason = Some(DisabledReason::RetiredRevision);
            return Ok(report);
        }
        if let Some(reason) = export_disabled_reason(state) {
            report.disabled_reason = Some(reason);
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }
        if sent.failed {
            control.next_send_after = Some(Instant::now() + self.backoff);
            report.backoff_active = true;
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }

        let existing = queue_file_count(&state.queue_dir)?;
        if existing >= MAX_PENDING_FILES {
            queue_counts(&state.queue_dir, &mut report)?;
            return Err(TelemetryError::QueueFull);
        }
        let snapshot = state
            .metrics
            .snapshot()
            .map_err(|_| TelemetryError::Snapshot)?;
        let mut export = ExportMetricsServiceRequest::from(&snapshot);
        replace_metric_resources(&mut export, &state.resource);
        if matches!(&self.route, ExportRoute::Statsig) {
            report.statsig_filtered_metrics = filter_statsig(&mut export);
        }
        if !export.resource_metrics.is_empty() {
            match encode_metric_export(&export, &self.route) {
                Ok(body) => {
                    if persist_pending(&state.queue_dir, self.route.encoding(), &body).is_ok() {
                        report.captured_batches = 1;
                        // The push reader is separate from the manual Delta
                        // reader. Discard its unused copy after persistence.
                        state.exporter.reset();
                    } else {
                        report.lost_snapshots = 1;
                    }
                }
                _ => report.lost_snapshots = 1,
            }
        }
        if report.lost_snapshots != 0 {
            queue_counts(&state.queue_dir, &mut report)?;
            return Ok(report);
        }
        sent = send_pending(
            state,
            &self.route,
            send_limit.saturating_sub(sent.sent),
            &mut report,
        )
        .await?;
        if state.owner.upgrade().is_none() {
            report.disabled_reason = Some(DisabledReason::RetiredRevision);
            return Ok(report);
        }
        if let Some(reason) = export_disabled_reason(state) {
            report.disabled_reason = Some(reason);
        }
        if sent.failed {
            control.next_send_after = Some(Instant::now() + self.backoff);
            report.backoff_active = true;
        }
        queue_counts(&state.queue_dir, &mut report)?;
        Ok(report)
    }

    fn account_state(&self, account: &Arc<Account>) -> Result<Arc<AccountMetrics>, TelemetryError> {
        if let ExportRoute::Custom(url) = &self.route
            && url.scheme() == "http"
            && (!self.allow_loopback_http || !loopback_host(url))
        {
            return Err(TelemetryError::InvalidEndpoint);
        }
        let key = (account.id().to_owned(), account.revision().to_owned());
        let mut accounts = self.accounts.lock().map_err(|_| TelemetryError::Storage)?;
        if let Some(state) = accounts.get(&key) {
            if state
                .owner
                .upgrade()
                .is_none_or(|owner| !Arc::ptr_eq(&owner, account))
            {
                state.retired.store(true, Ordering::Release);
                return Err(TelemetryError::AccountMismatch);
            }
            return Ok(state.clone());
        }
        let queue_dir = account
            .private_home()
            .join("official-metrics")
            .join(account.revision())
            .join(self.route.queue_key());
        create_private_directory(&queue_dir).map_err(|_| TelemetryError::Storage)?;
        let exporter = InMemoryMetricExporter::default();
        let service_name = codex_login::default_client::originator().value;
        let resource = trusted_metric_resource(&service_name);
        let metrics = MetricsClient::new(
            MetricsConfig::in_memory(
                // Fixed core/otel_init.rs:79-88, config/types.rs defaults.
                "dev",
                service_name,
                crate::CODEX_VERSION,
                exporter.clone(),
            )
            .with_runtime_reader()
            // The second reader exists only because the upstream constructor
            // requires a push exporter. It is never used for network export.
            .with_export_interval(Duration::from_secs(365 * 24 * 60 * 60)),
        )
        .map_err(|_| TelemetryError::MetricClient)?;
        let state = Arc::new(AccountMetrics {
            metrics,
            exporter,
            resource,
            client: account.client().clone(),
            owner: Arc::downgrade(account),
            queue_dir,
            retired: AtomicBool::new(false),
            flush_gate: AsyncMutex::new(FlushControl::default()),
        });
        for ((account_id, _), old) in accounts.iter() {
            if account_id == account.id() {
                old.retired.store(true, Ordering::Release);
            }
        }
        accounts.insert(key, state.clone());
        Ok(state)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("invalid outbound identity field: {0}")]
    InvalidField(&'static str),
}

/// A category whose values are fixed in this source, never copied from a
/// transport error. In particular, HTTP error bodies are not retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkErrorKind {
    Policy,
    Http,
    RetryLimit,
    Timeout,
    Connection,
    Network,
    Build,
    ResponseTooLarge,
    SseUtf8,
    SseParser,
    WebsocketTransport,
    Api,
}

impl NetworkErrorKind {
    fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Http => "http",
            Self::RetryLimit => "retry_limit",
            Self::Timeout => "timeout",
            Self::Connection => "connection",
            Self::Network => "network",
            Self::Build => "build",
            Self::ResponseTooLarge => "response_too_large",
            Self::SseUtf8 => "sse_utf8",
            Self::SseParser => "sse_parser",
            Self::WebsocketTransport => "websocket_transport",
            Self::Api => "api",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseEventKind {
    ResponseCreated,
    ResponseInProgress,
    ResponseCompleted,
    ResponseIncomplete,
    ResponseFailed,
    OutputItemAdded,
    OutputItemDone,
    Other,
}

impl SseEventKind {
    fn from_name(name: &str) -> Self {
        match name {
            "response.created" => Self::ResponseCreated,
            "response.in_progress" => Self::ResponseInProgress,
            "response.completed" => Self::ResponseCompleted,
            "response.incomplete" => Self::ResponseIncomplete,
            "response.failed" => Self::ResponseFailed,
            "response.output_item.added" => Self::OutputItemAdded,
            "response.output_item.done" => Self::OutputItemDone,
            _ => Self::Other,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ResponseCreated => "response.created",
            Self::ResponseInProgress => "response.in_progress",
            Self::ResponseCompleted => "response.completed",
            Self::ResponseIncomplete => "response.incomplete",
            Self::ResponseFailed => "response.failed",
            Self::OutputItemAdded => "response.output_item.added",
            Self::OutputItemDone => "response.output_item.done",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsePollOutcome {
    Event(SseEventKind),
    StreamError(NetworkErrorKind),
    End,
    IdleTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebsocketEventOutcome {
    TextFrame,
    BinaryFrame,
    CloseFrame,
    PingFrame,
    PongFrame,
    RawFrame,
    TransportError,
    ApiError(NetworkErrorKind),
    End,
}

impl WebsocketEventOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::TextFrame => "text",
            Self::BinaryFrame => "binary",
            Self::CloseFrame => "close",
            Self::PingFrame => "ping",
            Self::PongFrame => "pong",
            Self::RawFrame => "frame",
            Self::TransportError => "transport_error",
            Self::ApiError(_) => "api_error",
            Self::End => "end",
        }
    }

    fn success(self) -> bool {
        matches!(self, Self::TextFrame | Self::PingFrame | Self::PongFrame)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkEventKind {
    /// `sdk_attempt` is the SDK retry index; identity.attempt_id names the
    /// gateway's enclosing outbound attempt.
    Request {
        sdk_attempt: u64,
        status: Option<u16>,
        error: Option<NetworkErrorKind>,
        duration_ms: u64,
    },
    SsePoll {
        outcome: SsePollOutcome,
        duration_ms: u64,
    },
    WebsocketRequest {
        status: Option<u16>,
        error: Option<NetworkErrorKind>,
        connection_reused: bool,
        duration_ms: u64,
    },
    WebsocketEvent {
        outcome: WebsocketEventOutcome,
        duration_ms: u64,
    },
}

pub struct ObservedNetworkEvent {
    pub identity: Arc<OutboundIdentity>,
    pub kind: NetworkEventKind,
}

pub type ObservationSink = Arc<dyn Fn(ObservedNetworkEvent) + Send + Sync>;

/// A per-outbound-request adapter to the official Codex telemetry hooks.
/// Its MetricsClient is supplied by the selected account; nothing is
/// installed in the process-global metrics slot.
pub struct AccountTelemetry {
    identity: Arc<OutboundIdentity>,
    session: SessionTelemetry,
    model_slug: String,
    completion_usage_recorded: AtomicBool,
    observer: OnceLock<ObservationSink>,
}

impl AccountTelemetry {
    pub fn new(
        identity: OutboundIdentity,
        model: &str,
        slug: &str,
        metrics: MetricsClient,
    ) -> Result<Arc<Self>, IdentityError> {
        validate_identity(&identity)?;
        validate_text("model", model, MAX_MODEL_LEN)?;
        validate_text("slug", slug, MAX_MODEL_LEN)?;

        let thread_id = ThreadId::from_string(&identity.thread_id)
            .map_err(|_| IdentityError::InvalidField("thread_id"))?;
        let session = SessionTelemetry::new(
            thread_id,
            model,
            slug,
            Some(identity.workspace_account_id.clone()),
            None,
            Some(TelemetryAuthMode::Chatgpt),
            codex_login::default_client::originator().value,
            false,
            codex_terminal_detection::user_agent(),
            SessionSource::Custom("right-codex".to_owned()),
        )
        // The constructor reads the upstream global default. Replace it before
        // exposing the object and omit metadata labels with unbounded values.
        .with_metrics_without_metadata_tags(metrics);

        Ok(Arc::new(Self {
            identity: Arc::new(identity),
            session,
            model_slug: slug.to_owned(),
            completion_usage_recorded: AtomicBool::new(false),
            observer: OnceLock::new(),
        }))
    }

    /// Register a persistence sink once, before handing hooks to the SDK.
    /// A second registration returns the unused sink to its caller.
    pub fn set_observer(&self, sink: ObservationSink) -> Result<(), ObservationSink> {
        self.observer.set(sink)
    }

    pub fn request_hook(self: &Arc<Self>) -> Arc<dyn RequestTelemetry> {
        self.clone()
    }

    pub fn sse_hook(self: &Arc<Self>) -> Arc<dyn SseTelemetry> {
        self.clone()
    }

    pub fn ws_hook(self: &Arc<Self>) -> Arc<dyn WebsocketTelemetry> {
        self.clone()
    }

    /// Emits the pinned Codex turn-token histogram from an actual upstream
    /// `response.completed` only. An absent optional counter is not recorded
    /// as zero. The caller must invoke this after validating the terminal for
    /// this same outbound attempt; retries receive a distinct hook instance.
    pub fn record_verified_completion_usage(&self, completed: &Value) -> bool {
        if completed.get("type").and_then(Value::as_str) != Some("response.completed") {
            return false;
        }
        let Some(usage) = completed
            .pointer("/response/usage")
            .and_then(Value::as_object)
        else {
            return false;
        };
        let Some(input) = observed_count(usage.get("input_tokens")) else {
            return false;
        };
        let Some(output) = observed_count(usage.get("output_tokens")) else {
            return false;
        };
        let Some(total) = observed_count(usage.get("total_tokens")) else {
            return false;
        };
        let cached = usage
            .get("input_tokens_details")
            .and_then(Value::as_object)
            .and_then(|details| observed_count(details.get("cached_tokens")));
        let reasoning = usage
            .get("output_tokens_details")
            .and_then(Value::as_object)
            .and_then(|details| observed_count(details.get("reasoning_tokens")));
        if self
            .completion_usage_recorded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        for (token_type, value) in [
            ("total", Some(total)),
            ("input", Some(input)),
            ("cached_input", cached),
            ("output", Some(output)),
            ("reasoning_output", reasoning),
        ] {
            if let Some(value) = value {
                self.session.histogram(
                    codex_otel::TURN_TOKEN_USAGE_METRIC,
                    value,
                    &[("token_type", token_type), ("model", &self.model_slug)],
                );
            }
        }
        true
    }

    fn emit(&self, kind: NetworkEventKind) {
        if let Some(sink) = self.observer.get() {
            sink(ObservedNetworkEvent {
                identity: self.identity.clone(),
                kind,
            });
        }
    }
}

fn observed_count(value: Option<&Value>) -> Option<i64> {
    value?.as_i64().filter(|count| *count >= 0)
}

impl RequestTelemetry for AccountTelemetry {
    fn on_request(
        &self,
        attempt: u64,
        status: Option<StatusCode>,
        error: Option<&TransportError>,
        duration: Duration,
    ) {
        let status = status.or(match error {
            Some(TransportError::Http { status, .. }) => Some(*status),
            _ => None,
        });
        let error = error.map(classify_transport);
        let duration_ms = bounded_duration_ms(duration);
        self.session.record_api_request(
            attempt,
            status.map(|value| value.as_u16()),
            error.map(NetworkErrorKind::label),
            duration,
            true,
            Some("authorization"),
            false,
            None,
            None,
            &self.identity.endpoint,
            None,
            None,
            None,
            None,
            None,
        );
        self.emit(NetworkEventKind::Request {
            sdk_attempt: attempt,
            status: status.map(|value| value.as_u16()),
            error,
            duration_ms,
        });
    }
}

impl SseTelemetry for AccountTelemetry {
    fn on_sse_poll(
        &self,
        result: &Result<Option<Result<Event, EventStreamError<TransportError>>>, Elapsed>,
        duration: Duration,
    ) {
        let outcome = match result {
            Ok(Some(Ok(event))) => SsePollOutcome::Event(SseEventKind::from_name(&event.event)),
            Ok(Some(Err(EventStreamError::Transport(error)))) => {
                SsePollOutcome::StreamError(classify_transport(error))
            }
            Ok(Some(Err(EventStreamError::Utf8(_)))) => {
                SsePollOutcome::StreamError(NetworkErrorKind::SseUtf8)
            }
            Ok(Some(Err(EventStreamError::Parser(_)))) => {
                SsePollOutcome::StreamError(NetworkErrorKind::SseParser)
            }
            Ok(None) => SsePollOutcome::End,
            Err(_) => SsePollOutcome::IdleTimeout,
        };
        let (kind, success) = match outcome {
            SsePollOutcome::Event(kind) => (kind.label(), kind != SseEventKind::ResponseFailed),
            SsePollOutcome::StreamError(_) => ("stream_error", false),
            SsePollOutcome::IdleTimeout => ("idle_timeout", false),
            SsePollOutcome::End => ("end", true),
        };
        // The upstream log_sse_event reads and parses event data and emits raw
        // errors. Fixed labels retain its metric names without that exposure.
        let tags = [
            ("kind", kind),
            ("success", if success { "true" } else { "false" }),
        ];
        self.session
            .counter(codex_otel::SSE_EVENT_COUNT_METRIC, 1, &tags);
        self.session
            .record_duration(codex_otel::SSE_EVENT_DURATION_METRIC, duration, &tags);
        self.emit(NetworkEventKind::SsePoll {
            outcome,
            duration_ms: bounded_duration_ms(duration),
        });
    }
}

impl WebsocketTelemetry for AccountTelemetry {
    fn on_ws_request(&self, duration: Duration, error: Option<&ApiError>, connection_reused: bool) {
        let error_kind = error.map(classify_api);
        let status = error.and_then(api_status);
        self.session.record_websocket_request(
            duration,
            error_kind.map(NetworkErrorKind::label),
            connection_reused,
            None,
        );
        self.emit(NetworkEventKind::WebsocketRequest {
            status,
            error: error_kind,
            connection_reused,
            duration_ms: bounded_duration_ms(duration),
        });
    }

    fn on_ws_event(
        &self,
        result: &Result<Option<Result<Message, WebsocketError>>, ApiError>,
        duration: Duration,
    ) {
        let outcome = match result {
            Ok(Some(Ok(Message::Text(_)))) => WebsocketEventOutcome::TextFrame,
            Ok(Some(Ok(Message::Binary(_)))) => WebsocketEventOutcome::BinaryFrame,
            Ok(Some(Ok(Message::Close(_)))) => WebsocketEventOutcome::CloseFrame,
            Ok(Some(Ok(Message::Ping(_)))) => WebsocketEventOutcome::PingFrame,
            Ok(Some(Ok(Message::Pong(_)))) => WebsocketEventOutcome::PongFrame,
            Ok(Some(Ok(Message::Frame(_)))) => WebsocketEventOutcome::RawFrame,
            Ok(Some(Err(_))) => WebsocketEventOutcome::TransportError,
            Ok(None) => WebsocketEventOutcome::End,
            Err(error) => WebsocketEventOutcome::ApiError(classify_api(error)),
        };
        if !matches!(
            outcome,
            WebsocketEventOutcome::PingFrame | WebsocketEventOutcome::PongFrame
        ) {
            let tags = [
                ("kind", outcome.label()),
                ("success", if outcome.success() { "true" } else { "false" }),
            ];
            self.session
                .counter(codex_otel::WEBSOCKET_EVENT_COUNT_METRIC, 1, &tags);
            self.session.record_duration(
                codex_otel::WEBSOCKET_EVENT_DURATION_METRIC,
                duration,
                &tags,
            );
        }
        self.emit(NetworkEventKind::WebsocketEvent {
            outcome,
            duration_ms: bounded_duration_ms(duration),
        });
    }
}

fn validate_identity(identity: &OutboundIdentity) -> Result<(), IdentityError> {
    for (name, value) in [
        ("account_id", identity.account_id.as_str()),
        (
            "workspace_account_id",
            identity.workspace_account_id.as_str(),
        ),
        ("auth_revision", identity.auth_revision.as_str()),
        ("thread_id", identity.thread_id.as_str()),
        ("turn_id", identity.turn_id.as_str()),
        ("attempt_id", identity.attempt_id.as_str()),
    ] {
        validate_text(name, value, MAX_IDENTITY_LEN)?;
    }
    if identity.auth_revision.len() != 64
        || !identity
            .auth_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(IdentityError::InvalidField("auth_revision"));
    }
    validate_text("endpoint", &identity.endpoint, MAX_ENDPOINT_LEN)?;
    if !identity.endpoint.starts_with('/')
        || !identity
            .endpoint
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(IdentityError::InvalidField("endpoint"));
    }
    for (name, value) in [
        ("thread_id", identity.thread_id.as_str()),
        ("turn_id", identity.turn_id.as_str()),
        ("attempt_id", identity.attempt_id.as_str()),
    ] {
        Uuid::parse_str(value).map_err(|_| IdentityError::InvalidField(name))?;
    }
    Ok(())
}

fn validate_text(name: &'static str, value: &str, max_len: usize) -> Result<(), IdentityError> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(IdentityError::InvalidField(name));
    }
    Ok(())
}

fn bounded_duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn classify_transport(error: &TransportError) -> NetworkErrorKind {
    match error {
        TransportError::Policy(_) => NetworkErrorKind::Policy,
        TransportError::Http { .. } => NetworkErrorKind::Http,
        TransportError::RetryLimit => NetworkErrorKind::RetryLimit,
        TransportError::Timeout => NetworkErrorKind::Timeout,
        TransportError::Connection(_) => NetworkErrorKind::Connection,
        TransportError::Network(_) => NetworkErrorKind::Network,
        TransportError::Build(_) => NetworkErrorKind::Build,
        TransportError::ResponseTooLarge { .. } => NetworkErrorKind::ResponseTooLarge,
    }
}

fn classify_api(error: &ApiError) -> NetworkErrorKind {
    match error {
        ApiError::Transport(error) => classify_transport(error),
        ApiError::Api { .. } => NetworkErrorKind::Http,
        _ => NetworkErrorKind::Api,
    }
}

fn api_status(error: &ApiError) -> Option<u16> {
    match error {
        ApiError::Transport(TransportError::Http { status, .. }) | ApiError::Api { status, .. } => {
            Some(status.as_u16())
        }
        _ => None,
    }
}

/// Build from trusted local facts, never from Resource::builder() or an
/// incoming/persisted resource. The official builder also reads process-wide
/// OTEL_RESOURCE_ATTRIBUTES, including arbitrary host/instance/account IDs.
/// Its OS fields are conditional, so even an allowlist of snapshot keys would
/// trust an environment value when native OS discovery returned unspecified.
fn trusted_metric_resource(service_name: &str) -> Resource {
    // This SDK detector emits only its own name, language, and version; unlike
    // Resource::builder(), it does not invoke the environment detectors.
    let mut resource = Resource::from(&TelemetryResourceDetector.detect());
    resource.attributes.extend([
        metric_resource_attribute("service.name", service_name),
        metric_resource_attribute("service.version", crate::CODEX_VERSION),
        metric_resource_attribute("env", "dev"),
    ]);
    // Keep the same static OS classifications as the pinned official client,
    // including its omission of unspecified values, without copying env data.
    static OS_ATTRIBUTES: OnceLock<Vec<KeyValue>> = OnceLock::new();
    resource.attributes.extend(
        OS_ATTRIBUTES
            .get_or_init(|| {
                let info = os_info::get();
                [
                    ("os", info.os_type().to_string()),
                    ("os_version", info.version().to_string()),
                ]
                .into_iter()
                .filter_map(|(key, value)| {
                    let value = codex_otel::sanitize_metric_tag_value(&value);
                    (value != "unspecified").then(|| metric_resource_attribute(key, &value))
                })
                .collect()
            })
            .iter()
            .cloned(),
    );
    // The pinned official resource has no account identity attributes. Account
    // ownership remains in the private client/queue/transport; do not invent
    // shared host IDs or export local account labels as upstream identities.
    resource
}

fn metric_resource_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_owned())),
        }),
    }
}

fn replace_metric_resources(export: &mut ExportMetricsServiceRequest, resource: &Resource) {
    for metrics in &mut export.resource_metrics {
        // Replacing the whole object also removes entity references and
        // dropped-attribute counts from historical queue entries.
        metrics.resource = Some(resource.clone());
        metrics.schema_url.clear();
    }
}

fn encode_metric_export(
    export: &ExportMetricsServiceRequest,
    route: &ExportRoute,
) -> Result<Vec<u8>, TelemetryError> {
    let body = match route {
        ExportRoute::Statsig => serde_json::to_vec(export).map_err(|_| TelemetryError::Encoding)?,
        ExportRoute::Custom(_) => export.encode_to_vec(),
    };
    if body.is_empty() || body.len() > MAX_BATCH_BYTES {
        return Err(TelemetryError::Encoding);
    }
    Ok(body)
}

fn isolate_queued_metric_resources(
    body: &[u8],
    route: &ExportRoute,
    resource: &Resource,
) -> Result<Vec<u8>, TelemetryError> {
    let mut export = match route {
        ExportRoute::Statsig => {
            serde_json::from_slice(body).map_err(|_| TelemetryError::Encoding)?
        }
        ExportRoute::Custom(_) => {
            ExportMetricsServiceRequest::decode(body).map_err(|_| TelemetryError::Encoding)?
        }
    };
    replace_metric_resources(&mut export, resource);
    encode_metric_export(&export, route)
}

fn filter_statsig(export: &mut ExportMetricsServiceRequest) -> usize {
    let mut filtered = 0;
    for resource in &mut export.resource_metrics {
        for scope in &mut resource.scope_metrics {
            let before = scope.metrics.len();
            scope
                .metrics
                .retain(|metric| !STATSIG_DISABLED_METRICS.contains(&metric.name.as_str()));
            filtered += before - scope.metrics.len();
        }
        resource
            .scope_metrics
            .retain(|scope| !scope.metrics.is_empty());
    }
    export
        .resource_metrics
        .retain(|resource| !resource.scope_metrics.is_empty());
    filtered
}

struct SendResult {
    sent: usize,
    failed: bool,
}

/// Move pending to attempted and sync the directory before entering reqwest.
/// An attempted batch is never selected again, even after a lost response or
/// process crash. This is at-most-once transport, not confirmed delivery.
async fn send_pending(
    state: &AccountMetrics,
    route: &ExportRoute,
    limit: usize,
    report: &mut FlushReport,
) -> Result<SendResult, TelemetryError> {
    send_pending_to_endpoint(state, route, route.endpoint(), limit, report).await
}

async fn send_pending_to_endpoint(
    state: &AccountMetrics,
    route: &ExportRoute,
    endpoint: &str,
    limit: usize,
    report: &mut FlushReport,
) -> Result<SendResult, TelemetryError> {
    let mut result = SendResult {
        sent: 0,
        failed: false,
    };
    for pending in list_queue_files(&state.queue_dir, "pending")?
        .into_iter()
        .take(limit)
    {
        if export_disabled_reason(state).is_some() {
            break;
        }
        let (encoding, body) = read_queue_file(&pending)?;
        if encoding != route.encoding() {
            return Err(TelemetryError::Storage);
        }
        // Apply the same boundary to old queue files after a cold restart.
        // A malformed historical body fails closed before any POST or state
        // transition; filtering only new snapshots would leave E03 open.
        let body = isolate_queued_metric_resources(&body, route, &state.resource)?;
        // build() has no network side effect. A local build error leaves the
        // file pending; no attempted state has been recorded yet.
        let mut request = state
            .client
            .post(endpoint)
            .header(CONTENT_TYPE, route.content_type());
        if matches!(route, ExportRoute::Statsig) {
            request = request.header(STATSIG_HEADER, STATSIG_KEY);
        }
        let request = request
            .body(body)
            .build()
            .map_err(|_| TelemetryError::InvalidEndpoint)?;
        let attempted = pending.with_extension("attempted");
        fs::rename(&pending, &attempted).map_err(|_| TelemetryError::Storage)?;
        sync_directory(&state.queue_dir)?;
        if export_disabled_reason(state).is_some() {
            // No POST has started. Revert the local marker while holding the
            // single-flight gate so a temporarily disabled account retains
            // its pending batch for the same revision after re-enable. A crash
            // between the two renames still leaves the conservative unknown.
            fs::rename(&attempted, &pending).map_err(|_| TelemetryError::Storage)?;
            sync_directory(&state.queue_dir)?;
            break;
        }
        result.sent += 1;
        match state.client.execute(request).await {
            Ok(response) if response.status().is_success() => {
                fs::remove_file(&attempted).map_err(|_| TelemetryError::Storage)?;
                sync_directory(&state.queue_dir)?;
                report.acked_batches += 1;
            }
            Ok(_) | Err(_) => {
                // A non-2xx response or network error does not prove that the
                // collector ignored the batch. Keep the attempted marker.
                result.failed = true;
                break;
            }
        }
    }
    Ok(result)
}

fn persist_pending(directory: &Path, encoding: u8, body: &[u8]) -> Result<(), TelemetryError> {
    if body.is_empty() || body.len() > MAX_BATCH_BYTES {
        return Err(TelemetryError::Encoding);
    }
    let created_ms = now_ms();
    let sequence = QUEUE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let id = format!("{created_ms:020}-{sequence:020}-{}", Uuid::new_v4());
    let temp = directory.join(format!("{id}.tmp"));
    let pending = directory.join(format!("{id}.pending"));
    let result = (|| {
        let mut file = private_new_file(&temp)?;
        file.write_all(QUEUE_MAGIC)
            .map_err(|_| TelemetryError::Storage)?;
        file.write_all(&created_ms.to_be_bytes())
            .map_err(|_| TelemetryError::Storage)?;
        file.write_all(&[encoding])
            .map_err(|_| TelemetryError::Storage)?;
        file.write_all(&(body.len() as u32).to_be_bytes())
            .map_err(|_| TelemetryError::Storage)?;
        file.write_all(body).map_err(|_| TelemetryError::Storage)?;
        file.sync_all().map_err(|_| TelemetryError::Storage)?;
        fs::rename(&temp, &pending).map_err(|_| TelemetryError::Storage)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_queue_file(path: &Path) -> Result<(u8, Vec<u8>), TelemetryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TelemetryError::Storage)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TelemetryError::Storage);
    }
    if metadata.len() < QUEUE_HEADER_LEN as u64
        || metadata.len() > (QUEUE_HEADER_LEN + MAX_BATCH_BYTES) as u64
    {
        return Err(TelemetryError::Storage);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| TelemetryError::Storage)?;
    if bytes.len() != metadata.len() as usize || &bytes[..4] != QUEUE_MAGIC {
        return Err(TelemetryError::Storage);
    }
    let encoding = bytes[12];
    let size = u32::from_be_bytes(
        bytes[13..17]
            .try_into()
            .map_err(|_| TelemetryError::Storage)?,
    ) as usize;
    if size == 0 || size > MAX_BATCH_BYTES || size + QUEUE_HEADER_LEN != bytes.len() {
        return Err(TelemetryError::Storage);
    }
    Ok((encoding, bytes[QUEUE_HEADER_LEN..].to_vec()))
}

fn cleanup_expired(
    directory: &Path,
    ttl: Duration,
    report: &mut FlushReport,
) -> Result<(), TelemetryError> {
    let now = now_ms();
    let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
    for entry in fs::read_dir(directory).map_err(|_| TelemetryError::Storage)? {
        let entry = entry.map_err(|_| TelemetryError::Storage)?;
        let path = entry.path();
        let ext = path.extension().and_then(|ext| ext.to_str());
        if !matches!(ext, Some("pending" | "attempted" | "tmp")) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| TelemetryError::Storage)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(TelemetryError::Storage);
        }
        let created = if ext == Some("tmp") {
            metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_millis().min(u64::MAX as u128) as u64)
                .ok_or(TelemetryError::Storage)?
        } else {
            read_created_ms(&path)?
        };
        if now.saturating_sub(created) >= ttl_ms {
            fs::remove_file(&path).map_err(|_| TelemetryError::Storage)?;
            report.expired_batches += usize::from(ext != Some("tmp"));
        }
    }
    sync_directory(directory)
}

fn read_created_ms(path: &Path) -> Result<u64, TelemetryError> {
    let mut header = [0_u8; QUEUE_HEADER_LEN];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| TelemetryError::Storage)?;
    if &header[..4] != QUEUE_MAGIC {
        return Err(TelemetryError::Storage);
    }
    Ok(u64::from_be_bytes(
        header[4..12]
            .try_into()
            .map_err(|_| TelemetryError::Storage)?,
    ))
}

fn queue_counts(directory: &Path, report: &mut FlushReport) -> Result<(), TelemetryError> {
    report.withheld_batches = list_queue_files(directory, "pending")?.len();
    report.unknown_delivery_batches = list_queue_files(directory, "attempted")?.len();
    Ok(())
}

fn queue_file_count(directory: &Path) -> Result<usize, TelemetryError> {
    Ok(list_queue_files(directory, "pending")?.len()
        + list_queue_files(directory, "attempted")?.len())
}

fn metric_queue_directories(account: &Account) -> Result<Vec<(String, PathBuf)>, TelemetryError> {
    // The account private home is selected by AccountPool, not by a request
    // parameter. Do not derive a path from a caller-supplied account label.
    let root = account.private_home().join("official-metrics");
    match fs::symlink_metadata(&root) {
        Ok(_) => checked_queue_directory(&root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(TelemetryError::Storage),
    }
    let mut queues = Vec::new();
    for revision in fs::read_dir(&root).map_err(|_| TelemetryError::Storage)? {
        let revision = revision.map_err(|_| TelemetryError::Storage)?;
        let revision_name = revision.file_name();
        let revision_name = revision_name.to_str().ok_or(TelemetryError::Storage)?;
        if !sha256_component(revision_name) {
            return Err(TelemetryError::Storage);
        }
        let revision_path = revision.path();
        checked_queue_directory(&revision_path)?;
        for route in fs::read_dir(&revision_path).map_err(|_| TelemetryError::Storage)? {
            let route = route.map_err(|_| TelemetryError::Storage)?;
            let route_name = route.file_name();
            let route_name = route_name.to_str().ok_or(TelemetryError::Storage)?;
            if !sha256_component(route_name) {
                return Err(TelemetryError::Storage);
            }
            let directory = route.path();
            checked_queue_directory(&directory)?;
            queues.push((revision_name.to_owned(), directory));
        }
    }
    queues.sort();
    Ok(queues)
}

fn sha256_component(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn checked_queue_directory(path: &Path) -> Result<(), TelemetryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| TelemetryError::Storage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(TelemetryError::Storage);
    }
    Ok(())
}

fn list_queue_files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, TelemetryError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| TelemetryError::Storage)? {
        let entry = entry.map_err(|_| TelemetryError::Storage)?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == extension) {
            let metadata = fs::symlink_metadata(&path).map_err(|_| TelemetryError::Storage)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(TelemetryError::Storage);
            }
            files.push((read_created_ms(&path)?, path));
        }
    }
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

fn private_new_file(path: &Path) -> Result<File, TelemetryError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| TelemetryError::Storage)
}

fn sync_directory(directory: &Path) -> Result<(), TelemetryError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| TelemetryError::Storage)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain("localhost")) => true,
        _ => false,
    }
}

#[cfg(test)]
mod resource_isolation_tests {
    use super::*;
    use crate::accounts::AccountPool;
    use crate::config::{AccountConfig, GatewayConfig};
    use axum::{Router, body::Bytes, extract::State, http::HeaderMap, routing::post};
    use base64::Engine;
    use serde_json::json;
    use std::process::Command;
    use tempfile::TempDir;

    const CHILD: &str = "CODEX_TEST_METRIC_ROUTE_RESOURCE_CHILD";

    #[test]
    fn statsig_and_official_otlp_cold_queues_use_the_same_resource_boundary() {
        if std::env::var_os(CHILD).is_none() {
            let home = TempDir::new().unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "observability::resource_isolation_tests::statsig_and_official_otlp_cold_queues_use_the_same_resource_boundary",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", home.path())
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env(CHILD, "1")
                .env("OTEL_RESOURCE_ATTRIBUTES", "host.id=ENV_SENTINEL_HOST,service.instance.id=ENV_SENTINEL_INSTANCE,telemetry.sdk.version=ENV_SENTINEL_SDK,custom.unique=ENV_SENTINEL_CUSTOM")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated route child failed: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(exercise_routes());
    }

    #[derive(Default)]
    struct Captured(Mutex<Vec<(HeaderMap, Vec<u8>)>>);

    async fn capture(
        State(state): State<Arc<Captured>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        state.0.lock().unwrap().push((headers, body.to_vec()));
        StatusCode::OK
    }

    async fn exercise_routes() {
        let directory = TempDir::new().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/metrics", listener.local_addr().unwrap());
        let captured = Arc::new(Captured::default());
        let server = tokio::spawn({
            let captured = captured.clone();
            async move {
                axum::serve(
                    listener,
                    Router::new()
                        .route("/metrics", post(capture))
                        .with_state(captured),
                )
                .await
                .unwrap();
            }
        });
        let mut config = GatewayConfig {
            state_dir: directory.path().join("state"),
            ..GatewayConfig::default()
        };
        for id in ["alpha", "beta"] {
            let auth_path = directory.path().join(format!("{id}.json"));
            let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
                "https://api.openai.com/auth":{
                    "chatgpt_account_id":format!("workspace-{id}"),"chatgpt_user_id":format!("user-{id}"),"chatgpt_plan_type":"pro"
                }
            })).unwrap());
            fs::write(&auth_path, serde_json::to_vec(&json!({"auth_mode":"chatgpt","tokens":{
                "id_token":format!("eyJhbGciOiJub25lIn0.{claims}.synthetic"),
                "access_token":format!("synthetic-access-{id}"),"refresh_token":format!("synthetic-refresh-{id}"),"account_id":format!("workspace-{id}")
            }})).unwrap()).unwrap();
            config.accounts.push(AccountConfig {
                id: id.into(),
                auth_path,
                proxy: None,
                enabled: true,
            });
        }
        let pool = AccountPool::from_config(&config).unwrap();
        let accounts = [
            pool.by_id("alpha").unwrap().unwrap(),
            pool.by_id("beta").unwrap().unwrap(),
        ];
        for route in [
            ExportRoute::Statsig,
            ExportRoute::Custom(Url::parse(STATSIG_ENDPOINT).unwrap()),
        ] {
            // Only the transport destination is overridden for this private
            // test: production encoding, headers, queue recovery and account
            // clients remain in use. This is not a public Statsig receipt and
            // does not weaken the production debug-default export gate.
            let mut original = TelemetryRegistry::new(TelemetryConfig::default()).unwrap();
            original.route = route.clone();
            for (index, account) in accounts.iter().enumerate() {
                let state = original.account_state(account).unwrap();
                state
                    .metrics
                    .counter(
                        "codex.sse_event",
                        index as i64 + 1,
                        &[("kind", account.id())],
                    )
                    .unwrap();
                let mut old = ExportMetricsServiceRequest::from(&state.metrics.snapshot().unwrap());
                let before = serde_json::to_string(&old).unwrap();
                assert!(
                    before.contains("ENV_SENTINEL_HOST"),
                    "prove the official resource detector saw the synthetic environment"
                );
                for metrics in &mut old.resource_metrics {
                    metrics.schema_url = "COLD_SENTINEL_SCHEMA".into();
                    let resource = metrics.resource.as_mut().unwrap();
                    for attribute in &mut resource.attributes {
                        attribute.value =
                            metric_resource_attribute("", "COLD_SENTINEL_VALUE").value;
                    }
                }
                let body = encode_metric_export(&old, &route).unwrap();
                persist_pending(&state.queue_dir, route.encoding(), &body).unwrap();
            }
            drop(original);
            let mut restored = TelemetryRegistry::new(TelemetryConfig::default()).unwrap();
            restored.route = route.clone();
            for account in &accounts {
                let state = restored.account_state(account).unwrap();
                let mut report = FlushReport::default();
                let sent = send_pending_to_endpoint(&state, &route, &endpoint, 1, &mut report)
                    .await
                    .unwrap();
                assert_eq!(sent.sent, 1);
                assert!(!sent.failed);
                assert_eq!(report.acked_batches, 1);
                let (headers, body) = captured.0.lock().unwrap().last().unwrap().clone();
                assert_eq!(headers[CONTENT_TYPE], route.content_type());
                assert_eq!(
                    headers.get(STATSIG_HEADER).is_some(),
                    matches!(route, ExportRoute::Statsig)
                );
                assert!(!headers.contains_key("authorization"));
                assert!(!headers.contains_key("chatgpt-account-id"));
                let decoded: ExportMetricsServiceRequest = match route {
                    ExportRoute::Statsig => serde_json::from_slice(&body).unwrap(),
                    ExportRoute::Custom(_) => {
                        ExportMetricsServiceRequest::decode(body.as_slice()).unwrap()
                    }
                };
                for metrics in &decoded.resource_metrics {
                    assert_eq!(metrics.resource.as_ref(), Some(&state.resource));
                    assert!(metrics.schema_url.is_empty());
                }
                let text = serde_json::to_string(&decoded).unwrap();
                assert!(!text.contains("SENTINEL"));
                assert!(text.contains(account.id()));
                let other = if account.id() == "alpha" {
                    "beta"
                } else {
                    "alpha"
                };
                assert!(!text.contains(other));
            }
        }
        assert_eq!(captured.0.lock().unwrap().len(), 4);
        server.abort();
    }
}
