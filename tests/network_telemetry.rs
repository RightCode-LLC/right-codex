//! Network facts are taken from the gateway's actual outbound request and
//! upstream stream. Both the OAuth bearer and the collector are synthetic.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::post;
use codex_client::{Provider, RetryConfig};
use codex_http_client::{
    EncodedJsonBody, HttpTransport, RequestBody, RequestCompression, ReqwestTransport,
};
use codex_otel::{MetricsClient, MetricsConfig};
use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use prost::Message;
use right_codex::accounts::AccountPool;
use right_codex::config::{AccountConfig, GatewayConfig};
use right_codex::observability::AccountTelemetry;
use right_codex::observability::{
    DisabledReason, MetricDeliveryState, NetworkEventKind, ObservedNetworkEvent, TelemetryRegistry,
};
use right_codex::telemetry::{
    FactExporter, FactLedger, LedgerError, LedgerPolicy, NetworkFact, OutboundIdentity,
    TerminalKind,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn identity(account: &str) -> OutboundIdentity {
    OutboundIdentity {
        account_id: account.into(),
        workspace_account_id: format!("workspace-{account}"),
        auth_revision: digest(format!("synthetic-revision-{account}").as_bytes()),
        thread_id: Uuid::new_v4().to_string(),
        turn_id: Uuid::new_v4().to_string(),
        attempt_id: Uuid::new_v4().to_string(),
        endpoint: "/responses".into(),
    }
}

#[test]
fn verified_completion_usage_emits_only_observed_official_counters_once() {
    let metrics = MetricsClient::new(
        MetricsConfig::in_memory(
            "test",
            "right-codex",
            "0.160.0",
            InMemoryMetricExporter::default(),
        )
        .with_runtime_reader(),
    )
    .unwrap();
    let telemetry =
        AccountTelemetry::new(identity("alpha"), "gpt-5", "gpt-5", metrics.clone()).unwrap();
    assert!(!telemetry.record_verified_completion_usage(&json!({
        "type":"response.in_progress","response":{"usage":{"input_tokens":7}}
    })));
    assert!(!telemetry.record_verified_completion_usage(&json!({
        "type":"response.completed","response":{"usage":{"input_tokens":7}}
    })));
    let complete = json!({"type":"response.completed","response":{"usage":{
        "input_tokens":7,"output_tokens":2,"total_tokens":9,
        "input_tokens_details":{"cached_tokens":3}
    }}});
    assert!(telemetry.record_verified_completion_usage(&complete));
    assert!(!telemetry.record_verified_completion_usage(&complete));
    let snapshot = metrics.snapshot().unwrap();
    let metric = snapshot
        .scope_metrics()
        .flat_map(|scope| scope.metrics())
        .find(|metric| metric.name() == codex_otel::TURN_TOKEN_USAGE_METRIC)
        .unwrap();
    let AggregatedMetrics::F64(MetricData::Histogram(histogram)) = metric.data() else {
        panic!("official turn token metric must be a histogram");
    };
    let mut points = histogram
        .data_points()
        .map(|point| {
            let tags = point
                .attributes()
                .map(|tag| (tag.key.as_str().to_owned(), tag.value.as_str().into_owned()))
                .collect::<std::collections::HashMap<_, _>>();
            (
                tags["token_type"].clone(),
                tags["model"].clone(),
                point.count(),
                point.sum(),
            )
        })
        .collect::<Vec<_>>();
    points.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        points,
        vec![
            ("cached_input".to_owned(), "gpt-5".to_owned(), 1, 3.0),
            ("input".to_owned(), "gpt-5".to_owned(), 1, 7.0),
            ("output".to_owned(), "gpt-5".to_owned(), 1, 2.0),
            ("total".to_owned(), "gpt-5".to_owned(), 1, 9.0),
        ]
    );
}

#[test]
fn incomplete_attempt_remains_unknown_and_terminal_requires_real_completion() {
    let directory = TempDir::new().unwrap();
    let ledger =
        FactLedger::open(directory.path().join("private"), LedgerPolicy::default()).unwrap();
    let mut attempt = ledger
        .begin(identity("alpha"), &digest(b"logical"), &digest(b"wire"))
        .unwrap();
    attempt
        .http_response(200, Some("upstream-request"), Duration::from_millis(4))
        .unwrap();
    assert!(matches!(
        attempt.finish(TerminalKind::Completed, false),
        Err(LedgerError::MissingCompletion)
    ));
    let rows = ledger.snapshot("alpha").unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].terminal.is_none());
    attempt
        .stream_event(
            "response.completed",
            br#"{"type":"response.in_progress","response":{"id":"wrong-type"}}"#,
        )
        .unwrap();
    assert!(matches!(
        attempt.finish(TerminalKind::Completed, false),
        Err(LedgerError::MissingCompletion)
    ));
    attempt.stream_event("response.completed", br#"{"type":"response.completed","response":{"id":"real-response","usage":{"input_tokens":3}}}"#).unwrap();
    attempt.finish(TerminalKind::Completed, true).unwrap();
    assert!(matches!(
        attempt.finish(TerminalKind::Completed, true),
        Err(LedgerError::AlreadyTerminal)
    ));
    let rows = FactLedger::open(directory.path().join("private"), LedgerPolicy::default())
        .unwrap()
        .snapshot("alpha")
        .unwrap();
    assert_eq!(rows[0].terminal, Some(TerminalKind::Completed));
    assert!(matches!(
        &rows[0].facts.last().unwrap().fact,
        NetworkFact::Terminal {
            offered_to_client: true,
            ..
        }
    ));
    assert!(ledger.snapshot("beta").unwrap().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let root = directory.path().join("private");
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let account_dir = root.join(digest(b"alpha"));
        assert_eq!(
            std::fs::metadata(&account_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let file = std::fs::read_dir(account_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let raw = std::fs::read_to_string(file).unwrap();
        assert!(!raw.contains("workspace-alpha"));
        assert!(!raw.contains("synthetic-revision-alpha"));
    }
}

#[test]
fn account_revision_and_attempt_bind_hooks_without_leaking_usage_metadata() {
    let directory = TempDir::new().unwrap();
    let ledger =
        FactLedger::open(directory.path().join("private"), LedgerPolicy::default()).unwrap();
    let alpha = identity("alpha");
    let mut attempt = ledger
        .begin(alpha.clone(), &digest(b"logical"), &digest(b"wire"))
        .unwrap();
    let mut foreign = alpha.clone();
    foreign.account_id = "beta".into();
    let hook = |identity| ObservedNetworkEvent {
        identity: Arc::new(identity),
        kind: NetworkEventKind::Request {
            sdk_attempt: 1,
            status: Some(200),
            error: None,
            duration_ms: 3,
        },
    };
    assert!(matches!(
        attempt.observe_hook(&hook(foreign)),
        Err(LedgerError::InvalidIdentity)
    ));
    let mut foreign = alpha.clone();
    foreign.auth_revision = digest(b"different-revision");
    assert!(matches!(
        attempt.observe_hook(&hook(foreign)),
        Err(LedgerError::InvalidIdentity)
    ));
    attempt.observe_hook(&hook(alpha.clone())).unwrap();
    attempt.stream_event("response.completed", br#"{"type":"response.completed","response":{"id":"actual-id","usage":{"input_tokens":4,"output_tokens":2,"attribution":{"request_fields":{"client_metadata":"private-client"}}}}}"#).unwrap();
    attempt.finish(TerminalKind::Completed, false).unwrap();
    assert!(matches!(
        attempt.observe_hook(&hook(alpha)),
        Err(LedgerError::AlreadyTerminal)
    ));
    let rows = ledger.snapshot("alpha").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].facts.len(), 4);
    let encoded = serde_json::to_string(&rows[0].facts).unwrap();
    assert!(!encoded.contains("private-client"));
    assert!(!encoded.contains("request_fields"));
    assert!(encoded.contains("input_tokens"));
    assert!(ledger.snapshot("beta").unwrap().is_empty());
}

#[derive(Default)]
struct Upstream {
    bodies: Mutex<Vec<Vec<u8>>>,
    wires: Mutex<Vec<Vec<u8>>>,
    headers: Mutex<Vec<HeaderMap>>,
}

async fn upstream(
    State(state): State<Arc<Upstream>>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, [(String, String); 2], String) {
    state.wires.lock().unwrap().push(body.to_vec());
    let decoded = if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value == "zstd")
    {
        zstd::stream::decode_all(std::io::Cursor::new(body)).unwrap()
    } else {
        body.to_vec()
    };
    state.bodies.lock().unwrap().push(decoded);
    state.headers.lock().unwrap().push(headers);
    let completion = json!({"type":"response.completed","response":{"id":"upstream-real-response","usage":{"input_tokens":7,"output_tokens":2}}});
    (
        StatusCode::OK,
        [
            ("content-type".into(), "text/event-stream".into()),
            ("x-request-id".into(), "upstream-real-request".into()),
        ],
        format!("event: response.completed\ndata: {completion}\n\n"),
    )
}

#[derive(Default)]
struct Collector {
    codes: Mutex<VecDeque<StatusCode>>,
    bodies: Mutex<Vec<Value>>,
}

async fn collector(State(state): State<Arc<Collector>>, body: Bytes) -> StatusCode {
    state
        .bodies
        .lock()
        .unwrap()
        .push(serde_json::from_slice(&body).unwrap());
    state
        .codes
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(StatusCode::OK)
}

#[tokio::test]
async fn actual_oauth_post_and_collector_ack_follow_the_same_outbound_attempt() {
    let directory = TempDir::new().unwrap();
    let policy = LedgerPolicy {
        retry_backoff: Duration::from_millis(10),
        ..LedgerPolicy::default()
    };
    let ledger = FactLedger::open(directory.path().join("private"), policy).unwrap();
    let upstream_state = Arc::new(Upstream::default());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!(
        "http://{}/backend-api/codex",
        upstream_listener.local_addr().unwrap()
    );
    let upstream_for_service = upstream_state.clone();
    let upstream_service = tokio::spawn(async move {
        axum::serve(
            upstream_listener,
            Router::new()
                .route("/backend-api/codex/responses", post(upstream))
                .with_state(upstream_for_service),
        )
        .await
        .unwrap()
    });
    let collector_state = Arc::new(Collector::default());
    collector_state
        .codes
        .lock()
        .unwrap()
        .extend([StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK]);
    let collector_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector_url = format!("http://{}/facts", collector_listener.local_addr().unwrap());
    let collector_for_service = collector_state.clone();
    let collector_service = tokio::spawn(async move {
        axum::serve(
            collector_listener,
            Router::new()
                .route("/facts", post(collector))
                .with_state(collector_for_service),
        )
        .await
        .unwrap()
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        "Bearer synthetic-oauth-access".parse().unwrap(),
    );
    headers.insert("chatgpt-account-id", "workspace-alpha".parse().unwrap());
    let provider = Provider {
        name: "OpenAI".into(),
        base_url: upstream_url,
        query_params: None,
        headers,
        retry: RetryConfig {
            max_attempts: 0,
            base_delay: Duration::from_millis(1),
            retry_429: false,
            retry_5xx: false,
            retry_transport: false,
        },
        stream_idle_timeout: Duration::from_secs(5),
    };
    let encoded =
        EncodedJsonBody::encode(&json!({"model":"gpt-5","input":[],"stream":true})).unwrap();
    let logical_sha = digest(encoded.as_bytes());
    let mut request = provider.build_request(http::Method::POST, "/responses");
    request.body = Some(RequestBody::EncodedJson(encoded));
    request.compression = RequestCompression::Zstd;
    let request = request.into_prepared().unwrap();
    let wire_sha = match request.body.as_ref().unwrap() {
        RequestBody::EncodedJson(body) => digest(body.as_bytes()),
        _ => panic!("prepared request must remain encoded JSON"),
    };
    let outbound_identity = identity("alpha");
    let journal = Arc::new(Mutex::new(
        ledger
            .begin(outbound_identity.clone(), &logical_sha, &wire_sha)
            .unwrap(),
    ));
    let metrics = MetricsClient::new(
        MetricsConfig::in_memory(
            "test",
            "right-codex",
            "0.160.0",
            InMemoryMetricExporter::default(),
        )
        .with_runtime_reader(),
    )
    .unwrap();
    let telemetry = AccountTelemetry::new(outbound_identity, "gpt-5", "gpt-5", metrics).unwrap();
    let hooked_journal = journal.clone();
    telemetry
        .set_observer(Arc::new(move |observed| {
            hooked_journal
                .lock()
                .unwrap()
                .observe_hook(&observed)
                .unwrap();
        }))
        .unwrap_or_else(|_| panic!("hook observer is already installed"));
    let transport = ReqwestTransport::new(client);
    let started = std::time::Instant::now();
    let response = transport.stream(request).await.unwrap();
    telemetry
        .request_hook()
        .on_request(1, Some(response.status), None, started.elapsed());
    journal
        .lock()
        .unwrap()
        .http_response(
            response.status.as_u16(),
            response
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Duration::from_millis(3),
        )
        .unwrap();
    let mut stream = response.bytes.eventsource();
    while let Some(event) = stream.next().await {
        let event = event.unwrap();
        telemetry
            .sse_hook()
            .on_sse_poll(&Ok(Some(Ok(event.clone()))), Duration::from_millis(1));
        journal
            .lock()
            .unwrap()
            .stream_event(&event.event, event.data.as_bytes())
            .unwrap();
    }
    journal
        .lock()
        .unwrap()
        .finish(TerminalKind::Completed, true)
        .unwrap();

    {
        let sent_bodies = upstream_state.bodies.lock().unwrap();
        assert_eq!(sent_bodies.len(), 1);
        assert_eq!(digest(&sent_bodies[0]), logical_sha);
        assert_eq!(digest(&upstream_state.wires.lock().unwrap()[0]), wire_sha);
        let sent_headers = upstream_state.headers.lock().unwrap();
        assert_eq!(
            sent_headers[0][header::AUTHORIZATION],
            "Bearer synthetic-oauth-access"
        );
        assert_eq!(sent_headers[0]["chatgpt-account-id"], "workspace-alpha");
    }

    let exporter = FactExporter::new(ledger.clone(), &collector_url, true).unwrap();
    assert!(matches!(
        exporter.export_once("alpha").await,
        Err(LedgerError::ExportFailed)
    ));
    assert!(matches!(
        exporter.export_once("alpha").await,
        Err(LedgerError::ExportDeferred)
    ));
    tokio::time::sleep(Duration::from_millis(15)).await;
    let delivered = exporter.export_once("alpha").await.unwrap();
    assert_eq!(delivered.pending, 0);
    assert_eq!(delivered.acknowledged, 6);
    assert_eq!(exporter.export_once("alpha").await.unwrap().acknowledged, 0);
    let deliveries = collector_state.bodies.lock().unwrap();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(deliveries[0], deliveries[1]);
    let serialized = deliveries[1].to_string();
    assert!(!serialized.contains("synthetic-oauth-access"));
    assert!(!serialized.contains("workspace-alpha"));
    assert!(serialized.contains(&wire_sha));
    assert!(serialized.contains("upstream-real-response"));
    assert_eq!(deliveries[1]["facts"].as_array().unwrap().len(), 6);
    upstream_service.abort();
    collector_service.abort();
}

#[tokio::test]
async fn private_collector_pauses_for_idle_disabled_or_deleted_account() {
    let directory = TempDir::new().unwrap();
    let auth_path = directory.path().join("auth.json");
    std::fs::write(
        &auth_path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt",
            "tokens":{
                "access_token":"synthetic-access",
                "refresh_token":"synthetic-refresh",
                "account_id":"fixture-workspace-alpha"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let config = GatewayConfig {
        allow_insecure_http: true,
        state_dir: directory.path().join("state"),
        accounts: vec![AccountConfig {
            id: "alpha".into(),
            auth_path,
            proxy: None,
            enabled: true,
        }],
        ..GatewayConfig::default()
    };
    let pool = AccountPool::from_config(&config).unwrap();
    let account = pool.next_enabled().unwrap().unwrap();
    let ledger = FactLedger::open(
        directory.path().join("private-facts"),
        LedgerPolicy::default(),
    )
    .unwrap();
    let record = || {
        let mut outbound = identity("alpha");
        outbound.workspace_account_id = account.workspace_account_id().to_owned();
        outbound.auth_revision = account.revision().to_owned();
        ledger
            .begin(outbound, &digest(b"logical"), &digest(b"wire"))
            .unwrap()
            .finish(TerminalKind::Unknown, false)
            .unwrap();
    };
    let collector_state = Arc::new(Collector::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/facts", listener.local_addr().unwrap());
    let server = tokio::spawn({
        let collector_state = collector_state.clone();
        async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/facts", post(collector))
                    .with_state(collector_state),
            )
            .await
            .unwrap();
        }
    });
    let exporter = FactExporter::new(ledger.clone(), &endpoint, true).unwrap();

    let mut prior_revision = identity("alpha");
    prior_revision.workspace_account_id = account.workspace_account_id().to_owned();
    ledger
        .begin(
            prior_revision,
            &digest(b"old-logical"),
            &digest(b"old-wire"),
        )
        .unwrap()
        .finish(TerminalKind::Unknown, false)
        .unwrap();
    record();
    pool.set_enabled("alpha", false).unwrap();
    assert!(matches!(
        exporter.export_for_account(&account).await,
        Err(LedgerError::AccountInactive)
    ));
    assert!(collector_state.bodies.lock().unwrap().is_empty());

    pool.set_enabled("alpha", true).unwrap();
    assert_eq!(
        exporter
            .export_for_account(&account)
            .await
            .unwrap()
            .acknowledged,
        2
    );
    assert_eq!(collector_state.bodies.lock().unwrap().len(), 1);
    assert_eq!(
        collector_state.bodies.lock().unwrap()[0]["facts"]
            .as_array()
            .unwrap()
            .len(),
        2,
        "a current revision must not export a predecessor's facts"
    );

    let active = pool.lease("alpha", true).unwrap().unwrap();
    record();
    assert!(!pool.delete_draining("alpha").unwrap());
    // A request that already owns a lease may drain its own facts.
    assert_eq!(
        exporter
            .export_for_account(&account)
            .await
            .unwrap()
            .acknowledged,
        2
    );
    assert_eq!(collector_state.bodies.lock().unwrap().len(), 2);

    record();
    drop(active);
    assert!(matches!(
        exporter.export_for_account(&account).await,
        Err(LedgerError::AccountInactive)
    ));
    assert_eq!(collector_state.bodies.lock().unwrap().len(), 2);
    server.abort();
}

#[derive(Default)]
struct OtlpCollector {
    bodies: Mutex<Vec<Vec<u8>>>,
    headers: Mutex<Vec<HeaderMap>>,
    codes: Mutex<VecDeque<StatusCode>>,
}

async fn otlp_collector(
    State(state): State<Arc<OtlpCollector>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    state.bodies.lock().unwrap().push(body.to_vec());
    state.headers.lock().unwrap().push(headers);
    state
        .codes
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(StatusCode::OK)
}

#[tokio::test]
async fn disabled_revision_pauses_metrics_then_reenable_and_draining_follow_live_owner() {
    let directory = TempDir::new().unwrap();
    let collector = Arc::new(OtlpCollector::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/metrics", listener.local_addr().unwrap());
    let server = tokio::spawn({
        let collector = collector.clone();
        async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/metrics", post(otlp_collector))
                    .with_state(collector),
            )
            .await
            .unwrap();
        }
    });
    let auth_path = directory.path().join("auth.json");
    std::fs::write(
        &auth_path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt","tokens":{"access_token":"synthetic-access",
                "refresh_token":"synthetic-refresh","account_id":"fixture-workspace-alpha"}
        }))
        .unwrap(),
    )
    .unwrap();
    let mut config = GatewayConfig {
        allow_insecure_http: true,
        state_dir: directory.path().join("state"),
        accounts: vec![AccountConfig {
            id: "alpha".into(),
            auth_path,
            proxy: None,
            enabled: true,
        }],
        ..GatewayConfig::default()
    };
    config.telemetry.otlp_endpoint = Some(endpoint);
    config.telemetry.allow_loopback_http = true;
    let pool = AccountPool::from_config(&config).unwrap();
    let account = pool.next_enabled().unwrap().unwrap();
    let registry = TelemetryRegistry::new(config.telemetry).unwrap();
    let mut outbound = identity("alpha");
    outbound.workspace_account_id = account.workspace_account_id().to_owned();
    outbound.auth_revision = account.revision().to_owned();
    let hook = registry
        .for_account(&account, outbound, "gpt-5", "gpt-5")
        .unwrap();
    hook.request_hook()
        .on_request(1, Some(StatusCode::OK), None, Duration::from_millis(2));

    pool.set_enabled("alpha", false).unwrap();
    let paused = registry.flush_account(&account).await.unwrap();
    assert_eq!(
        paused.disabled_reason,
        Some(DisabledReason::InactiveAccount)
    );
    assert!(collector.bodies.lock().unwrap().is_empty());
    pool.set_enabled("alpha", true).unwrap();
    let resumed = registry.flush_account(&account).await.unwrap();
    assert_eq!(resumed.acked_batches, 1);
    assert_eq!(collector.bodies.lock().unwrap().len(), 1);

    let lease = pool.lease("alpha", true).unwrap().unwrap();
    hook.request_hook()
        .on_request(2, Some(StatusCode::OK), None, Duration::from_millis(3));
    assert!(!pool.delete_draining("alpha").unwrap());
    // An already active request may finish its own metric delivery.
    assert_eq!(
        registry
            .flush_account(&account)
            .await
            .unwrap()
            .acked_batches,
        1
    );
    assert_eq!(collector.bodies.lock().unwrap().len(), 2);
    hook.request_hook()
        .on_request(3, Some(StatusCode::OK), None, Duration::from_millis(4));
    drop(lease);
    assert_eq!(
        registry
            .flush_account(&account)
            .await
            .unwrap()
            .disabled_reason,
        Some(DisabledReason::InactiveAccount)
    );
    assert_eq!(collector.bodies.lock().unwrap().len(), 2);
    drop(account);
    assert_eq!(registry.export_all().await.unwrap().disabled_accounts, 1);
    assert_eq!(collector.bodies.lock().unwrap().len(), 2);
    server.abort();
}

#[tokio::test]
async fn official_metrics_use_actual_account_client_and_durable_unknown_delivery() {
    let directory = TempDir::new().unwrap();
    let state = Arc::new(OtlpCollector::default());
    state
        .codes
        .lock()
        .unwrap()
        .push_back(StatusCode::SERVICE_UNAVAILABLE);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/metrics", listener.local_addr().unwrap());
    let server_state = state.clone();
    let service = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/metrics", post(otlp_collector))
                .with_state(server_state),
        )
        .await
        .unwrap()
    });

    let auth_path = directory.path().join("auth.json");
    std::fs::write(
        &auth_path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt",
            "tokens":{
                "access_token":"synthetic-access",
                "refresh_token":"synthetic-refresh",
                "account_id":"fixture-workspace-alpha"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mut gateway = GatewayConfig {
        allow_insecure_http: true,
        state_dir: directory.path().join("state"),
        accounts: vec![AccountConfig {
            id: "alpha".into(),
            auth_path,
            proxy: None,
            enabled: true,
        }],
        ..GatewayConfig::default()
    };
    gateway.telemetry.otlp_endpoint = Some(endpoint);
    gateway.telemetry.allow_loopback_http = true;
    gateway.telemetry.retry_backoff_seconds = 1;
    let accounts = AccountPool::from_config(&gateway).unwrap();
    let account = accounts.next_enabled().unwrap().unwrap();
    let registry = TelemetryRegistry::new(gateway.telemetry.clone()).unwrap();
    let mut outbound = identity("alpha");
    outbound.workspace_account_id = account.workspace_account_id().to_owned();
    outbound.auth_revision = account.revision().to_owned();
    let hooks = registry
        .for_account(&account, outbound, "gpt-5", "gpt-5")
        .unwrap();
    hooks
        .request_hook()
        .on_request(1, Some(StatusCode::OK), None, Duration::from_millis(6));
    hooks.sse_hook().on_sse_poll(
        &Ok(Some(Ok(eventsource_stream::Event {
            event: "response.completed".into(),
            ..Default::default()
        }))),
        Duration::from_millis(2),
    );

    let first = registry.flush_account(&account).await.unwrap();
    assert_eq!(first.acked_batches, 0);
    assert!(first.unknown_delivery_batches >= 1);
    assert_eq!(state.bodies.lock().unwrap().len(), 1);
    let body = state.bodies.lock().unwrap()[0].clone();
    let parsed = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
    let names = parsed
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
        .map(|metric| metric.name.as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"codex.api_request"));
    assert!(names.contains(&"codex.sse_event"));
    assert!(!String::from_utf8_lossy(&body).contains("synthetic-access"));
    assert!(!String::from_utf8_lossy(&body).contains("fixture-workspace-alpha"));
    assert_eq!(
        state.headers.lock().unwrap()[0][header::CONTENT_TYPE],
        "application/x-protobuf"
    );
    assert!(
        state.headers.lock().unwrap()[0]
            .get(header::AUTHORIZATION)
            .is_none()
    );

    let second = registry.flush_account(&account).await.unwrap();
    assert_eq!(second.acked_batches, 0);
    assert!(second.unknown_delivery_batches >= 1);
    assert_eq!(
        state.bodies.lock().unwrap().len(),
        1,
        "an unconfirmed POST must not be replayed"
    );
    drop(registry);
    let restarted = TelemetryRegistry::new(gateway.telemetry.clone()).unwrap();
    let delivery = restarted.delivery_list(&account).await.unwrap();
    assert_eq!(delivery.len(), 1);
    assert_eq!(delivery[0].auth_revision, account.revision());
    assert_eq!(delivery[0].state, MetricDeliveryState::Attempted);
    let cleared = restarted.clear_delivery(&account).await.unwrap();
    assert_eq!(cleared.pending, 0);
    assert_eq!(cleared.attempted, 1);
    assert_eq!(cleared.acked, 0);
    assert!(restarted.delivery_list(&account).await.unwrap().is_empty());
    service.abort();
}
