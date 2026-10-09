//! A real gateway router and the pinned SDK send to controlled loopback peers.
//! OAuth tokens, upstream responses, OTLP, and the private collector are fixtures.
use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use base64::Engine;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value;
use opentelemetry_proto::tonic::metrics::v1::metric;
use prost::Message;
use right_codex::accounts::AccountPool;
use right_codex::config::{AccountConfig, GatewayConfig};
use right_codex::gateway::{AppState, router};
use right_codex::telemetry::{NetworkFact, TerminalKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone)]
struct Outbound {
    headers: HeaderMap,
    wire: Vec<u8>,
    logical: Vec<u8>,
    body: Value,
    raw_events: Vec<String>,
}

#[derive(Default)]
struct Upstream {
    outbound: Mutex<Vec<Outbound>>,
}

async fn upstream(State(state): State<Arc<Upstream>>, headers: HeaderMap, wire: Bytes) -> Response {
    let logical = if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "zstd")
    {
        zstd::stream::decode_all(std::io::Cursor::new(&wire)).unwrap()
    } else {
        wire.to_vec()
    };
    let body: Value = serde_json::from_slice(&logical).unwrap();
    let workspace = headers["chatgpt-account-id"].to_str().unwrap().to_owned();
    let (response_id, input, output) = match workspace.as_str() {
        "workspace-alpha" => ("upstream-alpha", 7, 3),
        "workspace-beta" => ("upstream-beta", 11, 5),
        _ => panic!("unexpected outbound workspace"),
    };
    let created = json!({"type":"response.created","response":{
        "id":response_id,"status":"in_progress"}})
    .to_string();
    let completed = json!({"type":"response.completed","response":{
        "id":response_id,"status":"completed","output":[{"type":"message",
            "id":format!("message-{workspace}"),"role":"assistant",
            "content":[{"type":"output_text","text":"fixture answer","annotations":[]}]}
        ],"usage":{"input_tokens":input,"output_tokens":output,
            "total_tokens":input+output,"input_tokens_details":{"cached_tokens":2},
            "output_tokens_details":{"reasoning_tokens":1}}}})
    .to_string();
    state.outbound.lock().unwrap().push(Outbound {
        headers,
        wire: wire.to_vec(),
        logical,
        body,
        raw_events: vec![created.clone(), completed.clone()],
    });
    let payload = format!(
        "event: response.created\ndata: {created}\n\nevent: response.completed\ndata: {completed}\n\n"
    );
    let chunks = payload
        .as_bytes()
        .chunks(13)
        .map(|chunk| Ok::<Bytes, Infallible>(Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header("x-request-id", format!("fixture-{workspace}"))
        .body(Body::from_stream(futures_util::stream::iter(chunks)))
        .unwrap()
}

async fn account_route(headers: HeaderMap) -> axum::Json<Value> {
    let workspace = headers["chatgpt-account-id"].to_str().unwrap();
    let account = workspace.strip_prefix("workspace-").unwrap();
    assert!(matches!(account, "alpha" | "beta"));
    assert_eq!(
        headers[header::AUTHORIZATION].to_str().unwrap(),
        format!("Bearer pool-secret-{account}")
    );
    axum::Json(json!({"accounts":[
        {"id":"workspace-alpha"},{"id":"workspace-beta"}
    ],"default_account_id":"workspace-alpha"}))
}

#[derive(Default)]
struct Collector {
    metrics: Mutex<Vec<Vec<u8>>>,
    facts: Mutex<Vec<Value>>,
}

async fn collect_metrics(State(state): State<Arc<Collector>>, body: Bytes) -> StatusCode {
    state.metrics.lock().unwrap().push(body.to_vec());
    StatusCode::OK
}

async fn collect_facts(State(state): State<Arc<Collector>>, body: Bytes) -> StatusCode {
    state
        .facts
        .lock()
        .unwrap()
        .push(serde_json::from_slice(&body).unwrap());
    StatusCode::OK
}

fn auth(path: &std::path::Path, account: &str) {
    let encode = |value: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    };
    let id_token = format!(
        "{}.{}.fixture",
        encode(json!({"alg":"none"})),
        encode(
            json!({"email":"fixture@example.invalid","exp":3000000000_u64,
            "https://api.openai.com/auth":{"chatgpt_account_id":format!("workspace-{account}"),
                "chatgpt_user_id":format!("user-{account}"),"chatgpt_plan_type":"plus"}})
        )
    );
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt",
            "tokens":{"id_token":id_token,"access_token":format!("pool-secret-{account}"),
                "refresh_token":format!("pool-refresh-{account}"),
                "account_id":format!("workspace-{account}")},
            "last_refresh":"2026-10-09T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
}

fn usage_points(raw: &[u8]) -> (HashSet<String>, BTreeMap<String, (u64, f64)>) {
    let decoded = ExportMetricsServiceRequest::decode(raw).unwrap();
    let mut names = HashSet::new();
    let mut usage = BTreeMap::new();
    for metric in decoded
        .resource_metrics
        .iter()
        .flat_map(|resource| &resource.scope_metrics)
        .flat_map(|scope| &scope.metrics)
    {
        names.insert(metric.name.clone());
        if metric.name != "codex.turn.token_usage" {
            continue;
        }
        let Some(metric::Data::Histogram(histogram)) = &metric.data else {
            panic!("official token usage must be a histogram");
        };
        for point in &histogram.data_points {
            let token_type = point
                .attributes
                .iter()
                .find_map(|attribute| {
                    if attribute.key != "token_type" {
                        return None;
                    }
                    match attribute.value.as_ref()?.value.as_ref()? {
                        any_value::Value::StringValue(value) => Some(value.clone()),
                        _ => None,
                    }
                })
                .unwrap();
            assert_eq!(point.count, 1);
            assert!(
                usage
                    .insert(token_type, (point.count, point.sum.unwrap()))
                    .is_none()
            );
        }
    }
    (names, usage)
}

#[tokio::test]
async fn actual_gateway_attempt_aligns_wire_private_facts_and_account_scoped_otlp() {
    let directory = TempDir::new().unwrap();
    let upstream_state = Arc::new(Upstream::default());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn({
        let state = upstream_state.clone();
        async move {
            axum::serve(
                upstream_listener,
                Router::new()
                    .route("/backend-api/codex/responses", post(upstream))
                    .route("/backend-api/wham/accounts/check", get(account_route))
                    .with_state(state),
            )
            .await
            .unwrap();
        }
    });
    let collector_state = Arc::new(Collector::default());
    let collector_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let collector_addr = collector_listener.local_addr().unwrap();
    let collector_task = tokio::spawn({
        let state = collector_state.clone();
        async move {
            axum::serve(
                collector_listener,
                Router::new()
                    .route("/metrics", post(collect_metrics))
                    .route("/facts", post(collect_facts))
                    .with_state(state),
            )
            .await
            .unwrap();
        }
    });
    let mut config = GatewayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        allow_insecure_http: true,
        state_dir: directory.path().join("state"),
        base_url: format!("http://{upstream_addr}/backend-api/codex"),
        chatgpt_base_url: format!("http://{upstream_addr}/backend-api"),
        oauth_issuer: format!("http://{upstream_addr}"),
        ..GatewayConfig::default()
    };
    config.scheduling.startup_spacing_secs = 0;
    config.scheduling.max_sessions_by_account_age = [16; 5];
    config.telemetry.allow_loopback_http = true;
    config.telemetry.otlp_endpoint = Some(format!("http://{collector_addr}/metrics"));
    config.telemetry.collector_endpoint = Some(format!("http://{collector_addr}/facts"));
    for account in ["alpha", "beta"] {
        let path = directory.path().join(format!("{account}.json"));
        auth(&path, account);
        config.accounts.push(AccountConfig {
            id: account.to_owned(),
            auth_path: path,
            proxy: None,
            enabled: true,
        });
    }
    let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
    assert_eq!(state.accounts.enabled_count().unwrap(), 2);
    assert!(
        state
            .accounts
            .has_eligible_excluding(&HashSet::new())
            .unwrap()
    );
    assert!(
        state.collector.is_some(),
        "configured collector must be live"
    );
    let gateway_listener = TcpListener::bind(config.listen).await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let gateway_task = tokio::spawn({
        let state = state.clone();
        async move {
            axum::serve(
                gateway_listener,
                router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut client_terminals = Vec::new();
    for suffix in ["A", "B"] {
        let response = client
            .post(format!("http://{gateway_addr}/v1/responses"))
            .bearer_auth(format!("CLIENT_ONLY_OAUTH_{suffix}"))
            .header("thread-id", format!("CLIENT_THREAD_{suffix}"))
            .header("chatgpt-account-id", format!("CLIENT_ACCOUNT_{suffix}"))
            .header(header::USER_AGENT, format!("CLIENT_USER_AGENT_{suffix}"))
            .json(&json!({
                "model":"fixture-model","stream":true,
                "input":[{"role":"user","content":"hello"}],
                "client_metadata":{"thread_id":format!("CLIENT_METADATA_{suffix}"),
                    "turn_id":format!("CLIENT_TURN_{suffix}")},
                "metadata":{"client_id":format!("CLIENT_ID_{suffix}")}
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let response_body = response.text().await.unwrap();
        let error_code = serde_json::from_str::<Value>(&response_body)
            .ok()
            .and_then(|body| {
                body.pointer("/error/code")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        assert_eq!(
            status,
            StatusCode::OK,
            "request {suffix} gateway error code: {error_code:?}"
        );
        let events = response_body
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|raw| serde_json::from_str::<Value>(raw).unwrap())
            .collect::<Vec<_>>();
        let terminal = events
            .iter()
            .find(|event| event["type"] == "response.completed")
            .expect("the validated terminal was delivered");
        client_terminals.push(terminal.clone());
    }

    let captured = upstream_state.outbound.lock().unwrap().clone();
    assert_eq!(captured.len(), 2);
    let workspace_ids = captured
        .iter()
        .map(|item| {
            item.headers["chatgpt-account-id"]
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        workspace_ids,
        HashSet::from(["workspace-alpha".to_owned(), "workspace-beta".to_owned()])
    );
    let private = state.facts.snapshot();
    assert_eq!(private.len(), 2);
    for sent in &captured {
        let workspace = sent.headers["chatgpt-account-id"].to_str().unwrap();
        let account = workspace.strip_prefix("workspace-").unwrap();
        assert_eq!(
            sent.headers[header::AUTHORIZATION].to_str().unwrap(),
            format!("Bearer pool-secret-{account}")
        );
        assert_eq!(sent.headers[header::CONTENT_ENCODING], "zstd");
        assert_eq!(
            sent.wire,
            zstd::stream::encode_all(std::io::Cursor::new(&sent.logical), 3).unwrap()
        );
        let raw = String::from_utf8_lossy(&sent.logical);
        assert!(!raw.contains("CLIENT_"));
        assert!(
            !sent.headers[header::USER_AGENT]
                .to_str()
                .unwrap()
                .starts_with("CLIENT_")
        );
        let diagnostic = private
            .iter()
            .find(|fact| fact.account_id == account)
            .unwrap();
        let attempts = state.ledger.snapshot(account).unwrap();
        assert_eq!(attempts.len(), 1);
        let attempt = &attempts[0];
        assert_eq!(diagnostic.outcome, "completed");
        assert_eq!(attempt.terminal, Some(TerminalKind::Completed));
        assert_eq!(diagnostic.attempt_id, attempt.identity.attempt_id);
        assert_eq!(diagnostic.request_sha256, sha(&sent.logical));
        assert_eq!(diagnostic.wire_sha256, sha(&sent.wire));
        assert_eq!(
            attempt.identity.thread_id,
            sent.headers["thread-id"].to_str().unwrap()
        );
        assert_eq!(
            attempt.identity.turn_id,
            sent.body["client_metadata"]["turn_id"].as_str().unwrap()
        );
        assert_eq!(diagnostic.thread_id, attempt.identity.thread_id);
        assert_eq!(diagnostic.turn_id, attempt.identity.turn_id);
        assert_eq!(diagnostic.event_count, 2);
        assert_eq!(
            diagnostic.usage.as_ref().unwrap()["input_tokens"],
            if account == "alpha" { 7 } else { 11 }
        );
        let original_hashes = sent
            .raw_events
            .iter()
            .map(|event| sha(event.as_bytes()))
            .collect::<HashSet<_>>();
        let mut observed_hashes = HashSet::new();
        let mut http_hooks = 0;
        let mut sse_hooks = 0;
        let mut offered = false;
        for item in &attempt.facts {
            match &item.fact {
                NetworkFact::Started {
                    identity,
                    request_sha256,
                    wire_sha256,
                    ..
                } => {
                    assert_eq!(identity.thread_id, attempt.identity.thread_id);
                    assert_eq!(identity.turn_id, attempt.identity.turn_id);
                    assert_eq!(identity.attempt_id, attempt.identity.attempt_id);
                    assert_eq!(request_sha256, &sha(&sent.logical));
                    assert_eq!(wire_sha256, &sha(&sent.wire));
                }
                NetworkFact::HttpResponse {
                    status,
                    upstream_request_id,
                    ..
                } => {
                    assert_eq!(*status, 200);
                    let expected_request_id = format!("fixture-{workspace}");
                    assert_eq!(
                        upstream_request_id.as_deref(),
                        Some(expected_request_id.as_str())
                    );
                }
                NetworkFact::StreamEvent {
                    event_sha256,
                    event_kind,
                    usage,
                    ..
                } => {
                    assert!(matches!(
                        event_kind.as_str(),
                        "response.created" | "response.completed"
                    ));
                    observed_hashes.insert(event_sha256.clone());
                    if event_kind == "response.completed" {
                        let original: Value = serde_json::from_str(&sent.raw_events[1]).unwrap();
                        assert_eq!(
                            usage.as_ref().unwrap()["total_tokens"],
                            original["response"]["usage"]["total_tokens"]
                        );
                    }
                }
                NetworkFact::HookObservation { source, .. } if source == "http_request" => {
                    http_hooks += 1
                }
                NetworkFact::HookObservation { source, .. } if source == "sse_poll" => {
                    sse_hooks += 1
                }
                NetworkFact::Terminal {
                    outcome,
                    offered_to_client,
                    ..
                } => {
                    assert_eq!(*outcome, TerminalKind::Completed);
                    offered = *offered_to_client;
                }
                _ => {}
            }
        }
        assert_eq!(observed_hashes, original_hashes);
        assert_eq!(http_hooks, 1);
        assert!(sse_hooks >= 2);
        assert!(offered);
    }
    for terminal in &client_terminals {
        assert!(
            [10, 16].contains(
                &terminal["response"]["usage"]["total_tokens"]
                    .as_u64()
                    .unwrap()
            )
        );
        assert!(
            !["upstream-alpha", "upstream-beta"]
                .contains(&terminal["response"]["id"].as_str().unwrap())
        );
    }

    for account in state.accounts.all().unwrap() {
        let report = state.metrics.flush_account(&account).await.unwrap();
        assert_eq!(report.acked_batches, 1);
    }
    let metrics = collector_state.metrics.lock().unwrap().clone();
    assert_eq!(metrics.len(), 2);
    let mut metric_totals = HashSet::new();
    for body in &metrics {
        let decoded = ExportMetricsServiceRequest::decode(body.as_slice()).unwrap();
        for resource in &decoded.resource_metrics {
            let attributes = &resource.resource.as_ref().unwrap().attributes;
            let string_attribute = |name: &str| {
                attributes.iter().find_map(|attribute| {
                    if attribute.key != name {
                        return None;
                    }
                    match attribute.value.as_ref()?.value.as_ref()? {
                        any_value::Value::StringValue(value) => Some(value.as_str()),
                        _ => None,
                    }
                })
            };
            assert_eq!(string_attribute("env"), Some("dev"));
            assert_eq!(string_attribute("service.version"), Some("0.160.0"));
            assert_eq!(
                string_attribute("service.name"),
                Some(codex_login::default_client::originator().value.as_str())
            );
        }
        let (names, points) = usage_points(body);
        assert!(names.contains("codex.api_request"));
        assert!(names.contains("codex.sse_event"));
        assert_eq!(points["cached_input"], (1, 2.0));
        assert_eq!(points["reasoning_output"], (1, 1.0));
        let total = points["total"].1;
        assert_eq!(points["input"].0, 1);
        assert_eq!(points["output"].0, 1);
        assert!(metric_totals.insert(total as u64));
        assert!(!String::from_utf8_lossy(body).contains("CLIENT_"));
        assert!(!String::from_utf8_lossy(body).contains("pool-secret"));
    }
    assert_eq!(metric_totals, HashSet::from([10, 16]));

    // The configured private collector is exercised by the runtime worker,
    // rather than by a test-only direct FactExporter construction.
    let runtime = right_codex::runtime::start(state.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if collector_state.facts.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    runtime.abort();
    let delivered = collector_state.facts.lock().unwrap().clone();
    assert_eq!(delivered.len(), 2);
    let accounts = delivered
        .iter()
        .map(|batch| batch["account_key"].as_str().unwrap().to_owned())
        .collect::<HashSet<_>>();
    assert_eq!(accounts, HashSet::from([sha(b"alpha"), sha(b"beta")]));
    for batch in &delivered {
        let encoded = batch.to_string();
        assert!(!encoded.contains("CLIENT_"));
        assert!(!encoded.contains("pool-secret"));
        assert!(
            batch["facts"]
                .as_array()
                .is_some_and(|facts| !facts.is_empty())
        );
    }
    gateway_task.abort();
    upstream_task.abort();
    collector_task.abort();
}
