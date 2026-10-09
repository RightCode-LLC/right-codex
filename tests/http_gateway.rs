//! Loopback protocol checks. All OAuth tokens and upstream responses are synthetic.
//! No official account, home directory, TUI, daemon or external network is used.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use base64::Engine;
use right_codex::accounts::AccountPool;
use right_codex::config::{AccountConfig, GatewayConfig};
use right_codex::gateway::{AppState, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const CLIENT_KEY: &str = "synthetic-client-gateway-key";

#[derive(Clone)]
struct Captured {
    headers: HeaderMap,
    wire: Vec<u8>,
    decoded: Vec<u8>,
    body: Value,
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: &'static str,
    retry_after: Option<&'static str>,
}

impl Reply {
    fn sse(events: Vec<Value>) -> Self {
        let mut body = Vec::new();
        for event in events {
            body.extend_from_slice(
                format!(
                    "event: {}\ndata: {}\n\n",
                    event["type"].as_str().unwrap(),
                    event
                )
                .as_bytes(),
            );
        }
        Self {
            status: StatusCode::OK,
            body,
            content_type: "text/event-stream",
            retry_after: None,
        }
    }

    fn http(status: StatusCode) -> Self {
        Self {
            status,
            body: br#"{"error":{"code":"synthetic_upstream_rejection"}}"#.to_vec(),
            content_type: "application/json",
            retry_after: Some("3"),
        }
    }
}

struct Upstream {
    captured: Mutex<Vec<Captured>>,
    replies: Mutex<VecDeque<Reply>>,
}

async fn upstream(State(state): State<Arc<Upstream>>, headers: HeaderMap, wire: Bytes) -> Response {
    let decoded = if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v == "zstd")
    {
        zstd::stream::decode_all(std::io::Cursor::new(&wire)).unwrap()
    } else {
        wire.to_vec()
    };
    let body: Value = serde_json::from_slice(&decoded).unwrap();
    let ordinal = {
        let mut captured = state.captured.lock().unwrap();
        captured.push(Captured {
            headers,
            wire: wire.to_vec(),
            decoded,
            body,
        });
        captured.len()
    };
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .expect("every expected upstream send has an explicit response");
    // Deliberately split even JSON strings and SSE delimiters across body chunks.
    let chunks: Vec<Bytes> = reply.body.chunks(11).map(Bytes::copy_from_slice).collect();
    let body = Body::from_stream(futures_util::stream::iter(
        chunks.into_iter().map(Ok::<_, Infallible>),
    ));
    let mut response = Response::builder()
        .status(reply.status)
        .header(header::CONTENT_TYPE, reply.content_type)
        .header("x-request-id", format!("fixture-request-{ordinal}"))
        .header("openai-model", format!("fixture-model-{ordinal}"))
        .header("x-reasoning-included", "false")
        .header("x-models-etag", "fixture-catalog")
        .header("x-codex-primary-used-percent", "23.5")
        .header("x-codex-primary-window-minutes", "300")
        .header("x-codex-safety-buffering-enabled", "true")
        .header("x-codex-safety-buffering-faster-model", "fixture-faster")
        .header("cf-ray", "fixture-private-ray")
        .header("x-codex-turn-state", "fixture-private-sticky")
        .body(body)
        .unwrap();
    if let Some(value) = reply.retry_after {
        response
            .headers_mut()
            .insert("retry-after", value.parse().unwrap());
    }
    response
}

struct Fixture {
    directory: TempDir,
    state: Arc<AppState>,
    upstream: Arc<Upstream>,
    client: reqwest::Client,
    endpoint: String,
    servers: Vec<JoinHandle<()>>,
}

impl Fixture {
    async fn new(replies: Vec<Reply>) -> Self {
        Self::with_accounts(replies, &["alpha", "beta"]).await
    }

    async fn with_accounts(replies: Vec<Reply>, ids: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Arc::new(Upstream {
            captured: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let upstream_router = Router::new()
            .route("/backend-api/codex/responses", post(self::upstream))
            .with_state(upstream.clone());
        let upstream_server = tokio::spawn(async move {
            axum::serve(listener, upstream_router).await.unwrap();
        });
        let accounts: Vec<AccountConfig> = ids
            .iter()
            .copied()
            .map(|id| {
                let path = directory.path().join(format!("{id}-auth.json"));
                write_auth(&path, id, &format!("synthetic-access-{id}"));
                AccountConfig {
                    id: id.into(),
                    auth_path: path,
                    proxy: None,
                    enabled: true,
                }
            })
            .collect();
        let config = GatewayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            client_api_key: CLIENT_KEY.into(),
            base_url: format!("http://{upstream_addr}/backend-api/codex"),
            allow_insecure_http: true,
            accounts,
            state_dir: directory.path().join("private-state"),
            oauth_issuer: format!("http://{upstream_addr}"),
            scheduling: right_codex::config::SchedulingConfig {
                max_sessions_by_account_age: [128; 5],
                startup_spacing_secs: 0,
                ..Default::default()
            },
            ..GatewayConfig::default()
        };
        let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
        let listener = TcpListener::bind(config.listen).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let gateway = router(state.clone());
        let gateway_server = tokio::spawn(async move {
            axum::serve(
                listener,
                gateway.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            directory,
            state,
            upstream,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            endpoint: format!("http://{addr}/v1/responses"),
            servers: vec![upstream_server, gateway_server],
        }
    }

    fn request(&self, thread: &str, body: &Value) -> reqwest::RequestBuilder {
        self.client
            .post(&self.endpoint)
            .bearer_auth(CLIENT_KEY)
            .header("thread-id", thread)
            .json(body)
    }

    async fn send(&self, thread: &str, body: &Value) -> (StatusCode, Vec<Value>) {
        let response = self.request(thread, body).send().await.unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        let events = text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|data| serde_json::from_str(data).unwrap())
            .collect();
        (status, events)
    }

    fn captured(&self) -> Vec<Captured> {
        self.upstream.captured.lock().unwrap().clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

fn write_auth(path: &std::path::Path, account: &str, token: &str) {
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "exp": 3000000000_u64, "https://api.openai.com/auth": {
                "chatgpt_account_id": format!("fixture-workspace-{account}"),
                "chatgpt_user_id": format!("fixture-user-{account}"), "chatgpt_plan_type":"pro"
            }
        }))
        .unwrap(),
    );
    std::fs::write(path, serde_json::to_vec(&json!({
        "auth_mode":"chatgpt",
        "tokens":{"id_token":format!("e30.{claims}.fixture"), "access_token":token,
            "refresh_token":format!("synthetic-refresh-{account}"), "account_id":format!("fixture-workspace-{account}")},
        "last_refresh":"2026-10-10T00:00:00Z"
    })).unwrap()).unwrap();
}

fn request_body() -> Value {
    json!({"model":"fixture-model","stream":true,"input":[{"role":"user","content":"hello"}]})
}

#[tokio::test]
async fn configured_session_capacity_rest_and_idle_recycling_preserve_existing_conversation() {
    let fixture = Fixture::new(vec![
        ordinary("first"),
        ordinary("existing"),
        ordinary("after-idle"),
    ])
    .await;
    fixture.state.accounts.set_enabled("beta", false).unwrap();
    let mut settings = fixture.state.scheduling();
    settings.max_sessions_by_account_age = [1; 5];
    settings.idle_timeout_secs = 1;
    fixture.state.set_scheduling(settings).unwrap();
    terminal(&fixture.send("capacity-existing", &request_body()).await.1);
    assert_eq!(
        fixture.send("capacity-new", &request_body()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture
        .state
        .accounts
        .rest("alpha", Duration::from_secs(30))
        .unwrap();
    // Rest blocks a new logical session, not the already assigned conversation.
    terminal(&fixture.send("capacity-existing", &request_body()).await.1);
    assert_eq!(
        fixture.send("resting-new", &request_body()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture
        .state
        .accounts
        .rest("alpha", Duration::ZERO)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    terminal(&fixture.send("after-idle", &request_body()).await.1);
    assert_eq!(fixture.captured().len(), 3);
    let restored = AppState::try_new(
        fixture.state.config.clone(),
        AccountPool::from_config(&fixture.state.config).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.scheduling().max_sessions_by_account_age, [1; 5]);
}

fn completed(id: &str, output: Value) -> Value {
    json!({"type":"response.completed","response":{"id":id,"status":"completed","output":output,
        "usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10,
            "attribution":{"request_fields":{"service_tier":"default","text":{"verbosity":"low"}}}}}})
}

fn ordinary(id: &str) -> Reply {
    Reply::sse(vec![
        json!({"type":"response.created","response":{"id":id,"status":"in_progress"}}),
        json!({"type":"response.output_text.delta","response_id":id,"item_id":"upstream-message","delta":"hello"}),
        completed(
            id,
            json!([{"type":"message","id":"upstream-message","role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}]),
        ),
    ])
}

fn terminal(events: &[Value]) -> &Value {
    events
        .iter()
        .find(|event| event["type"] == "response.completed")
        .expect("an actual completed event must be delivered")
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[tokio::test]
async fn complete_fragmented_sse_preserves_semantics_and_replaces_client_identity() {
    let fixture = Fixture::new(vec![ordinary("upstream-response-one")]).await;
    let mut input = request_body();
    input["input"][0]["id"] = json!("CLIENT_MESSAGE_ID");
    input["input"].as_array_mut().unwrap().push(json!({"type":"reasoning","id":"CLIENT_REASONING_ID",
        "summary":[{"type":"summary_text","text":"readable summary"}],"encrypted_content":"CLIENT_CIPHERTEXT"}));
    input["instructions"] = json!("preserve instructions");
    input["reasoning"] = json!({"effort":"medium","summary":"concise","context":"all_turns"});
    input["text"] = json!({"verbosity":"low"});
    input["client_metadata"] = json!({"thread_id":"CLIENT_METADATA_THREAD","turn_id":"CLIENT_METADATA_TURN","x-codex-turn-metadata": "{\"request_kind\":\"turn\"}"});
    input["metadata"] = json!({"client_id":"CLIENT_METADATA_ID"});
    input["prompt_cache_key"] = json!("CLIENT_CACHE_KEY");
    input["id"] = json!("CLIENT_REQUEST_ID");
    input["store"] = json!(true);
    let response = fixture
        .request("CLIENT_THREAD_LABEL", &input)
        .header(header::USER_AGENT, "CLIENT_USER_AGENT")
        .header("originator", "CLIENT_ORIGINATOR")
        .header("session-id", "CLIENT_SESSION_HEADER")
        .header("x-codex-installation-id", "CLIENT_INSTALLATION")
        .header("traceparent", "CLIENT_TRACE_HEADER")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let text = response.text().await.unwrap();
    let events: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|data| serde_json::from_str(data).unwrap())
        .collect();
    let end = terminal(&events);
    assert_eq!(
        end["response"]["usage"],
        completed("unused", json!([]))["response"]["usage"]
    );
    assert_ne!(end["response"]["id"], "upstream-response-one");
    let captured = fixture.captured();
    assert_eq!(captured.len(), 1);
    let sent = &captured[0];
    assert_eq!(sent.headers[header::CONTENT_ENCODING], "zstd");
    assert_eq!(
        sent.wire,
        zstd::stream::encode_all(std::io::Cursor::new(&sent.decoded), 3).unwrap()
    );
    assert_eq!(sent.body["instructions"], input["instructions"]);
    assert_eq!(sent.body["reasoning"], input["reasoning"]);
    assert_eq!(sent.body["text"], input["text"]);
    assert_eq!(sent.body["input"][0]["content"][0]["text"], "hello");
    assert_eq!(
        sent.body["input"][1]["summary"],
        input["input"][1]["summary"]
    );
    assert!(sent.body["input"][1].get("encrypted_content").is_none());
    assert_eq!(sent.body["store"], false);
    let official_originator = codex_login::default_client::originator().value;
    assert_eq!(
        sent.headers["originator"].to_str().unwrap(),
        official_originator
    );
    assert_eq!(
        sent.headers[header::USER_AGENT].to_str().unwrap(),
        codex_login::default_client::get_codex_user_agent()
    );
    assert!(
        sent.headers[header::USER_AGENT]
            .to_str()
            .unwrap()
            .starts_with(&format!(
                "{official_originator}/{} ",
                right_codex::CODEX_VERSION
            ))
    );
    assert_ne!(sent.headers[header::USER_AGENT], "CLIENT_USER_AGENT");
    assert_eq!(
        sent.headers["chatgpt-account-id"],
        "fixture-workspace-alpha"
    );
    assert_eq!(
        sent.headers[header::AUTHORIZATION],
        "Bearer synthetic-access-alpha"
    );
    for name in ["traceparent", "x-codex-installation-id"] {
        assert!(!sent.headers.contains_key(name));
    }
    let serialized = serde_json::to_string(&sent.body).unwrap();
    assert!(!serialized.contains("CLIENT_"));
    assert_eq!(
        sent.body["client_metadata"]["thread_id"].as_str().unwrap(),
        sent.headers["thread-id"].to_str().unwrap()
    );
    let facts = fixture.state.facts.snapshot();
    assert_eq!(facts.len(), 1);
    let fact = &facts[0];
    assert_eq!(fact.outcome, "completed");
    assert_eq!(fact.request_sha256, sha(&sent.decoded));
    assert_eq!(fact.wire_sha256, sha(&sent.wire));
    assert_ne!(fact.request_sha256, fact.wire_sha256);
    assert_eq!(fact.thread_id, sent.headers["thread-id"].to_str().unwrap());
    assert_eq!(
        fact.turn_id,
        sent.body["client_metadata"]["turn_id"].as_str().unwrap()
    );
    assert_eq!(fact.account_id, "alpha");
    assert_eq!(
        fact.upstream_request_id.as_deref(),
        Some("fixture-request-1")
    );
    assert_eq!(
        fact.upstream_response_id.as_deref(),
        Some("upstream-response-one")
    );
    assert_eq!(fact.usage.as_ref().unwrap(), &end["response"]["usage"]);
    assert_eq!(fact.event_count, 3);
    // The real official parser observes every event before the attempt closes.
    let attempts = fixture.state.ledger.snapshot("alpha").unwrap();
    let hooks = attempts[0]
        .facts
        .iter()
        .filter_map(|row| {
            if let right_codex::telemetry::NetworkFact::HookObservation { source, detail, .. } =
                &row.fact
            {
                (source == "sse_poll").then_some(detail.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(hooks.len(), 3);
    assert!(hooks.iter().any(|v| v.contains("ResponseCompleted")));
}

#[tokio::test]
async fn threads_reuse_their_account_and_auth_reload_replaces_all_upstream_scope() {
    let fixture = Fixture::new(
        (0..4)
            .map(|_| ordinary("repeated-fixture-response-id"))
            .collect(),
    )
    .await;
    for thread in ["client-a", "client-a", "client-b"] {
        let (status, events) = fixture.send(thread, &request_body()).await;
        assert_eq!(status, StatusCode::OK);
        terminal(&events);
    }
    write_auth(
        &fixture.directory.path().join("alpha-auth.json"),
        "alpha",
        "synthetic-access-alpha-revised",
    );
    assert!(fixture.state.accounts.reload_auth("alpha").unwrap());
    let (status, events) = fixture.send("client-a", &request_body()).await;
    assert_eq!(status, StatusCode::OK);
    terminal(&events);
    let sent = fixture.captured();
    assert_eq!(sent.len(), 4);
    assert_eq!(
        sent[0].headers["chatgpt-account-id"],
        sent[1].headers["chatgpt-account-id"]
    );
    assert_eq!(sent[0].headers["thread-id"], sent[1].headers["thread-id"]);
    assert_eq!(sent[0].headers["session-id"], sent[1].headers["session-id"]);
    assert_eq!(
        sent[0].body["prompt_cache_key"],
        sent[1].body["prompt_cache_key"]
    );
    assert_ne!(
        sent[0].body["client_metadata"]["turn_id"],
        sent[1].body["client_metadata"]["turn_id"]
    );
    assert_eq!(
        sent[2].headers["chatgpt-account-id"],
        "fixture-workspace-beta"
    );
    for field in ["thread-id", "session-id"] {
        assert_ne!(sent[0].headers[field], sent[2].headers[field]);
        assert_ne!(sent[0].headers[field], sent[3].headers[field]);
    }
    assert_ne!(
        sent[0].body["prompt_cache_key"],
        sent[2].body["prompt_cache_key"]
    );
    assert_ne!(
        sent[0].body["prompt_cache_key"],
        sent[3].body["prompt_cache_key"]
    );
    assert_eq!(
        sent[3].headers[header::AUTHORIZATION],
        "Bearer synthetic-access-alpha-revised"
    );
    let facts = fixture.state.facts.snapshot();
    assert_eq!(facts.len(), 4);
    assert_eq!(facts[0].auth_revision, facts[1].auth_revision);
    assert_ne!(facts[0].auth_revision, facts[3].auth_revision);
    assert_eq!(facts[0].account_id, "alpha");
    assert_eq!(facts[2].account_id, "beta");
    assert!(facts.iter().all(|fact| fact.outcome == "completed"));
}

#[tokio::test]
async fn function_call_alias_round_trips_without_rewriting_free_json_arguments() {
    let arguments = r#"{"id":"literal-content-id","nested":{"call_id":"literal-content-call","file_id":"literal-content-file"}}"#;
    let call = json!({"type":"function_call","id":"fc_original_upstream","call_id":"call_original_upstream","name":"read","arguments":arguments});
    let fixture = Fixture::new(vec![
        Reply::sse(vec![
            json!({"type":"response.output_item.added","item":call}),
            json!({"type":"response.output_item.done","item":call}),
            completed("response-original-call", json!([call])),
        ]),
        ordinary("response-after-tool"),
    ])
    .await;
    let (_, first) = fixture.send("client-tools", &request_body()).await;
    let aliased = terminal(&first)["response"]["output"][0].clone();
    assert_ne!(aliased["call_id"], "call_original_upstream");
    assert_ne!(aliased["id"], "fc_original_upstream");
    assert_eq!(aliased["arguments"], arguments);
    for event in &first[..2] {
        assert_eq!(event["item"]["call_id"], aliased["call_id"]);
    }
    let output = r#"{"id":"tool-output-content","call_id":"tool-output-literal"}"#;
    let next = json!({"model":"fixture-model","input":[
        {"role":"user","content":"hello"}, aliased.clone(),
        {"type":"function_call_output","id":"CLIENT_OUTPUT_ID","call_id":aliased["call_id"],"output":output,
            "internal_chat_message_metadata_passthrough":{"executed_tool_calls":[{"id":"CLIENT_EXECUTION_CLAIM"}]}}
    ]});
    let (status, second) = fixture.send("client-tools", &next).await;
    assert_eq!(status, StatusCode::OK);
    terminal(&second);
    let sent = fixture.captured();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].body["input"][1]["id"], "fc_original_upstream");
    assert_eq!(
        sent[1].body["input"][1]["call_id"],
        "call_original_upstream"
    );
    assert_eq!(
        sent[1].body["input"][2]["call_id"],
        "call_original_upstream"
    );
    assert_eq!(sent[1].body["input"][1]["arguments"], arguments);
    assert_eq!(sent[1].body["input"][2]["output"], output);
    assert!(
        sent[1].body["input"][2]
            .get("internal_chat_message_metadata_passthrough")
            .is_none()
    );
    assert_ne!(sent[1].body["input"][2]["id"], "CLIENT_OUTPUT_ID");
    assert_eq!(sent[0].headers["thread-id"], sent[1].headers["thread-id"]);
    assert_eq!(fixture.state.facts.snapshot().len(), 2);
}

#[tokio::test]
async fn v2_requires_completed_compaction_and_never_promotes_eof_or_foreign_cipher() {
    let item = json!({"type":"compaction","id":"compact_original","encrypted_content":"scope-owned-compact-cipher"});
    let item_done = json!({"type":"response.output_item.done","item":item});
    let fixture = Fixture::new(vec![
        Reply::sse(vec![
            item_done.clone(),
            completed("compact-response", json!([item.clone()])),
        ]),
        ordinary("after-compaction"),
        Reply::sse(vec![completed("missing-compaction", json!([]))]),
        Reply::sse(vec![item_done]),
    ])
    .await;
    let mut compact = request_body();
    compact["input"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"compaction_trigger"}));
    let (status, success) = fixture.send("compact-owner", &compact).await;
    assert_eq!(status, StatusCode::OK);
    let owned = terminal(&success)["response"]["output"][0].clone();
    let after = json!({"model":"fixture-model","input":[owned.clone(),{"role":"user","content":"continue"}]});
    let (status, after_events) = fixture.send("compact-owner", &after).await;
    assert_eq!(status, StatusCode::OK);
    terminal(&after_events);
    let response = fixture
        .request("foreign-compact-owner", &after)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fixture.captured().len(), 2);
    for (thread, expected_error) in [
        ("missing-compact", "invalid_compaction_response"),
        ("eof-compact", "upstream_stream_incomplete"),
    ] {
        let (status, events) = fixture.send(thread, &compact).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !events
                .iter()
                .any(|event| event["type"] == "response.completed")
        );
        assert_eq!(events.last().unwrap()["error"]["code"], expected_error);
    }
    let response = fixture.request("eof-compact", &after).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let sent = fixture.captured();
    assert_eq!(sent.len(), 4);
    assert_eq!(
        sent[0].body["input"].as_array().unwrap().last().unwrap()["type"],
        "compaction_trigger"
    );
    assert_eq!(
        sent[1].body["input"][0]["encrypted_content"],
        "scope-owned-compact-cipher"
    );
    let facts = fixture.state.facts.snapshot();
    assert_eq!(facts.len(), 4);
    assert_eq!(facts[0].outcome, "completed");
    assert_eq!(facts[2].outcome, "invalid_compaction_response");
    assert_eq!(facts[3].outcome, "stream_incomplete");
    assert_eq!(
        facts[2].upstream_response_id.as_deref(),
        Some("missing-compaction")
    );
    assert!(facts[3].upstream_response_id.is_none());
}

#[tokio::test]
async fn upstream_401_is_a_single_send_and_does_not_refresh_or_rotate_account() {
    let fixture = Fixture::new(vec![
        Reply::http(StatusCode::UNAUTHORIZED),
        ordinary("later-client-request"),
    ])
    .await;
    let response = fixture
        .request("unauthorized-upstream", &request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "synthetic_upstream_rejection");
    assert_eq!(fixture.captured().len(), 1);
    let facts = fixture.state.facts.snapshot();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].status, Some(401));
    assert_eq!(facts[0].outcome, "http_rejected");
    assert_eq!(facts[0].account_id, "alpha");
    assert!(facts[0].upstream_response_id.is_none());
    assert_eq!(facts[0].event_count, 0);
    let snapshot_path = std::fs::read_dir(fixture.state.config.state_dir.join("sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let snapshot: Value = serde_json::from_slice(&std::fs::read(snapshot_path).unwrap()).unwrap();
    assert_eq!(
        snapshot["session"]["attempts"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["state"],
        "failed"
    );
    assert!(
        fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    let (_, events) = fixture.send("unauthorized-upstream", &request_body()).await;
    terminal(&events);
    assert_eq!(
        fixture.captured()[1].headers["chatgpt-account-id"],
        "fixture-workspace-beta"
    );
}

#[tokio::test]
async fn authentication_missing_session_and_unsupported_inputs_never_send_upstream() {
    let fixture = Fixture::new(vec![]).await;
    let bad_key = fixture
        .client
        .post(&fixture.endpoint)
        .header(header::AUTHORIZATION, "Basic invalid")
        .header("thread-id", "invalid-key")
        .json(&request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(bad_key.status(), StatusCode::UNAUTHORIZED);
    let missing = fixture
        .client
        .post(&fixture.endpoint)
        .bearer_auth(CLIENT_KEY)
        .json(&request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    let cases = [
        ("temperature", json!(0.5)),
        ("stream", json!(false)),
        ("previous_response_id", json!("foreign-response-reference")),
        ("conversation", json!("foreign-conversation-reference")),
    ];
    for (field, value) in cases {
        let mut input = request_body();
        input[field] = value;
        let response = fixture.request("unsupported", &input).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            "unsupported_business_request"
        );
    }
    let cipher = json!({"model":"fixture-model","input":[{"type":"compaction","encrypted_content":"unowned-cipher"}]});
    assert_eq!(
        fixture
            .request("unsupported", &cipher)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(fixture.captured().is_empty());
    assert!(fixture.state.facts.snapshot().is_empty());
}

#[tokio::test]
async fn incomplete_is_one_terminal_preserves_usage_releases_lock_and_never_trusts_cipher() {
    let cases = [
        ("interrupted", "interrupted"),
        ("content_filter", "response_incomplete"),
        ("max_output_tokens", "response_incomplete"),
    ];
    let mut replies = Vec::new();
    for (reason, _) in cases {
        let mut incomplete = completed(
            &format!("upstream-incomplete-{reason}"),
            json!([{"type":"compaction","id":"partial-compaction-item","encrypted_content":"not-completed-cipher"}]),
        );
        incomplete["type"] = json!("response.incomplete");
        incomplete["response"]["status"] = json!("incomplete");
        incomplete["response"]["incomplete_details"] = json!({"reason":reason});
        replies.push(Reply::sse(vec![incomplete]));
        replies.push(ordinary(&format!("upstream-next-{reason}")));
    }
    let fixture = Fixture::new(replies).await;
    for (index, (reason, outcome)) in cases.into_iter().enumerate() {
        let thread = format!("incomplete-client-{reason}");
        let (status, events) = fixture.send(&thread, &request_body()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            events.len(),
            1,
            "no synthetic error may follow an actual incomplete terminal"
        );
        assert_eq!(events[0]["type"], "response.incomplete");
        assert_eq!(
            events[0]["response"]["incomplete_details"]["reason"],
            reason
        );
        assert_eq!(
            events[0]["response"]["usage"],
            completed("unused", json!([]))["response"]["usage"]
        );
        assert_ne!(
            events[0]["response"]["id"],
            format!("upstream-incomplete-{reason}")
        );
        let captured_before = fixture.captured().len();
        let partial = events[0]["response"]["output"][0].clone();
        let untrusted =
            json!({"model":"fixture-model","input":[partial,{"role":"user","content":"continue"}]});
        assert_eq!(
            fixture
                .request(&thread, &untrusted)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(fixture.captured().len(), captured_before);
        // This is an immediate request on the same logical conversation, with no sleep/retry.
        let (status, next) = fixture.send(&thread, &request_body()).await;
        assert_eq!(status, StatusCode::OK);
        terminal(&next);
        let facts = fixture.state.facts.snapshot();
        let interrupted = &facts[index * 2];
        assert_eq!(interrupted.outcome, outcome);
        assert_eq!(
            interrupted.upstream_response_id.as_deref(),
            Some(format!("upstream-incomplete-{reason}").as_str())
        );
        assert_eq!(
            interrupted.usage.as_ref().unwrap(),
            &events[0]["response"]["usage"]
        );
        assert_eq!(interrupted.event_count, 1);
        assert_eq!(interrupted.thread_id, facts[index * 2 + 1].thread_id);
        assert_eq!(facts[index * 2 + 1].outcome, "completed");
    }
    assert_eq!(fixture.captured().len(), 6);
    assert_eq!(fixture.state.facts.snapshot().len(), 6);
}

#[tokio::test]
async fn malformed_json_is_authenticated_first_and_rejected_bilingually_without_upstream() {
    let fixture = Fixture::new(vec![]).await;
    for (key, expected) in [
        ("", StatusCode::UNAUTHORIZED),
        (CLIENT_KEY, StatusCode::BAD_REQUEST),
    ] {
        let response = fixture
            .client
            .post(&fixture.endpoint)
            .bearer_auth(key)
            .header("thread-id", "malformed-json-client")
            .header(header::CONTENT_TYPE, "application/json")
            .body("{invalid json")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let error: Value = response.json().await.unwrap();
        let message = error["error"]["message"].as_str().unwrap();
        assert!(message.contains(" / "));
        assert!(message.chars().any(|ch| ch.is_ascii_alphabetic()));
        assert!(
            message
                .chars()
                .any(|ch| ('\u{4e00}'..='\u{9fff}').contains(&ch))
        );
        if expected == StatusCode::UNAUTHORIZED {
            assert_eq!(error["error"]["code"], "oauth_header_required");
        } else {
            assert_eq!(error["error"]["code"], "invalid_request_json");
        }
    }
    assert!(fixture.captured().is_empty());
    assert!(fixture.state.facts.snapshot().is_empty());
}

#[tokio::test]
async fn tool_outputs_need_a_prior_call_and_item_call_string_collision_stays_typed() {
    let fixture = Fixture::new(vec![ordinary("after-adopted-history")]).await;
    let orphan = json!({"model":"fixture-model","input":[
        {"type":"function_call_output","id":"untrusted-output-id","call_id":"not-observed-or-declared","output":"ok"}
    ]});
    let response = fixture
        .request("untrusted-history", &orphan)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "unsupported_business_request"
    );
    assert!(fixture.captured().is_empty());
    assert!(fixture.state.facts.snapshot().is_empty());
    let arguments = r#"{"id":"same-client-string","call_id":"literal-user-content"}"#;
    let declared_call = json!({"type":"function_call","id":"same-client-string","call_id":"same-client-string","name":"read","arguments":arguments});
    let declared_output = json!({"type":"function_call_output","id":"distinct-output-item","call_id":"same-client-string","output":"{\"id\":\"literal-tool-output\"}"});
    let reversed =
        json!({"model":"fixture-model","input":[declared_output.clone(),declared_call.clone()]});
    let response = fixture
        .request("ordered-history", &reversed)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a later declaration is not prior call provenance"
    );
    assert!(fixture.captured().is_empty());
    let history = json!({"model":"fixture-model","input":[{"role":"user","content":"prior history"},declared_call,declared_output]});
    let (status, events) = fixture.send("adopted-complete-history", &history).await;
    assert_eq!(status, StatusCode::OK);
    terminal(&events);
    let captured = fixture.captured();
    assert_eq!(captured.len(), 1);
    let call = &captured[0].body["input"][1];
    let output = &captured[0].body["input"][2];
    assert_ne!(call["id"], call["call_id"]);
    assert_ne!(call["id"], "same-client-string");
    assert_ne!(call["call_id"], "same-client-string");
    assert_eq!(call["call_id"], output["call_id"]);
    assert_eq!(call["arguments"], arguments);
    assert_eq!(output["output"], "{\"id\":\"literal-tool-output\"}");
    assert_eq!(fixture.state.facts.snapshot().len(), 1);
}

#[tokio::test]
async fn fragmented_429_is_returned_once_and_only_a_new_request_selects_beta() {
    let fixture = Fixture::new(vec![
        Reply::http(StatusCode::TOO_MANY_REQUESTS),
        ordinary("beta-later"),
    ])
    .await;
    let response = fixture
        .request("quota-thread", &request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "3");
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "synthetic_upstream_rejection"
    );
    assert_eq!(fixture.captured().len(), 1);
    assert!(
        fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown
    );
    let (_, events) = fixture.send("quota-thread", &request_body()).await;
    terminal(&events);
    let sent = fixture.captured();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[1].headers["chatgpt-account-id"],
        "fixture-workspace-beta"
    );
    for field in ["thread-id", "session-id"] {
        assert_ne!(sent[0].headers[field], sent[1].headers[field]);
    }
    assert_ne!(
        sent[0].body["prompt_cache_key"],
        sent[1].body["prompt_cache_key"]
    );
}

#[tokio::test]
async fn partial_text_then_quota_is_forwarded_and_stops_without_continuation() {
    let quota = json!({"type":"error","error":{"code":"usage_limit_reached","message":"quota original", "resets_in_seconds":120}});
    let first = Reply::sse(vec![
        json!({"type":"response.created","response":{"id":"alpha-response","status":"in_progress"}}),
        json!({"type":"response.output_text.delta","response_id":"alpha-response","item_id":"alpha-item","output_index":0,"content_index":0,"delta":"observed partial text"}),
        quota.clone(),
        completed("must-not-deliver", json!([])),
    ]);
    let fixture = Fixture::new(vec![first]).await;
    let (status, events) = fixture.send("partial-quota", &request_body()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(events.last().unwrap(), &quota);
    assert_eq!(events.len(), 3);
    assert_eq!(events[1]["delta"], "observed partial text");
    assert_eq!(fixture.captured().len(), 1);
    assert!(
        fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown
    );
    assert_eq!(fixture.state.facts.snapshot()[0].outcome, "response_failed");
}

#[tokio::test]
async fn stream_errors_never_replay_even_after_tools_and_failed_without_response_id() {
    for failure in [
        json!({"type":"error","status":401,"error":{"code":"unauthorized","message":"expired"}}),
        json!({"type":"error","status":500,"error":{"code":"internal_error","message":"original server error"}}),
        json!({"type":"error","error":{"code":"unmapped_error","message":"original unknown error"}}),
        json!({"type":"response.failed","response":{"error":{"code":"invalid_prompt","message":"original failed"}}}),
    ] {
        let reply = Reply::sse(vec![
            json!({"type":"response.output_item.done","item":{"type":"function_call","id":"actual-tool","call_id":"actual-call","name":"shell","arguments":"{}"}}),
            failure.clone(),
        ]);
        let fixture = Fixture::new(vec![reply]).await;
        let (_, events) = fixture.send("source-error", &request_body()).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events.last().unwrap(), &failure);
        assert_ne!(events[0]["item"]["call_id"], "actual-call");
        assert_eq!(fixture.captured().len(), 1);
        let availability = fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap();
        assert_eq!(availability.auth_invalid, failure["status"] == 401);
        assert!(!availability.quota_cooldown);
    }
}

#[tokio::test]
async fn restart_restores_owned_cipher_and_response_without_reusing_external_ids() {
    let cipher = json!({"type":"reasoning","id":"reasoning-owned","summary":[],"encrypted_content":"owned-only"});
    let fixture = Fixture::new(vec![
        Reply::sse(vec![completed("persisted-response", json!([cipher]))]),
        ordinary("resumed-response"),
    ])
    .await;
    let (_, events) = fixture.send("durable-native-thread", &request_body()).await;
    let output = terminal(&events)["response"]["output"].clone();
    let config = fixture.state.config.clone();
    let restored = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            router(restored).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let response = fixture
        .client
        .post(format!("http://{addr}/v1/responses"))
        .bearer_auth(CLIENT_KEY)
        .header("thread-id", "durable-native-thread")
        .json(&json!({"model":"fixture-model","input":output}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("response.completed")
    );
    let sent = fixture.captured();
    assert_eq!(sent[1].body["input"][0]["encrypted_content"], "owned-only");
    assert_eq!(sent[0].headers["thread-id"], sent[1].headers["thread-id"]);
    handle.abort();
}

#[tokio::test]
async fn error_controls_describe_the_rejected_account_without_hidden_second_attempt() {
    let fixture = Fixture::new(vec![Reply::http(StatusCode::TOO_MANY_REQUESTS)]).await;
    let response = fixture
        .request("control-error", &request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["openai-model"], "fixture-model-1");
    assert_eq!(response.headers()["x-models-etag"], "fixture-catalog");
    assert_eq!(response.headers()["retry-after"], "3");
    for name in ["x-request-id", "cf-ray", "x-codex-turn-state"] {
        assert!(!response.headers().contains_key(name));
    }
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "synthetic_upstream_rejection"
    );
    assert_eq!(fixture.captured().len(), 1);
}

#[tokio::test]
async fn http_rejection_keeps_controls_but_strips_structured_nested_identity() {
    let mut reply = Reply::http(StatusCode::BAD_REQUEST);
    let message = "ordinary text keeps request_id=private-previous-account";
    reply.body = json!({"request_id":"private-top","error":{"code":"bad_request","message":message,
        "response_id":"private-response","request_id":"private-request","headers":{"cf-ray":"private-ray","openai-model":"business-model"},
        "response":{"id":"private-nested-response","error":{"account_id":"private-account","message":message}}}}).to_string().into_bytes();
    let fixture = Fixture::new(vec![reply]).await;
    let response = fixture
        .request("error-projection", &request_body())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["retry-after"], "3");
    assert_eq!(response.headers()["openai-model"], "fixture-model-1");
    assert!(!response.headers().contains_key("x-request-id"));
    let body: Value = response.json().await.unwrap();
    assert!(body.get("request_id").is_none());
    assert!(body["error"].get("response_id").is_none());
    assert!(body["error"]["response"].get("id").is_none());
    assert!(body["error"]["headers"].get("cf-ray").is_none());
    assert_eq!(body["error"]["headers"]["openai-model"], "business-model");
    assert_eq!(body["error"]["message"], message);
}

#[tokio::test]
async fn raw_http_errors_and_429_without_reset_preserve_body_and_do_not_cool_down() {
    for (status, body, content_type) in [
        (
            StatusCode::TOO_MANY_REQUESTS,
            b"{ \"error\": {\"code\":\"rate_limit_exceeded\", \"message\":\"no reset\"} }".to_vec(),
            "application/json",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            b"<html>original error</html>".to_vec(),
            "text/html",
        ),
        (
            StatusCode::BAD_GATEWAY,
            vec![0xff, 0xfe, 0x00, 0x80],
            "application/octet-stream",
        ),
        (StatusCode::CONFLICT, vec![], "text/plain"),
    ] {
        let mut reply = Reply::http(status);
        reply.body = body.clone();
        reply.content_type = content_type;
        reply.retry_after = None;
        let fixture = Fixture::new(vec![reply]).await;
        let response = fixture
            .request("raw-error", &request_body())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
        assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_slice());
        assert_eq!(fixture.captured().len(), 1);
        let availability = fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap();
        assert!(!availability.quota_cooldown);
        assert!(!availability.auth_invalid);
    }
}

#[tokio::test]
async fn sse_401_is_not_replaced_when_account_state_cannot_be_persisted() {
    let failure = json!({"type":"error","status":401,"error":{"code":"expired","message":"original source error"}});
    let fixture = Fixture::new(vec![Reply::sse(vec![failure.clone()])]).await;
    // A directory at the atomic file's target forces publication to fail.
    std::fs::create_dir(
        fixture
            .state
            .config
            .state_dir
            .join("accounts/alpha/admission.json"),
    )
    .unwrap();
    let (_, events) = fixture.send("401-storage-failure", &request_body()).await;
    assert_eq!(events, vec![failure]);
    assert_eq!(fixture.captured().len(), 1);
    assert!(fixture.state.accounts.by_id("alpha").unwrap().is_none());
    assert!(
        fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
}
