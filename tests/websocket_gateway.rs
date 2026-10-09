//! Synthetic OAuth loopback: actual WebSocket sockets, no client processes or external account.
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, StatusCode, header};
use right_codex::{
    accounts::AccountPool,
    config::{AccountConfig, GatewayConfig},
    gateway::{AppState, router},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message as ClientMessage, client::IntoClientRequest},
};

enum Reply {
    Events(Vec<Value>),
    EventsThenSidebands(Vec<Value>, Vec<Value>),
    Interrupt,
    Hold,
    IdleError(Value),
    DelayedError(Value),
}
struct RawRejection {
    chunks: Vec<Vec<u8>>,
    length: Option<usize>,
    truncate: bool,
}
struct Upstream {
    handshakes: Mutex<Vec<HeaderMap>>,
    rejects: Mutex<VecDeque<StatusCode>>,
    raw_rejection: Mutex<Option<RawRejection>>,
    requests: Mutex<Vec<Value>>,
    interrupts: Mutex<Vec<Value>>,
    replies: Mutex<VecDeque<Reply>>,
}
async fn endpoint(
    State(state): State<Arc<Upstream>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    state.handshakes.lock().unwrap().push(headers);
    let raw_rejection = state.raw_rejection.lock().unwrap().take();
    if let Some(rejection) = raw_rejection {
        let stream = async_stream::stream! {
            for chunk in rejection.chunks {
                tokio::time::sleep(Duration::from_millis(20)).await;
                yield Ok::<_, std::io::Error>(bytes::Bytes::from(chunk));
            }
            if rejection.truncate {
                tokio::time::sleep(Duration::from_millis(20)).await;
                yield Err(std::io::Error::other("source truncated"));
            }
        };
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            axum::body::Body::from_stream(stream),
        )
            .into_response();
        response
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        if let Some(length) = rejection.length {
            response
                .headers_mut()
                .insert("content-length", length.to_string().parse().unwrap());
        }
        return response;
    }
    let reject = state.rejects.lock().unwrap().pop_front();
    if let Some(status) = reject {
        let mut response = match status {
            StatusCode::BAD_GATEWAY => (status, axum::Json(json!(["non-object-error"]))).into_response(),
            StatusCode::UNAUTHORIZED => (status, axum::Json(json!({"error":{"code":"token_expired","message":"Actual upstream rejection","param":"literal-field"}}))).into_response(),
            StatusCode::TOO_MANY_REQUESTS => (status, axum::Json(json!({"error":{"code":"usage_limit_reached","message":"Actual upstream quota","plan_type":"pro"}}))).into_response(),
            StatusCode::SERVICE_UNAVAILABLE => (status, "literal upstream plain text").into_response(),
            StatusCode::UPGRADE_REQUIRED => (status, "actual HTTP fallback response").into_response(),
            _ => status.into_response(),
        };
        response
            .headers_mut()
            .insert("retry-after", "7".parse().unwrap());
        response
            .headers_mut()
            .insert("x-request-id", "private-rejected-request".parse().unwrap());
        return response;
    }
    let mut response = ws.on_upgrade(move |socket| upstream(state, socket));
    for (name, value) in [
        ("openai-model", "fixture-server-model"),
        ("x-reasoning-included", "false"),
        ("x-models-etag", "fixture-catalog"),
        ("x-request-id", "fixture-private-request"),
        ("cf-ray", "fixture-private-ray"),
        ("x-codex-turn-state", "fixture-private-sticky"),
    ] {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
async fn upstream(state: Arc<Upstream>, mut socket: WebSocket) {
    while let Some(Ok(Message::Text(text))) = socket.next().await {
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["type"], "response.create");
        state.requests.lock().unwrap().push(value);
        let reply = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("one reply per actual native request");
        match reply {
            Reply::Events(events) => {
                for value in events {
                    if socket
                        .send(Message::Text(value.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Reply::EventsThenSidebands(events, sidebands) => {
                for value in events {
                    if socket
                        .send(Message::Text(value.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                for value in sidebands {
                    if socket
                        .send(Message::Text(value.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Reply::Interrupt => {
                socket.send(Message::Text(json!({"type":"response.created","response":{"id":"actual-interrupted","status":"in_progress"}}).to_string().into())).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    if let Message::Text(text) = message {
                        let value: Value = serde_json::from_str(&text).unwrap();
                        state.interrupts.lock().unwrap().push(value.clone());
                        if value["type"] == "response.interrupt" {
                            socket.send(Message::Text(json!({"type":"response.incomplete","response":{"id":"actual-interrupted","status":"incomplete","output":[],"incomplete_details":{"reason":"interrupted"}}}).to_string().into())).await.unwrap();
                            break;
                        }
                    }
                }
            }
            Reply::DelayedError(error) => {
                socket.send(Message::Text(json!({"type":"response.created","response":{"id":"before-error","status":"in_progress"}}).to_string().into())).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                socket
                    .send(Message::Text(error.to_string().into()))
                    .await
                    .unwrap();
            }
            Reply::IdleError(error) => {
                for value in events("completed-before-idle", json!([])) {
                    socket
                        .send(Message::Text(value.to_string().into()))
                        .await
                        .unwrap();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                socket
                    .send(Message::Text(error.to_string().into()))
                    .await
                    .unwrap();
            }
            Reply::Hold => {
                while socket.next().await.is_some() {}
                return;
            }
        }
    }
}
type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Fixture {
    directory: TempDir,
    state: Arc<AppState>,
    upstream: Arc<Upstream>,
    url: String,
    servers: Vec<JoinHandle<()>>,
}
impl Fixture {
    async fn new(replies: Vec<Reply>, rejects: Vec<StatusCode>) -> Self {
        Self::with_accounts(replies, rejects, &["alpha", "beta"]).await
    }
    async fn with_accounts(
        replies: Vec<Reply>,
        rejects: Vec<StatusCode>,
        account_names: &[&str],
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let upstream = Arc::new(Upstream {
            handshakes: Mutex::new(Vec::new()),
            rejects: Mutex::new(rejects.into()),
            raw_rejection: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            interrupts: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/backend-api/codex/responses", get(endpoint))
            .with_state(upstream.clone());
        let first = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let accounts=account_names.iter().copied().map(|id|{
            let path=directory.path().join(format!("{id}-auth.json"));
            // Local official auth-file parsing requires a JWT envelope; this
            // fictional token is never sent to an external authentication service.
            std::fs::write(&path,json!({"auth_mode":"chatgpt","tokens":{"id_token":"eyJhbGciOiJub25lIn0.e30.signature","access_token":format!("synthetic-access-{id}"),"refresh_token":format!("synthetic-refresh-{id}"),"account_id":format!("workspace-{id}")},"last_refresh":"2026-10-10T00:00:00Z"}).to_string()).unwrap();
            AccountConfig{id:id.into(),auth_path:path,proxy:None,enabled:true}
        }).collect();
        let config = GatewayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            base_url: format!("http://{address}/backend-api/codex"),
            allow_insecure_http: true,
            accounts,
            state_dir: directory.path().join("state"),
            oauth_issuer: format!("http://{address}"),
            queue_timeout_secs: 2,
            request_timeout_secs: 5,
            scheduling: right_codex::config::SchedulingConfig {
                max_sessions_by_account_age: [128; 5],
                startup_spacing_secs: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
        let listener = TcpListener::bind(config.listen).await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = router(state.clone());
        let second = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            directory,
            state,
            upstream,
            url: format!("ws://{address}/v1/responses"),
            servers: vec![first, second],
        }
    }
    async fn client(&self, thread: &str) -> Client {
        tokio_tungstenite::connect_async(self.client_request(thread))
            .await
            .unwrap()
            .0
    }
    fn client_request(&self, thread: &str) -> http::Request<()> {
        let mut request = self.url.as_str().into_client_request().unwrap();
        for (name, value) in [
            ("authorization", "Bearer SYNTHETIC_CLIENT_OAUTH"),
            ("chatgpt-account-id", "CLIENT_WORKSPACE"),
            ("thread-id", thread),
            ("originator", "CLIENT_ORIGINATOR"),
            ("user-agent", "CLIENT_UA"),
        ] {
            request.headers_mut().insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        request
    }
    fn requests(&self) -> Vec<Value> {
        self.upstream.requests.lock().unwrap().clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}
fn create(input: Value) -> Value {
    json!({"type":"response.create","model":"fixture-model","stream":true,"input":input})
}
fn events(id: &str, output: Value) -> Vec<Value> {
    let mut events =
        vec![json!({"type":"response.created","response":{"id":id,"status":"in_progress"}})];
    for item in output.as_array().unwrap() {
        events.push(json!({"type":"response.output_item.done","response_id":id,"item":item}));
    }
    events.push(json!({"type":"response.completed","response":{"id":id,"status":"completed","output":output}}));
    events
}
fn ordinary(id: &str) -> Reply {
    Reply::Events(events(
        id,
        json!([{"type":"message","id":format!("message-{id}"),"role":"assistant","content":[{"type":"output_text","text":"hello","annotations":[]}]}]),
    ))
}
async fn send(client: &mut Client, value: Value) {
    client
        .send(ClientMessage::Text(value.to_string().into()))
        .await
        .unwrap();
}
async fn next(client: &mut Client) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            ClientMessage::Text(text) => return serde_json::from_str(&text).unwrap(),
            ClientMessage::Ping(data) => client.send(ClientMessage::Pong(data)).await.unwrap(),
            other => panic!("unexpected fixture message {other:?}"),
        }
    }
}
async fn terminal(client: &mut Client) -> Vec<Value> {
    let mut out = vec![];
    loop {
        let event = next(client).await;
        let done = matches!(
            event["type"].as_str(),
            Some("response.completed" | "response.incomplete" | "response.failed" | "error")
        );
        out.push(event);
        if done {
            return out;
        }
    }
}

#[tokio::test]
async fn two_turns_reuse_actual_socket_and_function_call_provenance() {
    let args = r#"{"id":"literal-free-json","call_id":"literal-call"}"#;
    let call = json!({"type":"function_call","id":"actual-item","call_id":"actual-call","name":"read","arguments":args});
    let fixture = Fixture::new(
        vec![
            Reply::Events(events("actual-first", json!([call]))),
            ordinary("actual-second"),
        ],
        vec![],
    )
    .await;
    let mut client = fixture.client("CLIENT_THREAD").await;
    let input = create(json!([{"role":"user","content":"hello","id":"CLIENT_INPUT"}]));
    send(&mut client, input.clone()).await;
    let first = terminal(&mut client).await;
    let mapped = &first
        .iter()
        .find(|e| e["type"] == "response.output_item.done")
        .unwrap()["item"];
    assert_ne!(mapped["call_id"], "actual-call");
    assert_eq!(mapped["arguments"], args);
    let follow = create(
        json!([{"role":"user","content":"hello"},mapped.clone(),{"type":"function_call_output","id":"CLIENT_OUTPUT","call_id":mapped["call_id"],"output":"done"}]),
    );
    send(&mut client, follow).await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1]["input"][1]["call_id"], "actual-call");
    assert_eq!(requests[1]["input"][2]["call_id"], "actual-call");
    let handshake = fixture.upstream.handshakes.lock().unwrap();
    assert_eq!(handshake.len(), 1);
    assert_eq!(
        handshake[0][header::AUTHORIZATION],
        "Bearer synthetic-access-alpha"
    );
    assert_eq!(handshake[0]["chatgpt-account-id"], "workspace-alpha");
    assert_ne!(handshake[0]["originator"], "CLIENT_ORIGINATOR");
    assert_ne!(handshake[0][header::USER_AGENT], "CLIENT_UA");
    let serialized = serde_json::to_string(&requests).unwrap();
    for forbidden in [
        "CLIENT_THREAD",
        "CLIENT_INPUT",
        "CLIENT_OUTPUT",
        "CLIENT_WORKSPACE",
        "SYNTHETIC_CLIENT_OAUTH",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    assert_eq!(
        requests[0]["client_metadata"]["thread_id"],
        requests[1]["client_metadata"]["thread_id"]
    );
    assert_ne!(
        requests[0]["client_metadata"]["turn_id"],
        requests[1]["client_metadata"]["turn_id"]
    );
}

#[tokio::test]
async fn empty_completed_output_keeps_custom_call_in_native_incremental_continuation() {
    let call = json!({"type":"custom_tool_call","id":"ctc_actual","call_id":"call_actual","name":"execute","input":"literal id field"});
    let mut first_events = events("actual-call-response", json!([call]));
    first_events.last_mut().unwrap()["response"]["output"] = json!([]);
    let fixture = Fixture::new(
        vec![Reply::Events(first_events), ordinary("actual-tool-follow")],
        vec![],
    )
    .await;
    let mut client = fixture.client("custom-delta-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"run"}])),
    )
    .await;
    let first = terminal(&mut client).await;
    assert_eq!(first.last().unwrap()["response"]["output"], json!([]));
    let call = first
        .iter()
        .find(|event| event["type"] == "response.output_item.done")
        .unwrap()["item"]
        .clone();
    let mut follow = create(
        json!([{"type":"custom_tool_call_output","call_id":call["call_id"],"output":"actual client result"}]),
    );
    follow["previous_response_id"] = first.last().unwrap()["response"]["id"].clone();
    send(&mut client, follow).await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].get("previous_response_id").is_none());
    assert_eq!(requests[1]["input"][1]["type"], "custom_tool_call");
    assert_eq!(requests[1]["input"][1]["id"], "ctc_actual");
    assert_eq!(requests[1]["input"][1]["call_id"], "call_actual");
    assert_eq!(requests[1]["input"][1]["input"], "literal id field");
    assert_eq!(requests[1]["input"][2]["type"], "custom_tool_call_output");
    assert_eq!(requests[1]["input"][2]["call_id"], "call_actual");
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn prewarm_and_incremental_local_response_expand_without_foreign_previous_id() {
    let fixture = Fixture::new(
        vec![
            Reply::Events(events("actual-warm", json!([]))),
            ordinary("actual-warm-follow"),
        ],
        vec![],
    )
    .await;
    let mut client = fixture.client("warm-thread").await;
    let mut warm = create(json!([{"role":"user","content":"prewarm"}]));
    warm["generate"] = json!(false);
    send(&mut client, warm).await;
    let first = terminal(&mut client).await;
    let alias = first.last().unwrap()["response"]["id"].clone();
    let mut delta = create(json!([{"role":"user","content":"follow"}]));
    delta["previous_response_id"] = alias;
    send(&mut client, delta).await;
    terminal(&mut client).await;
    let requests = fixture.requests();
    assert_eq!(requests[0]["generate"], false);
    assert!(requests[1].get("previous_response_id").is_none());
    assert_eq!(requests[1]["input"].as_array().unwrap().len(), 2);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn current_response_interrupt_maps_only_the_real_created_response_and_keeps_next_turn() {
    let fixture = Fixture::new(vec![Reply::Interrupt, ordinary("after-interrupt")], vec![]).await;
    let mut client = fixture.client("interrupt-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    let created = next(&mut client).await;
    assert_eq!(created["type"], "response.created");
    send(
        &mut client,
        json!({"type":"response.interrupt","response_id":"foreign","mode":"discard_partial_items"}),
    )
    .await;
    assert_eq!(
        next(&mut client).await["error"]["code"],
        "foreign_response_interrupt"
    );
    send(&mut client,json!({"type":"response.interrupt","response_id":created["response"]["id"],"mode":"discard_partial_items"})).await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.incomplete"
    );
    assert_eq!(
        fixture.upstream.interrupts.lock().unwrap().as_slice(),
        &[
            json!({"type":"response.interrupt","response_id":"actual-interrupted","mode":"discard_partial_items"})
        ]
    );
    send(
        &mut client,
        create(json!([{"role":"user","content":"continue"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn observed_429_handshake_is_returned_once_and_next_connection_selects_other_account() {
    let fixture = Fixture::new(
        vec![ordinary("after-quota")],
        vec![StatusCode::TOO_MANY_REQUESTS],
    )
    .await;
    let rejected =
        rejected_handshake(&fixture, "quota-thread", StatusCode::TOO_MANY_REQUESTS).await;
    assert_eq!(rejected.headers()["retry-after"], "7");
    assert!(!rejected.headers().contains_key("x-request-id"));
    assert_eq!(
        serde_json::from_slice::<Value>(rejected.body().as_ref().unwrap()).unwrap(),
        json!({"error":{"code":"usage_limit_reached","message":"Actual upstream quota","plan_type":"pro"}})
    );
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    assert!(fixture.requests().is_empty());
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
    let mut client = fixture.client("quota-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    let handshakes = fixture.upstream.handshakes.lock().unwrap();
    assert_eq!(handshakes.len(), 2);
    assert_eq!(
        handshakes[0][header::AUTHORIZATION],
        "Bearer synthetic-access-alpha"
    );
    assert_eq!(
        handshakes[1][header::AUTHORIZATION],
        "Bearer synthetic-access-beta"
    );
    assert_ne!(handshakes[0]["thread-id"], handshakes[1]["thread-id"]);
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn every_426_handshake_keeps_actual_body_and_does_not_cache_a_synthetic_rejection() {
    let fixture = Fixture::with_accounts(
        vec![],
        vec![StatusCode::UPGRADE_REQUIRED, StatusCode::UPGRADE_REQUIRED],
        &["alpha"],
    )
    .await;
    for _ in 0..2 {
        let response =
            rejected_handshake(&fixture, "native-fallback", StatusCode::UPGRADE_REQUIRED).await;
        assert_eq!(
            response.body().as_ref().unwrap(),
            b"actual HTTP fallback response"
        );
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
    }
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 2);
    assert!(fixture.requests().is_empty());
    assert!(
        tokio_tungstenite::connect_async(fixture.client_request("native-fallback"))
            .await
            .is_ok()
    );
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn account_change_after_101_rejects_pending_frame_without_sending_to_another_account() {
    let fixture = Fixture::new(vec![], vec![]).await;
    let mut client = fixture.client("changed-after-101").await;
    fixture.state.accounts.set_enabled("alpha", false).unwrap();
    send(
        &mut client,
        create(json!([{"role":"user","content":"pending"}])),
    )
    .await;
    let rejected = next(&mut client).await;
    assert_eq!(rejected["error"]["code"], "websocket_account_changed");
    assert_eq!(rejected["status"], 503);
    expect_closed(&mut client).await;
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    assert!(fixture.requests().is_empty());
}

#[tokio::test]
async fn handshake_401_is_returned_once_then_disables_only_the_rejected_account() {
    let fixture = Fixture::new(
        vec![ordinary("new-request")],
        vec![StatusCode::UNAUTHORIZED],
    )
    .await;
    let rejected = rejected_handshake(&fixture, "expired-oauth", StatusCode::UNAUTHORIZED).await;
    assert_eq!(
        serde_json::from_slice::<Value>(rejected.body().as_ref().unwrap()).unwrap(),
        json!({"error":{"code":"token_expired","message":"Actual upstream rejection","param":"literal-field"}})
    );
    assert!(
        !fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .enabled
    );
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    assert!(fixture.requests().is_empty());
    let mut client = fixture.client("expired-oauth").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"explicit new request"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(
        fixture.upstream.handshakes.lock().unwrap()[1][header::AUTHORIZATION],
        "Bearer synthetic-access-beta"
    );
}

#[tokio::test]
async fn midstream_quota_keeps_partial_text_and_error_and_switches_only_on_next_connection() {
    let error = json!({"type":"error","status":429,"error":{"code":"usage_limit_reached","message":"quota with actual reset","resets_at":4102444800_u64,"plan_type":"pro"},"headers":{"retry-after":"120","x-request-id":"private-429"}});
    let fixture = Fixture::new(vec![Reply::Events(vec![
        json!({"type":"response.created","response":{"id":"alpha-response","status":"in_progress"}}),
        json!({"type":"response.output_text.delta","response_id":"alpha-response","item_id":"alpha-item","delta":"visible partial"}),
        error.clone(),
    ]), ordinary("beta-response")], vec![]).await;
    let mut client = fixture.client("midstream-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    let delivered = terminal(&mut client).await;
    assert!(delivered.iter().any(|e| e["delta"] == "visible partial"));
    assert_eq!(delivered.last().unwrap()["error"], error["error"]);
    assert_eq!(delivered.last().unwrap()["status"], 429);
    assert_eq!(delivered.last().unwrap()["headers"]["retry-after"], "120");
    assert!(
        delivered.last().unwrap()["headers"]
            .get("x-request-id")
            .is_none()
    );
    expect_closed(&mut client).await;
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
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
    let mut next_client = fixture.client("midstream-thread").await;
    send(
        &mut next_client,
        create(json!([{"role":"user","content":"explicit next request"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut next_client).await.last().unwrap()["type"],
        "response.completed"
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert!(!requests[1].to_string().contains("visible partial"));
    assert!(!requests[1].to_string().contains("alpha-response"));
    assert!(!requests[1].to_string().contains("alpha-item"));
    for field in [
        "thread_id",
        "session_id",
        "turn_id",
        "x-codex-installation-id",
        "x-codex-window-id",
    ] {
        assert_ne!(
            requests[0]["client_metadata"][field],
            requests[1]["client_metadata"][field]
        );
    }
}

#[tokio::test]
async fn client_socket_cancel_persists_unknown_and_does_not_replay() {
    let fixture = Fixture::new(vec![Reply::Hold], vec![]).await;
    let mut client = fixture.client("cancel-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    for _ in 0..40 {
        if !fixture.requests().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    client.close(None).await.unwrap();
    for _ in 0..40 {
        if !fixture.state.facts.snapshot().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(fixture.requests().len(), 1);
    let files = std::fs::read_dir(fixture.directory.path().join("state/sessions")).unwrap();
    let mut sending = 0;
    for file in files {
        let path = file.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            sending += v["session"]["attempts"]
                .as_object()
                .unwrap()
                .values()
                .filter(|a| a["state"] == "unknown")
                .count();
        }
    }
    assert_eq!(sending, 1);
}

#[tokio::test]
async fn late_metadata_and_rate_limits_have_connection_source_and_never_next_attempt() {
    let sidebands = vec![
        json!({"type":"codex.response.metadata","model_version":"fixture-model-version"}),
        json!({"type":"codex.rate_limits","rate_limits":{"remaining":7}}),
    ];
    let fixture = Fixture::new(
        vec![
            Reply::EventsThenSidebands(events("first", json!([])), sidebands.clone()),
            ordinary("second"),
        ],
        vec![],
    )
    .await;
    let mut client = fixture.client("late-thread").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    terminal(&mut client).await;
    assert_eq!(next(&mut client).await, sidebands[0]);
    assert_eq!(next(&mut client).await, sidebands[1]);
    send(
        &mut client,
        create(json!([{"role":"user","content":"second"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    let mut receipts = vec![];
    for entry in std::fs::read_dir(fixture.directory.path().join("state/sessions")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|v| v == "json") {
            let file: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            receipts.extend(
                file["session"]["connection_sidebands"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .cloned(),
            );
            for attempt in file["session"]["attempts"].as_object().unwrap().values() {
                assert!(
                    !attempt["delivered_events"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| matches!(
                            v["type"].as_str(),
                            Some("codex.rate_limits" | "codex.response.metadata")
                        ))
                );
            }
        }
    }
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["frame_index"], 1);
    assert_eq!(receipts[1]["frame_index"], 2);
    assert_eq!(receipts[0]["connection_id"], receipts[1]["connection_id"]);
    assert!(
        receipts
            .iter()
            .all(|v| v["client_socket_written"] == true && v.get("attempt_id").is_none())
    );
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn partial_tool_then_429_without_reset_has_no_replay_and_no_invented_cooldown() {
    let tool = json!({"type":"function_call","id":"alpha-tool","call_id":"alpha-call","name":"shell","arguments":"{\"text\":\"literal-id\"}"});
    let error = json!({"type":"error","status":429,"error":{"code":"usage_limit_reached","message":"reset time absent"}});
    let fixture = Fixture::with_accounts(
        vec![
            Reply::Events(vec![
                json!({"type":"response.created","response":{"id":"alpha","status":"in_progress"}}),
                json!({"type":"response.output_item.done","response_id":"alpha","item":tool}),
                error.clone(),
            ]),
            ordinary("independent"),
        ],
        vec![],
        &["alpha"],
    )
    .await;
    let mut client = fixture.client("partial-tool").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    let delivered = terminal(&mut client).await;
    assert_eq!(delivered.last().unwrap(), &error);
    assert_eq!(
        delivered
            .iter()
            .filter(|e| e["type"] == "response.output_item.done")
            .count(),
        1
    );
    assert_ne!(delivered[1]["item"]["call_id"], "alpha-call");
    expect_closed(&mut client).await;
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    let status = fixture
        .state
        .accounts
        .managed("alpha")
        .unwrap()
        .unwrap()
        .availability()
        .unwrap();
    assert!(status.enabled);
    assert!(!status.quota_cooldown);
    let mut next_client = fixture.client("partial-tool").await;
    send(
        &mut next_client,
        create(json!([{"role":"user","content":"new input"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut next_client).await.last().unwrap()["type"],
        "response.completed"
    );
    assert_eq!(fixture.requests().len(), 2);
}

#[tokio::test]
async fn orphan_tool_output_and_foreign_previous_response_never_send_model_request() {
    let fixture = Fixture::new(vec![ordinary("valid")], vec![]).await;
    let mut client = fixture.client("invalid-history-thread").await;
    send(
        &mut client,
        create(json!([{"type":"function_call_output","call_id":"foreign-call","output":"done"}])),
    )
    .await;
    assert_eq!(next(&mut client).await["status"], 400);
    let mut foreign = create(json!([{"role":"user","content":"hello"}]));
    foreign["previous_response_id"] = json!("foreign-response");
    send(&mut client, foreign).await;
    assert_eq!(next(&mut client).await["status"], 400);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    assert!(fixture.requests().is_empty());
    send(
        &mut client,
        create(json!([{"role":"user","content":"valid"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    assert_eq!(fixture.requests().len(), 1);
}

#[tokio::test]
async fn child_cipher_uses_actual_delivered_busy_parent_scope_before_preflight() {
    let call = json!({"type":"function_call","id":"fc_parent","call_id":"call_parent","namespace":"collaboration","name":"spawn_agent",
        "arguments":json!({"task_name":"child","message":"actual-parent-cipher"}).to_string()});
    let fixture=Fixture::with_accounts(vec![Reply::Events(vec![
        json!({"type":"response.created","response":{"id":"actual-parent","status":"in_progress"}}),
        json!({"type":"response.output_item.done","response_id":"actual-parent","item":call})
    ]),ordinary("actual-child")],vec![],&["alpha"]).await;
    let mut parent = fixture.client("local-parent").await;
    send(
        &mut parent,
        create(json!([{"role":"user","content":"spawn child"}])),
    )
    .await;
    assert_eq!(next(&mut parent).await["type"], "response.created");
    assert_eq!(next(&mut parent).await["type"], "response.output_item.done");
    let mut handshake = fixture.url.as_str().into_client_request().unwrap();
    for (name, value) in [
        ("authorization", "Bearer SYNTHETIC_CLIENT_OAUTH"),
        ("chatgpt-account-id", "CLIENT_WORKSPACE"),
        ("thread-id", "local-child"),
        ("x-openai-subagent", "thread_spawn"),
    ] {
        handshake.headers_mut().insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    let mut child = tokio_tungstenite::connect_async(handshake).await.unwrap().0;
    let mut input = create(
        json!([{"type":"agent_message","id":"amsg_local","author":"root","recipient":"root/child",
        "content":[{"type":"input_text","text":"Message Type: NEW_TASK"},{"type":"encrypted_content","encrypted_content":"actual-parent-cipher"}]}]),
    );
    input["client_metadata"] = json!({"x-codex-turn-metadata":json!({"request_kind":"turn","thread_id":"local-child","parent_thread_id":"local-parent"}).to_string()});
    send(&mut child, input.clone()).await;
    assert_eq!(
        terminal(&mut child).await.last().unwrap()["type"],
        "response.completed"
    );
    let requests = fixture.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1]["input"][0]["content"][1]["encrypted_content"],
        "actual-parent-cipher"
    );
    let parent_meta: Value = serde_json::from_str(
        requests[0]["client_metadata"]["x-codex-turn-metadata"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let child_meta: Value = serde_json::from_str(
        requests[1]["client_metadata"]["x-codex-turn-metadata"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(child_meta["parent_thread_id"], parent_meta["thread_id"]);
    assert_ne!(child_meta["parent_thread_id"], "local-parent");
    input["input"][0]["content"][1]["encrypted_content"] = json!("foreign-cipher");
    send(&mut child, input).await;
    assert_eq!(next(&mut child).await["status"], 400);
    assert_eq!(fixture.requests().len(), 2);
    parent.close(None).await.unwrap();
    child.close(None).await.unwrap();
}

#[tokio::test]
async fn controls_are_delivered_on_actual_101_without_creating_a_model_attempt() {
    let fixture = Fixture::new(vec![ordinary("observed-response")], vec![]).await;
    let (mut client, response) =
        tokio_tungstenite::connect_async(fixture.client_request("handshake-controls"))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.headers()["openai-model"], "fixture-server-model");
    assert_eq!(response.headers()["x-reasoning-included"], "false");
    assert_eq!(response.headers()["x-models-etag"], "fixture-catalog");
    for name in ["x-request-id", "cf-ray", "x-codex-turn-state"] {
        assert!(!response.headers().contains_key(name));
    }
    assert!(fixture.requests().is_empty());
    let connections =
        std::fs::read_dir(fixture.directory.path().join("state/connections")).unwrap();
    for entry in connections {
        let record: Value =
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
        assert_eq!(record["status"], 101);
        assert_eq!(record["model_requests"], 0);
    }
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut client).await.last().unwrap()["type"],
        "response.completed"
    );
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    let snapshots = fixture.state.ledger.snapshot("alpha").unwrap();
    assert_eq!(snapshots.len(), 1);
    let mut linked = 0;
    for entry in &snapshots[0].facts {
        use right_codex::telemetry::NetworkFact;
        assert!(!matches!(
            &entry.fact,
            NetworkFact::HttpResponse { status: 101, .. }
        ));
        if let NetworkFact::WebSocketConnectionUsed {
            connection_id,
            reused,
            ..
        } = &entry.fact
        {
            assert!(!reused);
            assert!(
                fixture
                    .directory
                    .path()
                    .join("state/connections")
                    .join(format!("{connection_id}.json"))
                    .is_file()
            );
            linked += 1;
        }
    }
    assert_eq!(linked, 1);
}

#[tokio::test]
async fn handshake_errors_keep_non_object_empty_and_plain_text_bodies_without_retry() {
    for (status, body, content_type) in [
        (
            StatusCode::BAD_GATEWAY,
            "[\"non-object-error\"]",
            Some("application/json"),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "literal upstream plain text",
            Some("text/plain; charset=utf-8"),
        ),
        (StatusCode::INTERNAL_SERVER_ERROR, "", None),
    ] {
        let fixture = Fixture::new(vec![], vec![status]).await;
        let response = rejected_handshake(&fixture, "one-handshake", status).await;
        assert_eq!(
            response.body().as_deref().unwrap_or_default(),
            body.as_bytes()
        );
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok()),
            content_type
        );
        assert_eq!(response.headers()["retry-after"], "7");
        assert!(!response.headers().contains_key("x-request-id"));
        assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
        assert!(fixture.requests().is_empty());
        assert!(
            fixture
                .state
                .accounts
                .managed("alpha")
                .unwrap()
                .unwrap()
                .availability()
                .unwrap()
                .enabled
        );
        assert!(
            !fixture
                .state
                .accounts
                .managed("alpha")
                .unwrap()
                .unwrap()
                .availability()
                .unwrap()
                .quota_cooldown
        );
    }
}

#[tokio::test]
async fn all_error_frames_terminate_once_and_only_401_stops_account_scheduling() {
    for error in [
        json!({"type":"error","status":401,"error":{"code":"token_expired","message":"actual token failure"}}),
        json!({"type":"error","status_code":500,"error":{"code":"server_failed","message":"actual failure"}}),
        json!({"type":"error","error":{"code":"new_upstream_error","message":"no mapped status","param":"unmodified"}}),
    ] {
        let fixture = Fixture::new(vec![Reply::Events(vec![error.clone()])], vec![]).await;
        let mut client = fixture.client("arbitrary-error").await;
        send(
            &mut client,
            create(json!([{"role":"user","content":"hello"}])),
        )
        .await;
        assert_eq!(next(&mut client).await, error);
        expect_closed(&mut client).await;
        assert_eq!(fixture.requests().len(), 1);
        assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
        let availability = fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap();
        assert_eq!(availability.enabled, error["status"] != 401);
        assert!(!availability.quota_cooldown);
    }
}

#[tokio::test]
async fn failed_response_without_output_keeps_original_error_and_is_not_an_unknown_send() {
    let error = json!({"type":"response.failed","response":{"error":{"code":"usage_limit_reached","message":"actual failed response","resets_in_seconds":60}}});
    let fixture = Fixture::new(vec![Reply::Events(vec![error.clone()])], vec![]).await;
    let mut client = fixture.client("failed-without-output").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    assert_eq!(next(&mut client).await, error);
    expect_closed(&mut client).await;
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
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
    let session = std::fs::read_dir(fixture.directory.path().join("state/sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let snapshot: Value = serde_json::from_slice(&std::fs::read(session).unwrap()).unwrap();
    assert_eq!(
        snapshot["session"]["attempts"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["state"],
        "failed"
    );
}

async fn rejected_handshake(
    fixture: &Fixture,
    thread: &str,
    status: StatusCode,
) -> http::Response<Option<Vec<u8>>> {
    match tokio_tungstenite::connect_async(fixture.client_request(thread)).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), status);
            *response
        }
        other => panic!("expected actual rejected upstream handshake, got {other:?}"),
    }
}

async fn expect_closed(client: &mut Client) {
    let message = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .unwrap();
    assert!(
        matches!(message, Some(Ok(ClientMessage::Close(_))) | None),
        "request transport was not closed: {message:?}"
    );
}

#[tokio::test]
async fn handshake_reads_delayed_long_and_chunked_bodies_once_and_observes_body_reset() {
    for chunked in [false, true] {
        let fixture = Fixture::new(vec![], vec![]).await;
        let body = format!("{{\n \"error\": {{\"code\":\"usage_limit_reached\",\"message\":\"{}\",\"resets_at\":4102444800}}\n}}", "actual source body ".repeat(3000)).into_bytes();
        *fixture.upstream.raw_rejection.lock().unwrap() = Some(RawRejection {
            chunks: body.chunks(9000).map(|v| v.to_vec()).collect(),
            length: (!chunked).then_some(body.len()),
            truncate: false,
        });
        let request = fixture.client_request("delayed-error");
        let response = reqwest::Client::new()
            .get(fixture.url.replacen("ws://", "http://", 1))
            .headers(request.headers().clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_slice());
        assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
        assert!(fixture.requests().is_empty());
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
    }
}

#[tokio::test]
async fn truncated_handshake_keeps_status_prefix_and_incomplete_delivery_without_retry() {
    let fixture = Fixture::new(vec![], vec![]).await;
    let prefix = b"{\"error\":{\"message\":\"actual truncated source".to_vec();
    *fixture.upstream.raw_rejection.lock().unwrap() = Some(RawRejection {
        chunks: vec![prefix.clone()],
        length: Some(prefix.len() + 100),
        truncate: true,
    });
    let request = fixture.client_request("truncated-error");
    let response = reqwest::Client::new()
        .get(fixture.url.replacen("ws://", "http://", 1))
        .headers(request.headers().clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut stream = response.bytes_stream();
    let mut observed = Vec::new();
    let mut incomplete = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => observed.extend_from_slice(&bytes),
            Err(_) => {
                incomplete = true;
                break;
            }
        }
    }
    assert_eq!(observed, prefix);
    assert!(incomplete);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
    assert!(fixture.requests().is_empty());
    assert!(
        !fixture
            .state
            .accounts
            .managed("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown
    );
}

#[tokio::test]
async fn idle_401_does_not_wait_for_session_lock_and_retires_other_existing_connections() {
    for error in [
        json!({"type":"error","status":401,"error":{"code":"token_expired","message":"actual idle rejection"}}),
        json!({"type":"response.failed","response":{"error":{"status_code":401,"code":"token_expired","message":"actual idle rejection"}}}),
    ] {
        assert_idle_rejection(error).await;
    }
}
async fn assert_idle_rejection(error: Value) {
    let fixture =
        Fixture::with_accounts(vec![Reply::IdleError(error.clone())], vec![], &["alpha"]).await;
    let mut first = fixture.client("idle-rejection").await;
    let mut other = fixture.client("other-existing").await;
    send(
        &mut first,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    assert_eq!(
        terminal(&mut first).await.last().unwrap()["type"],
        "response.completed"
    );
    let files: Vec<Value> = std::fs::read_dir(fixture.directory.path().join("state/sessions"))
        .unwrap()
        .map(|entry| {
            serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .collect();
    let key = files
        .iter()
        .find(|value| !value["session"]["attempts"].as_object().unwrap().is_empty())
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let session = fixture.state.sessions.get(&key).unwrap();
    let held = session.lock_owned().await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), next(&mut first))
            .await
            .unwrap(),
        error
    );
    expect_closed(&mut first).await;
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
    send(
        &mut other,
        create(json!([{"role":"user","content":"new after rejection"}])),
    )
    .await;
    assert_eq!(next(&mut other).await["status"], 503);
    expect_closed(&mut other).await;
    assert_eq!(fixture.requests().len(), 1);
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 2);
    drop(held);
}

#[tokio::test]
async fn rejected_handshake_keeps_original_response_even_when_evidence_directory_is_unwritable() {
    let fixture = Fixture::new(vec![], vec![StatusCode::UNAUTHORIZED]).await;
    std::fs::write(
        fixture.directory.path().join("state/connections"),
        b"not a directory",
    )
    .unwrap();
    let response = rejected_handshake(
        &fixture,
        "reject-without-evidence",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(response.body().as_ref().unwrap()).unwrap()["error"]["code"],
        "token_expired"
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
    assert_eq!(fixture.upstream.handshakes.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn active_error_is_not_replaced_when_session_persistence_fails() {
    let error = json!({"type":"error","status":401,"error":{"code":"token_expired","message":"actual source error"}});
    let fixture = Fixture::new(vec![Reply::DelayedError(error.clone())], vec![]).await;
    let mut client = fixture.client("error-persistence").await;
    send(
        &mut client,
        create(json!([{"role":"user","content":"hello"}])),
    )
    .await;
    assert_eq!(next(&mut client).await["type"], "response.created");
    let file = std::fs::read_dir(fixture.directory.path().join("state/sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    assert_eq!(next(&mut client).await, error);
    expect_closed(&mut client).await;
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
    assert_eq!(fixture.requests().len(), 1);
}
