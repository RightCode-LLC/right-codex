//! OAuth Responses WebSocket relay. The fixed official dialer owns proxy and
//! TLS negotiation; the gateway owns account-scoped identities and send latches.
use crate::{
    gateway::{self, Active, AppState, Conversation, StartFailure},
    protocol::{IdentityKind, V2Completion},
    session::{ConnectionSideband, Session, ToolDelivery},
    telemetry::TerminalKind,
    ws_transport::{self, ConnectionInner},
};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use codex_api::{ApiError, WebsocketTelemetry};
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_tungstenite::tungstenite::{Error as NativeError, Message as NativeMessage};
use uuid::Uuid;

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 256 * 1024 * 1024;
const MAX_QUEUED_CREATES: usize = 4;
pub async fn upgrade(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (binding, controls) = match preconnect(state.clone(), &headers).await {
        Ok(binding) => {
            let controls =
                crate::response_projection::project_response_headers(&binding.handshake_headers);
            (binding, controls)
        }
        Err(failure) => return failure.response,
    };
    let mut response = ws
        .max_frame_size(MAX_FRAME_BYTES)
        .max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |client| serve(state, headers, client, binding));
    response.headers_mut().extend(controls);
    response
}
struct Binding {
    socket: ConnectionInner,
    account: String,
    revision: String,
    account_snapshot: Arc<crate::accounts::Account>,
    key: String,
    connection_id: String,
    frame_index: u64,
    handshake_headers: HeaderMap,
    used: bool,
}

// The Upgrade header supplies local scope lookup material. No model input or
// model attempt is manufactured while the peer has not sent response.create.
async fn preconnect(state: Arc<AppState>, headers: &HeaderMap) -> Result<Binding, StartFailure> {
    let fail = |response| StartFailure {
        response,
        status: None,
    };
    let mut material = json!({});
    if let Some(raw) = headers.get(crate::metadata::CANONICAL_METADATA) {
        let raw = raw.to_str().map_err(|_| {
            fail(gateway::protocol_error(
                crate::protocol::ProtocolError::Invalid("metadata.header"),
            ))
        })?;
        material["client_metadata"] = json!({crate::metadata::CANONICAL_METADATA:raw});
    }
    let scope = gateway::scope(&state, headers, &material).map_err(fail)?;
    let mut conversation = Conversation::acquire(state.clone(), scope)
        .await
        .map_err(fail)?;
    let logical_turn = gateway::logical_turn(&conversation.namespace, &material, headers);
    let (account, lease) = conversation.account(&HashSet::new()).await.map_err(fail)?;
    let parent = gateway::parent_request_proof(&conversation, &material, headers).map_err(fail)?;
    let projected = conversation
        .session
        .prepare_handshake_metadata(&material, headers, &logical_turn, parent.as_ref())
        .map_err(|e| fail(gateway::protocol_error(e)))?;
    gateway::persist(&state, &conversation.key, &conversation.session)
        .map_err(|e| fail(gateway::protocol_error(e)))?;
    let result = dial(&mut conversation, &account, projected).await;
    drop(lease);
    result
}

async fn dial(
    conversation: &mut Conversation,
    account: &Arc<crate::accounts::Account>,
    projected: HeaderMap,
) -> Result<Binding, StartFailure> {
    let fail = |response| StartFailure {
        response,
        status: None,
    };
    let route = account
        .responses_route(&conversation.state.config.base_url)
        .await
        .map_err(|error| gateway::routing_failure(&conversation.state, account, error))?;
    let provider = gateway::provider(
        &conversation.state,
        account,
        route.base_url.clone(),
        projected,
    );
    let selected_route_sha256 = format!(
        "{:x}",
        Sha256::digest(
            json!([
                route.base_url,
                route.account_routing_override,
                route.auth_revision
            ])
            .to_string()
            .as_bytes()
        )
    );
    let url = provider.websocket_url_for_path("responses").map_err(|_| {
        fail(gateway::protocol_error(
            crate::protocol::ProtocolError::Invalid("websocket.url"),
        ))
    })?;
    let mut outbound = provider.headers;
    if let Some(value) = route.account_routing_override {
        outbound.insert(
            "x-openai-account-routing-override",
            HeaderValue::from_str(&value).map_err(|_| {
                fail(gateway::protocol_error(
                    crate::protocol::ProtocolError::Invalid("account.route_header"),
                ))
            })?,
        );
    }
    account.authorize_headers(&mut outbound).map_err(|_| {
        fail(gateway::error(
            StatusCode::BAD_GATEWAY,
            "account_auth_unavailable",
            "Account OAuth unavailable",
            "账号 OAuth 不可用",
        ))
    })?;
    for (name, value) in [
        ("session-id", &conversation.session.session_id),
        ("thread-id", &conversation.session.thread_id),
        ("x-client-request-id", &conversation.session.thread_id),
    ] {
        outbound.insert(
            name,
            HeaderValue::from_str(value).map_err(|_| {
                fail(gateway::protocol_error(
                    crate::protocol::ProtocolError::Invalid("websocket.headers"),
                ))
            })?,
        );
    }
    outbound.insert(
        "openai-beta",
        HeaderValue::from_static("responses_websockets=2026-02-06"),
    );
    let connection_id = Uuid::new_v4().to_string();
    let began = Instant::now();
    let capture: crate::ws_handshake::Capture = Arc::new(std::sync::Mutex::new(None));
    let result = tokio::time::timeout(
        Duration::from_secs(conversation.state.config.request_timeout_secs),
        ws_transport::connect(url.as_str(), outbound, account.proxy(), capture.clone()),
    )
    .await;
    let raw_error = capture
        .lock()
        .ok()
        .and_then(|mut value| value.take())
        .or_else(|| {
            if let Ok(Err(NativeError::Http(response))) = &result {
                Some(crate::transport::RawHttpError {
                    status: response.status(),
                    retry_after: codex_http_client::RetryAfter::from_headers(response.headers()),
                    headers: response.headers().clone(),
                    body: response.body().clone().unwrap_or_default(),
                    complete: false,
                })
            } else {
                None
            }
        });
    if let Some(error) = &raw_error
        && let Err(error) =
            crate::upstream_policy::observe_raw_http(&conversation.state.accounts, account, error)
    {
        tracing::error!(%error, "could not persist upstream account status");
    }
    let status = raw_error
        .as_ref()
        .map(|error| error.status)
        .or_else(|| match &result {
            Ok(Ok((_, response))) => Some(response.status()),
            _ => None,
        });
    let duration = began.elapsed();
    // Independent connection evidence: no model attempt, delivery or client
    // execution claim is created by a completed (or rejected) handshake.
    let evidence = json!({"version":1,"connection_id":connection_id,"scope_key":conversation.key,
        "account_id":account.id(),"auth_revision":account.revision(),"route_sha256":selected_route_sha256,
        "observed_at_unix_ms":gateway::now_ms(),"status":status.map(|s|s.as_u16()),
        "elapsed_micros":duration.as_micros(),"model_requests":0});
    let stored = crate::storage::atomic(
        &conversation
            .state
            .config
            .state_dir
            .join("connections")
            .join(format!("{connection_id}.json")),
        evidence.to_string().as_bytes(),
    );
    if let Err(error) = stored {
        if raw_error.is_none() {
            return Err(fail(gateway::protocol_error(error)));
        }
        tracing::error!(%error, "could not persist rejected handshake evidence");
    }
    if let Some(error) = raw_error {
        return Err(StartFailure {
            status: Some(error.status),
            response: error.into_response(),
        });
    }
    match result {
        Ok(Ok((socket, response))) => {
            if let Some(sticky) = response
                .headers()
                .get("x-codex-turn-state")
                .and_then(|v| v.to_str().ok())
            {
                conversation
                    .session
                    .set_sticky_from_upstream(account.id(), account.revision(), sticky.into())
                    .map_err(|e| fail(gateway::protocol_error(e)))?;
                gateway::persist(
                    &conversation.state,
                    &conversation.key,
                    &conversation.session,
                )
                .map_err(|e| fail(gateway::protocol_error(e)))?;
            }
            Ok(Binding {
                socket,
                account: account.id().into(),
                revision: account.revision().into(),
                account_snapshot: account.clone(),
                key: conversation.key.clone(),
                connection_id,
                frame_index: 0,
                handshake_headers: response.headers().clone(),
                used: false,
            })
        }
        _ => Err(StartFailure {
            status,
            response: gateway::error(
                status.unwrap_or(StatusCode::BAD_GATEWAY),
                "upstream_websocket_handshake_failed",
                "Upstream WebSocket handshake failed",
                "上游 WebSocket 握手失败",
            ),
        }),
    }
}
struct Running {
    active: Active,
    v2: V2Completion,
    response_alias: Option<String>,
    bytes: usize,
}

async fn serve(state: Arc<AppState>, headers: HeaderMap, mut client: WebSocket, initial: Binding) {
    let mut binding: Option<Binding> = Some(initial);
    let mut queue = VecDeque::new();
    'client: loop {
        let input = if let Some(input) = queue.pop_front() {
            input
        } else {
            enum Idle {
                Client(Option<Result<Message, axum::Error>>),
                Source(Option<Result<NativeMessage, NativeError>>),
                Expired,
            }
            let observed = if let Some(upstream) = binding.as_mut() {
                tokio::select! {
                    message=client.next()=>Idle::Client(message),
                    message=upstream.socket.next()=>Idle::Source(message),
                    _=tokio::time::sleep(Duration::from_secs(state.config.request_timeout_secs))=>Idle::Expired,
                }
            } else {
                Idle::Client(client.next().await)
            };
            let message = match observed {
                Idle::Client(Some(Ok(value))) => value,
                Idle::Client(_) | Idle::Expired => break,
                Idle::Source(Some(Ok(NativeMessage::Ping(data)))) => {
                    if let Some(upstream) = binding.as_mut() {
                        let _ = upstream.socket.send(NativeMessage::Pong(data)).await;
                    }
                    continue 'client;
                }
                Idle::Source(Some(Ok(NativeMessage::Pong(_)))) => continue 'client,
                Idle::Source(Some(Ok(NativeMessage::Text(raw)))) => {
                    let result = match binding.as_mut() {
                        Some(upstream) => {
                            idle_sideband(&state, upstream, &mut client, raw.as_str()).await
                        }
                        None => Err(()),
                    };
                    if result.is_err() {
                        let _ =
                            send_error(&mut client, 502, "unexpected_idle_websocket_frame").await;
                        break 'client;
                    }
                    if serde_json::from_str::<Value>(raw.as_str()).is_ok_and(|value| {
                        matches!(value["type"].as_str(), Some("error" | "response.failed"))
                    }) {
                        break 'client;
                    }
                    continue 'client;
                }
                Idle::Source(Some(Ok(NativeMessage::Close(frame)))) => {
                    let _ = client
                        .send(Message::Close(frame.map(|frame| {
                            axum::extract::ws::CloseFrame {
                                code: u16::from(frame.code),
                                reason: frame.reason.to_string().into(),
                            }
                        })))
                        .await;
                    break 'client;
                }
                Idle::Source(_) => break 'client,
            };
            match message {
                Message::Text(raw) => match parse_create(&raw) {
                    Ok(v) => v,
                    Err(code) => {
                        if send_error(&mut client, 400, code).await.is_err() {
                            break;
                        }
                        continue;
                    }
                },
                Message::Ping(data) => {
                    if client.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                    continue;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => break,
                Message::Binary(_) => {
                    let _ =
                        send_error(&mut client, 400, "binary_business_request_unsupported").await;
                    break;
                }
            }
        };
        let scope = match gateway::scope(&state, &headers, &input) {
            Ok(scope) => scope,
            Err(response) => {
                if send_response_error(&mut client, response).await.is_err() {
                    break;
                }
                continue;
            }
        };
        if binding.as_ref().is_some_and(|b| b.key != scope.key) {
            let _ = send_error(&mut client, 400, "websocket_conversation_changed").await;
            break;
        }
        let mut conversation = match Conversation::acquire(state.clone(), scope).await {
            Ok(v) => v,
            Err(response) => {
                if send_response_error(&mut client, response).await.is_err() {
                    break;
                }
                continue;
            }
        };
        let logical_turn = gateway::logical_turn(&conversation.namespace, &input, &headers);
        let mut running = match start(
            &mut conversation,
            &headers,
            input,
            &logical_turn,
            &mut binding,
        )
        .await
        {
            Ok(value) => value,
            Err(failure) => {
                let retire_connection = failure.status == Some(StatusCode::SERVICE_UNAVAILABLE);
                if send_response_error(&mut client, failure.response)
                    .await
                    .is_err()
                {
                    break 'client;
                }
                if retire_connection {
                    break 'client;
                }
                continue 'client;
            }
        };
        let mut deadline =
            tokio::time::Instant::now() + Duration::from_secs(state.config.request_timeout_secs);
        let mut close_client = false;
        loop {
            enum Next {
                Client(Option<Result<Message, axum::Error>>),
                Source(Option<Result<NativeMessage, NativeError>>),
                Timeout,
            }
            let poll_started = Instant::now();
            let next = {
                let Some(upstream) = binding.as_mut() else {
                    break;
                };
                tokio::select! {
                    message=client.next()=>Next::Client(message),
                    message=upstream.socket.next()=>Next::Source(message),
                    _=tokio::time::sleep_until(deadline)=>Next::Timeout,
                }
            };
            match next {
                Next::Client(Some(Ok(Message::Ping(data)))) => {
                    if client.send(Message::Pong(data)).await.is_err() {
                        close_client = true;
                        break;
                    }
                }
                Next::Client(Some(Ok(Message::Pong(_)))) => {}
                Next::Client(Some(Ok(Message::Text(raw)))) => {
                    let value = match serde_json::from_str::<Value>(&raw) {
                        Ok(v) => v,
                        Err(_) => {
                            let _ = send_error(&mut client, 400, "invalid_websocket_json").await;
                            continue;
                        }
                    };
                    if value["type"] == "response.interrupt" {
                        let mapped = match interrupt(
                            &value,
                            running.response_alias.as_deref(),
                            &conversation,
                        ) {
                            Ok(v) => v,
                            Err(code) => {
                                let _ = send_error(&mut client, 400, code).await;
                                continue;
                            }
                        };
                        let Some(upstream) = binding.as_mut() else {
                            break;
                        };
                        if upstream
                            .socket
                            .send(NativeMessage::Text(mapped.to_string().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // This is the actual socket send of a control, not an
                        // acknowledgement or model response completion.
                        if let Ok(mut journal) = running.active.journal.lock() {
                            let _ = journal.stream_event(
                                "gateway.response.interrupt.sent",
                                mapped.to_string().as_bytes(),
                            );
                        }
                    } else {
                        match parse_create(&raw) {
                            Ok(v) if queue.len() < MAX_QUEUED_CREATES => queue.push_back(v),
                            Ok(_) => {
                                let _ =
                                    send_error(&mut client, 503, "websocket_request_queue_full")
                                        .await;
                            }
                            Err(code) => {
                                let _ = send_error(&mut client, 400, code).await;
                            }
                        }
                    }
                }
                Next::Client(_) => {
                    running
                        .active
                        .finish(TerminalKind::Cancelled, "client_socket_closed", false);
                    close_client = true;
                    break;
                }
                Next::Timeout => {
                    running
                        .active
                        .finish(TerminalKind::Unknown, "websocket_idle_timeout", false);
                    let _ = send_error(&mut client, 504, "upstream_websocket_timeout").await;
                    binding = None;
                    break;
                }
                Next::Source(source) => {
                    let hook: Result<_, ApiError> = Ok(source);
                    running
                        .active
                        .hooks
                        .on_ws_event(&hook, poll_started.elapsed());
                    let source = match hook {
                        Ok(source) => source,
                        Err(_) => unreachable!("received socket observation"),
                    };
                    let message = match source {
                        Some(Ok(v)) => v,
                        _ => {
                            running.active.finish(
                                TerminalKind::Unknown,
                                "upstream_websocket_closed",
                                false,
                            );
                            let _ =
                                send_error(&mut client, 502, "upstream_websocket_incomplete").await;
                            binding = None;
                            break;
                        }
                    };
                    deadline = tokio::time::Instant::now()
                        + Duration::from_secs(state.config.request_timeout_secs);
                    let raw = match message {
                        NativeMessage::Text(raw) => raw,
                        NativeMessage::Ping(data) => {
                            if let Some(upstream) = binding.as_mut() {
                                let _ = upstream.socket.send(NativeMessage::Pong(data)).await;
                            }
                            continue;
                        }
                        NativeMessage::Pong(_) => continue,
                        NativeMessage::Close(frame) => {
                            running.active.finish(
                                TerminalKind::Unknown,
                                "upstream_websocket_closed",
                                false,
                            );
                            let _ = client
                                .send(Message::Close(frame.map(|frame| {
                                    axum::extract::ws::CloseFrame {
                                        code: u16::from(frame.code),
                                        reason: frame.reason.to_string().into(),
                                    }
                                })))
                                .await;
                            binding = None;
                            close_client = true;
                            break;
                        }
                        NativeMessage::Binary(_) | NativeMessage::Frame(_) => {
                            running.active.finish(
                                TerminalKind::Unknown,
                                "unexpected_upstream_binary",
                                false,
                            );
                            binding = None;
                            let _ =
                                send_error(&mut client, 502, "invalid_upstream_websocket_frame")
                                    .await;
                            break;
                        }
                    };
                    running.bytes = match running.bytes.checked_add(raw.len()) {
                        Some(bytes) if bytes <= MAX_STREAM_BYTES => bytes,
                        _ => {
                            binding = None;
                            let _ = send_error(&mut client, 502, "upstream_stream_budget_exceeded")
                                .await;
                            break;
                        }
                    };
                    let mut value: Value = match serde_json::from_str(&raw) {
                        Ok(v) => v,
                        Err(_) => {
                            binding = None;
                            let _ = send_error(&mut client, 502, "invalid_upstream_websocket_json")
                                .await;
                            break;
                        }
                    };
                    if is_sideband(&value) {
                        let Some(upstream) = binding.as_mut() else {
                            break;
                        };
                        if forward_sideband(
                            &state,
                            &conversation.key,
                            &mut conversation.session,
                            upstream,
                            &mut client,
                            raw.as_str(),
                            value,
                        )
                        .await
                        .is_err()
                        {
                            binding = None;
                            close_client = true;
                            break;
                        }
                        continue;
                    }
                    running.active.event(&raw, &value);
                    if let Err(error) = crate::upstream_policy::observe_event(
                        &state.accounts,
                        &running.active.account,
                        &value,
                    ) {
                        tracing::error!(%error, "could not persist upstream account status");
                    }
                    if running.active.is_compaction && running.v2.observe(&value).is_err() {
                        binding = None;
                        let _ = send_error(&mut client, 502, "invalid_compaction_response").await;
                        break;
                    }
                    let kind = value["type"].as_str().unwrap_or("").to_owned();
                    let terminal = matches!(
                        kind.as_str(),
                        "response.completed" | "response.incomplete" | "response.failed"
                    ) || kind == "error";
                    if kind == "response.completed"
                        && running.active.is_compaction
                        && running.v2.finish().is_err()
                    {
                        binding = None;
                        let _ = send_error(&mut client, 502, "invalid_compaction_response").await;
                        break;
                    }
                    let upstream_failure = matches!(kind.as_str(), "error" | "response.failed");
                    let original_failure = upstream_failure.then(|| value.clone());
                    if conversation.session.rewrite_event(&mut value).is_err() {
                        if let Some(original) = original_failure {
                            value = original;
                            crate::response_projection::sanitize_http_error(&mut value);
                        } else {
                            binding = None;
                            let _ = send_error(&mut client, 502, "invalid_upstream_identity").await;
                            break;
                        }
                    }
                    if kind == "response.created" {
                        running.response_alias =
                            value["response"]["id"].as_str().map(str::to_owned);
                    }
                    match conversation.session.record_delivery(&value) {
                        Ok(ToolDelivery::AlreadyDelivered) => continue,
                        Ok(_) => {}
                        Err(error) if upstream_failure => {
                            tracing::error!(%error, "could not record upstream error delivery")
                        }
                        Err(_) => {
                            binding = None;
                            let _ = send_error(&mut client, 502, "delivery_state_failed").await;
                            break;
                        }
                    }
                    if terminal {
                        if matches!(kind.as_str(), "error" | "response.failed") {
                            if let Err(error) = conversation
                                .session
                                .fail_attempt(&running.active.id, &value)
                            {
                                tracing::error!(%error, "could not record observed upstream failure");
                            }
                            close_client = true;
                        } else if conversation
                            .session
                            .finish_attempt(&running.active.id, &value)
                            .is_err()
                        {
                            binding = None;
                            let _ = send_error(&mut client, 502, "invalid_completion").await;
                            break;
                        }
                    }
                    if let Err(error) =
                        gateway::persist(&state, &conversation.key, &conversation.session)
                    {
                        if upstream_failure {
                            tracing::error!(%error, "could not persist upstream error delivery");
                        } else {
                            binding = None;
                            let _ = send_error(&mut client, 502, "persistence_failed").await;
                            break;
                        }
                    }
                    if client
                        .send(Message::Text(value.to_string().into()))
                        .await
                        .is_err()
                    {
                        close_client = true;
                        break;
                    }
                    if let Ok(mut journal) = running.active.journal.lock() {
                        let _ = journal.stream_event(
                            "gateway.websocket.client_text_written",
                            value.to_string().as_bytes(),
                        );
                    }
                    if terminal {
                        conversation.current = None;
                        if kind == "response.completed" {
                            running
                                .active
                                .hooks
                                .record_verified_completion_usage(&value);
                        }
                        let outcome = match kind.as_str() {
                            "response.completed" => TerminalKind::Completed,
                            "response.incomplete" => TerminalKind::Incomplete,
                            _ => TerminalKind::Failed,
                        };
                        running.active.finish(
                            outcome,
                            match kind.as_str() {
                                "response.completed" => "completed",
                                "response.incomplete" => "response_incomplete",
                                _ => "response_failed",
                            },
                            true,
                        );
                        break;
                    }
                }
            }
        }
        // Dropping the held conversation marks any unresolved send Unknown;
        // retaining a socket never retains its request mutex or account lease.
        drop(running);
        drop(conversation);
        if close_client || binding.is_none() {
            break;
        }
    }
    let _ = client.send(Message::Close(None)).await;
    drop(binding);
}

fn is_sideband(value: &Value) -> bool {
    matches!(
        value["type"].as_str(),
        Some("codex.response.metadata" | "codex.rate_limits")
    )
}
async fn idle_sideband(
    state: &Arc<AppState>,
    binding: &mut Binding,
    client: &mut WebSocket,
    raw: &str,
) -> Result<(), ()> {
    let mut value: Value = serde_json::from_str(raw).map_err(|_| ())?;
    if matches!(value["type"].as_str(), Some("error" | "response.failed")) {
        if let Err(error) = crate::upstream_policy::observe_event(
            &state.accounts,
            &binding.account_snapshot,
            &value,
        ) {
            tracing::error!(%error, "could not persist idle account status");
        }
        crate::response_projection::sanitize_http_error(&mut value);
        // No model attempt owns this idle error. Evidence is independent of
        // the session mutex, so another active request cannot suppress it.
        let evidence = json!({"connection_id":binding.connection_id, "account_id":binding.account,
            "auth_revision":binding.revision,"kind":"idle_error","raw_sha256":format!("{:x}",Sha256::digest(raw.as_bytes())),
            "bytes":raw.len(),"observed_at_unix_ms":gateway::now_ms()});
        if let Err(error) = crate::storage::atomic(
            &state
                .config
                .state_dir
                .join("connections")
                .join(format!("{}-idle-error.json", binding.connection_id)),
            evidence.to_string().as_bytes(),
        ) {
            tracing::error!(%error,"could not persist idle error evidence");
        }
        return client
            .send(Message::Text(value.to_string().into()))
            .await
            .map_err(|_| ());
    }
    if !is_sideband(&value) && value["type"] != "error" {
        return Err(());
    }
    let session = state.sessions.get(&binding.key).ok_or(())?;
    let mut session = tokio::time::timeout(
        Duration::from_secs(state.config.queue_timeout_secs),
        session.lock_owned(),
    )
    .await
    .map_err(|_| ())?;
    let key = binding.key.clone();
    forward_sideband(state, &key, &mut session, binding, client, raw, value).await
}
async fn forward_sideband(
    state: &Arc<AppState>,
    key: &str,
    session: &mut Session,
    binding: &mut Binding,
    client: &mut WebSocket,
    raw: &str,
    mut value: Value,
) -> Result<(), ()> {
    if session.account_id != binding.account || session.auth_revision != binding.revision {
        return Err(());
    }
    binding.frame_index = binding.frame_index.checked_add(1).ok_or(())?;
    let raw_sha = format!("{:x}", Sha256::digest(raw.as_bytes()));
    session
        .observe_connection_sideband(ConnectionSideband {
            connection_id: binding.connection_id.clone(),
            frame_index: binding.frame_index,
            account_id: binding.account.clone(),
            auth_revision: binding.revision.clone(),
            kind: value["type"].as_str().ok_or(())?.into(),
            raw_sha256: raw_sha.clone(),
            bytes: raw.len(),
            observed_at_unix_ms: gateway::now_ms(),
            client_socket_written: false,
        })
        .map_err(|_| ())?;
    session.rewrite_event(&mut value).map_err(|_| ())?;
    gateway::persist(state, key, session).map_err(|_| ())?;
    client
        .send(Message::Text(value.to_string().into()))
        .await
        .map_err(|_| ())?;
    if let Err(error) = session
        .connection_sideband_written(&binding.connection_id, binding.frame_index, &raw_sha)
        .and_then(|_| gateway::persist(state, key, session))
    {
        tracing::error!(%error, "could not persist sideband socket write");
    }
    Ok(())
}
async fn start(
    conversation: &mut Conversation,
    headers: &HeaderMap,
    input: Value,
    logical_turn: &str,
    binding: &mut Option<Binding>,
) -> Result<Running, StartFailure> {
    let fail = |response| StartFailure {
        response,
        status: None,
    };
    // Validate history before committing a model attempt. The real opening
    // handshake may already own an account reservation and scope identities.
    gateway::preflight(conversation, &input, headers, logical_turn).map_err(fail)?;
    let (account, lease) = conversation
        .account(&HashSet::new())
        .await
        .map_err(|response| StartFailure {
            status: Some(response.status()),
            response,
        })?;
    if binding.as_ref().is_none_or(|b| {
        b.account != account.id() || b.revision != account.revision() || b.key != conversation.key
    }) {
        return Err(StartFailure {
            status: Some(StatusCode::SERVICE_UNAVAILABLE),
            response: gateway::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "websocket_account_changed",
                "Reconnect WebSocket before sending a new request",
                "账号连接已变化，请重新建立 WebSocket 后发送新请求",
            ),
        });
    }
    let scoped = gateway::prepare(conversation, input, headers, logical_turn).map_err(fail)?;
    let mut payload = scoped.request.body.clone();
    payload["type"] = json!("response.create");
    let wire = payload.to_string();
    let mut active = gateway::observe(
        conversation,
        account.clone(),
        lease,
        &scoped,
        "/responses",
        format!("{:x}", Sha256::digest(wire.as_bytes())),
    )
    .map_err(fail)?;
    let reused = binding.as_ref().is_some_and(|b| b.used);
    if let Some(connected) = binding.as_mut() {
        active
            .journal
            .lock()
            .map_err(|_| {
                fail(gateway::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connection_fact_unavailable",
                    "Connection evidence unavailable",
                    "连接事实无法保存",
                ))
            })?
            .websocket_connection_used(&connected.connection_id, reused)
            .map_err(|_| {
                fail(gateway::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connection_fact_unavailable",
                    "Connection evidence unavailable",
                    "连接事实无法保存",
                ))
            })?;
        connected.used = true;
    }
    let began = Instant::now();
    let socket = &mut binding
        .as_mut()
        .ok_or_else(|| {
            fail(gateway::error(
                StatusCode::BAD_GATEWAY,
                "websocket_missing",
                "WebSocket unavailable",
                "WebSocket 不可用",
            ))
        })?
        .socket;
    let result = tokio::time::timeout(
        Duration::from_secs(conversation.state.config.request_timeout_secs),
        socket.send(NativeMessage::Text(wire.into())),
    )
    .await;
    let error = if result.as_ref().is_ok_and(|r| r.is_ok()) {
        None
    } else {
        Some(ApiError::Stream("WebSocket send failed".into()))
    };
    active
        .hooks
        .on_ws_request(began.elapsed(), error.as_ref(), reused);
    if error.is_some() {
        *binding = None;
        active.finish(TerminalKind::Unknown, "websocket_send_unknown", false);
        return Err(StartFailure {
            status: Some(StatusCode::SERVICE_UNAVAILABLE),
            response: gateway::error(
                StatusCode::BAD_GATEWAY,
                "websocket_send_unknown",
                "WebSocket send outcome is unknown",
                "WebSocket 发送结果未确认",
            ),
        });
    }
    Ok(Running {
        active,
        v2: V2Completion::default(),
        response_alias: None,
        bytes: 0,
    })
}

fn parse_create(raw: &str) -> Result<Value, &'static str> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err("websocket_request_too_large");
    }
    let mut value: Value = serde_json::from_str(raw).map_err(|_| "invalid_websocket_json")?;
    let object = value.as_object_mut().ok_or("invalid_websocket_request")?;
    if object.remove("type") != Some(json!("response.create")) {
        return Err("unsupported_websocket_request_type");
    }
    Ok(value)
}
fn interrupt(
    input: &Value,
    response_alias: Option<&str>,
    conversation: &Conversation,
) -> Result<Value, &'static str> {
    let object = input
        .as_object()
        .filter(|o| o.len() == 3)
        .ok_or("invalid_response_interrupt")?;
    if object.get("type") != Some(&json!("response.interrupt"))
        || object.get("mode") != Some(&json!("discard_partial_items"))
    {
        return Err("invalid_response_interrupt");
    }
    let response = input["response_id"]
        .as_str()
        .filter(|r| Some(*r) == response_alias)
        .ok_or("foreign_response_interrupt")?;
    let upstream = conversation
        .session
        .identifiers()
        .get(&(IdentityKind::Response, response.into()))
        .ok_or("unmapped_response_interrupt")?;
    Ok(json!({"type":"response.interrupt","response_id":upstream,"mode":"discard_partial_items"}))
}
async fn send_error(client: &mut WebSocket, status: u16, code: &str) -> Result<(), axum::Error> {
    client.send(Message::Text(json!({"type":"error","status":status,"error":{"code":code,"message":"Gateway WebSocket request failed / 网关 WebSocket 请求失败"}}).to_string().into())).await
}
async fn send_response_error(
    client: &mut WebSocket,
    response: Response,
) -> Result<(), axum::Error> {
    let status = response.status().as_u16();
    let controls = crate::response_projection::project_response_headers(response.headers());
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .ok();
    let mut value = body
        .and_then(|v| serde_json::from_slice::<Value>(&v).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| gateway::failure_value("gateway_request_failed"));
    crate::response_projection::sanitize_http_error(&mut value);
    if !controls.is_empty() {
        if !value.get("headers").is_some_and(Value::is_object) {
            value["headers"] = json!({});
        }
        for (name, entry) in &controls {
            if let Ok(entry) = entry.to_str() {
                value["headers"][name.as_str()] = json!(entry);
            }
        }
    }
    value["type"] = json!("error");
    value["status"] = json!(status);
    client.send(Message::Text(value.to_string().into())).await
}
