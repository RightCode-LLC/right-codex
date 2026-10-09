//! Synthetic OAuth loopback only. No host auth or external network.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use codex_api::{
    RealtimeEventParser, RealtimeOutputModality, RealtimeSessionConfig, RealtimeSessionMode,
    SearchCommands, SearchSettings,
};
use codex_client::{Provider, RetryConfig};
use codex_protocol::protocol::RealtimeVoice;
use right_codex::accounts::AccountPool;
use right_codex::auxiliary::{
    AuxiliaryClient, AuxiliaryError, project_image_edit, project_image_edit_with_resources,
    project_realtime_session, project_search,
};
use right_codex::config::{AccountConfig, GatewayConfig};
use right_codex::gateway::AppState;
use right_codex::resources::ResourceStore;
use right_codex::session::{FileProvenance, Session};
use right_codex::telemetry::{OutboundIdentity, TerminalKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Default)]
struct Received(Mutex<Vec<(String, HeaderMap, Value)>>);

const PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/nS8AAAAASUVORK5CYII=";

async fn upstream(
    State(received): State<Arc<Received>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    received
        .0
        .lock()
        .unwrap()
        .push((uri.to_string(), headers, body));
    let result = if uri.path().ends_with("/models") {
        json!({"models":[], "future_catalog_field":{"kept":true}})
    } else if uri.path().ends_with("/alpha/search") {
        json!({"output":"found","encrypted_output":null,"results":[],
            "future_search_field":{"source":"upstream"}})
    } else {
        json!({"created": 1, "data":[{"b64_json":PNG_B64,"generation_id":"gen_real",
            "future_data_field":"kept"}],"future_image_field":{"source":"upstream"}})
    };
    (StatusCode::OK, Json(result))
}

async fn realtime_upstream(
    State(received): State<Arc<Received>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    received.0.lock().unwrap().push((
        uri.to_string(),
        headers,
        Value::String(String::from_utf8(body.to_vec()).unwrap()),
    ));
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/sdp")
        .header(
            header::LOCATION,
            "/backend-api/codex/realtime/calls/rtc_upstream",
        )
        .body(Body::from("v=0\r\na=answer\r\n"))
        .unwrap()
}

fn auth(path: &std::path::Path) {
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt",
            "tokens":{"id_token":"fixture-id","access_token":"synthetic-oauth-secret",
                "refresh_token":"synthetic-refresh","account_id":"workspace-alpha"},
            "last_refresh":"2026-10-10T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn model_catalog_ignores_foreign_client_oauth_identity() {
    let dir = TempDir::new().unwrap();
    let first_auth = dir.path().join("alpha.json");
    let second_auth = dir.path().join("beta.json");
    auth(&first_auth);
    std::fs::write(
        &second_auth,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt",
            "tokens":{"access_token":"pool-beta-secret",
                "refresh_token":"pool-beta-refresh","account_id":"workspace-beta"}
        }))
        .unwrap(),
    )
    .unwrap();
    let received = Arc::new(Received::default());
    let upstream = Router::new()
        .route("/backend-api/codex/models", get(upstream))
        .with_state(received.clone());
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });
    let mut config = GatewayConfig {
        state_dir: dir.path().join("private"),
        base_url: format!("http://{upstream_address}/backend-api/codex"),
        chatgpt_base_url: format!("http://{upstream_address}/backend-api"),
        allow_insecure_http: true,
        ..GatewayConfig::default()
    };
    config.telemetry.official_metrics_enabled = false;
    config.accounts = vec![
        AccountConfig {
            id: "alpha".into(),
            auth_path: first_auth,
            proxy: None,
            enabled: true,
        },
        AccountConfig {
            id: "beta".into(),
            auth_path: second_auth,
            proxy: None,
            enabled: true,
        },
    ];
    let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, right_codex::auxiliary::router().with_state(state))
            .await
            .unwrap();
    });
    let response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models?client_version=0.160.0"))
        .header("chatgpt-account-id", "client-foreign-account")
        .header(header::AUTHORIZATION, "Bearer client-foreign-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = received.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let selected = calls[0].1["chatgpt-account-id"].to_str().unwrap();
    let bearer = calls[0].1[header::AUTHORIZATION].to_str().unwrap();
    assert!(matches!(
        (selected, bearer),
        ("workspace-alpha", "Bearer synthetic-oauth-secret")
            | ("workspace-beta", "Bearer pool-beta-secret")
    ));
    upstream_task.abort();
    task.abort();
}

#[test]
fn auxiliary_projection_rewrites_search_id_and_rejects_unrecognized_business_fields() {
    let session = Session::new("alpha".into(), format!("{:x}", Sha256::digest(b"revision")));
    let request = project_search(
        &json!({
            "id":"client-search-id", "model":"gpt-test", "input":"query",
            "commands":{"search_query":[{"q":"weather"}]}, "settings":{"external_web_access":true}
        }),
        &session,
    )
    .unwrap();
    assert_ne!(request.id, "client-search-id");
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["input"], "query");
    assert_eq!(value["commands"]["search_query"][0]["q"], "weather");
    assert_eq!(value["settings"]["external_web_access"], true);
    assert_eq!(
        project_search(
            &json!({"model":"gpt-test","input":"query","client_secret":"leak"}),
            &session
        ),
        Err(AuxiliaryError::Unsupported("search"))
    );
    assert_eq!(
        project_search(
            &json!({"model":"gpt-test","commands":{"search_query":[{"q":"x","private":"leak"}]}}),
            &session
        ),
        Err(AuxiliaryError::Unsupported("search.commands"))
    );
}

#[test]
fn official_search_command_and_settings_serialization_survives_projection() {
    let commands: SearchCommands = serde_json::from_value(json!({
        "search_query":[{"q":"official weather","recency":7,"domains":["example.com"]}],
        "open":[{"ref_id":"source-1","lineno":12}],
        "response_length":"medium"
    }))
    .unwrap();
    let settings: SearchSettings = serde_json::from_value(json!({
        "search_context_size":"high",
        "filters":{"allowed_domains":["example.com"]},
        "external_web_access":true
    }))
    .unwrap();
    let input = json!({
        "id":"client-search-id","model":"gpt-test",
        "input":"official query","commands":commands,"settings":settings
    });
    let session = Session::new("alpha".into(), "b".repeat(64));
    let projected = project_search(&input, &session).unwrap();
    let wire = serde_json::to_value(projected).unwrap();
    assert_eq!(wire["commands"], input["commands"]);
    assert_eq!(wire["settings"], input["settings"]);
    assert_ne!(wire["id"], input["id"]);

    let mut noncanonical = input;
    noncanonical["commands"]["image_query"] = Value::Null;
    assert_eq!(
        project_search(&noncanonical, &session),
        Err(AuxiliaryError::Unsupported("search.commands")),
    );
}

#[test]
fn image_edit_requires_same_account_file_provenance() {
    let revision = format!("{:x}", Sha256::digest(b"revision"));
    let mut session = Session::new("alpha".into(), revision.clone());
    let request =
        json!({"prompt":"edit\nthis", "model":"image-test", "images":[{"file_id":"local-file"}]});
    assert_eq!(
        project_image_edit(&request, &session),
        Err(AuxiliaryError::UnmappedFile)
    );
    session
        .register_file(FileProvenance {
            account_id: "alpha".into(),
            auth_revision: revision.clone(),
            client_id: "local-file".into(),
            upstream_id: "upstream-file".into(),
            content_sha256: format!("{:x}", Sha256::digest(b"actual-upload")),
        })
        .unwrap();
    let projected = project_image_edit(&request, &session).unwrap();
    assert_eq!(
        serde_json::to_value(projected).unwrap()["images"][0]["file_id"],
        "upstream-file"
    );
    session
        .switch_account("beta".into(), format!("{:x}", Sha256::digest(b"other")))
        .unwrap();
    assert_eq!(
        project_image_edit(&request, &session),
        Err(AuxiliaryError::UnmappedFile)
    );
}

#[test]
fn generated_image_alias_uses_local_bytes_after_account_switch() {
    let directory = TempDir::new().unwrap();
    let resources = ResourceStore::new(directory.path());
    let key = "a".repeat(64);
    let revision = "b".repeat(64);
    let generated = resources
        .alias_generated(
            &key,
            "alpha",
            &revision,
            json!({"created":1,"data":[{"b64_json":PNG_B64,"generation_id":"upstream-generation",
                "future_image_detail":"kept"}],"future_top":"kept"}),
        )
        .unwrap();
    assert_eq!(generated["future_top"], "kept");
    assert_eq!(generated["data"][0]["future_image_detail"], "kept");
    let alias = generated["data"][0]["generation_id"].as_str().unwrap();
    assert!(alias.starts_with("gen_"));
    assert_ne!(alias, "upstream-generation");
    let input = json!({"prompt":"edit", "model":"image-test", "images":[{"file_id":alias}]});
    let mut session = Session::new("alpha".into(), revision);
    let first = project_image_edit_with_resources(&input, &session, &resources, &key).unwrap();
    let first_wire = serde_json::to_value(first).unwrap();
    assert_eq!(
        first_wire["images"][0]["image_url"],
        format!("data:image/png;base64,{PNG_B64}")
    );
    assert!(!first_wire.to_string().contains("upstream-generation"));
    session
        .switch_account("beta".into(), "c".repeat(64))
        .unwrap();
    let switched = project_image_edit_with_resources(&input, &session, &resources, &key).unwrap();
    assert_eq!(
        serde_json::to_value(switched).unwrap()["images"][0]["image_url"],
        first_wire["images"][0]["image_url"]
    );
    assert_eq!(
        project_image_edit_with_resources(&input, &session, &resources, &"d".repeat(64)),
        Err(AuxiliaryError::UnmappedFile)
    );
}

#[test]
fn generation_id_without_actual_image_bytes_is_not_returned_to_client() {
    let directory = TempDir::new().unwrap();
    let resources = ResourceStore::new(directory.path());
    let result = resources.alias_generated(
        &"a".repeat(64),
        "alpha",
        &"b".repeat(64),
        json!({"created":1,"data":[{"generation_id":"upstream-only-id"}]}),
    );
    assert_eq!(result, Err(right_codex::resources::ResourceError::Image));
    assert!(!directory.path().join("generated-images").exists());
}

#[test]
fn realtime_session_accepts_exact_official_shape_and_rejects_unmapped_fields() {
    let source = RealtimeSessionConfig {
        instructions: "Speak briefly".into(),
        initial_items: Vec::new(),
        delegation_ack_filler: None,
        model: Some("realtime-test".into()),
        session_id: None,
        event_parser: RealtimeEventParser::V1,
        session_mode: RealtimeSessionMode::Conversational,
        output_modality: RealtimeOutputModality::Audio,
        voice: RealtimeVoice::Alloy,
    };
    let wire = codex_api::session_update_session_json(source).unwrap();
    let projected = project_realtime_session(&wire, "gateway-session").unwrap();
    assert_eq!(projected.session_id.as_deref(), Some("gateway-session"));
    assert_eq!(projected.instructions, "Speak briefly");
    let mut unsupported = wire;
    unsupported["client_metadata"] = json!({"device_id":"client-only"});
    assert_eq!(
        project_realtime_session(&unsupported, "gateway-session"),
        Err(AuxiliaryError::Unsupported("realtime.session"))
    );
}

#[tokio::test]
async fn native_search_header_only_scope_is_local_and_invalid_sources_never_send() {
    let dir = TempDir::new().unwrap();
    let auth_path = dir.path().join("auth.json");
    auth(&auth_path);
    let received = Arc::new(Received::default());
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = up_listener.local_addr().unwrap();
    let app = Router::new()
        .route("/backend-api/codex/alpha/search", post(upstream))
        .with_state(received.clone());
    let up_task = tokio::spawn(async move {
        axum::serve(up_listener, app).await.unwrap();
    });
    let mut config = GatewayConfig {
        state_dir: dir.path().join("private"),
        base_url: format!("http://{upstream_addr}/backend-api/codex"),
        allow_insecure_http: true,
        ..GatewayConfig::default()
    };
    config.telemetry.official_metrics_enabled = false;
    config.accounts = vec![AccountConfig {
        id: "alpha".into(),
        auth_path,
        proxy: None,
        enabled: true,
    }];
    let accounts = AccountPool::from_config(&config).unwrap();
    let state = AppState::new(config, accounts);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = right_codex::auxiliary::router().with_state(state);
    let gw_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let canonical = json!({"installation_id":"CLIENT_INSTALL_SECRET","session_id":"CLIENT_SESSION_SECRET",
        "thread_id":"CLIENT_THREAD_SECRET","turn_id":"CLIENT_TURN_SECRET",
        "window_id":"CLIENT_WINDOW_SECRET","tool_namespaces_info":{"functions":{"functions":{}}}});
    let input = json!({"id":"CLIENT_SEARCH_SECRET","model":"gpt-test","input":"find this"});
    let response = client
        .post(format!("http://{addr}/v1/alpha/search"))
        .header("x-codex-turn-metadata", canonical.to_string())
        .header("originator", "CLIENT_ORIGIN_SECRET")
        .header(header::USER_AGENT, "CLIENT_UA_SECRET")
        .json(&input)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await.unwrap()["output"], "found");
    for (metadata, body) in [
        ("not-json".to_owned(), input.clone()),
        (
            canonical.to_string(),
            json!({"id":"search","model":"gpt-test","input":"find this","client_metadata":{}}),
        ),
    ] {
        let response = client
            .post(format!("http://{addr}/v1/alpha/search"))
            .header("x-codex-turn-metadata", metadata)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let received = received.0.lock().unwrap();
    assert_eq!(received.len(), 1);
    let (_, headers, body) = &received[0];
    assert!(!body.to_string().contains("CLIENT_"));
    assert!(!body.as_object().unwrap().contains_key("client_metadata"));
    let projected: Value =
        serde_json::from_str(headers["x-codex-turn-metadata"].to_str().unwrap()).unwrap();
    assert_eq!(
        projected["tool_namespaces_info"],
        canonical["tool_namespaces_info"]
    );
    assert_ne!(projected["turn_id"], canonical["turn_id"]);
    assert_ne!(projected["thread_id"], canonical["thread_id"]);
    for value in headers.values() {
        assert!(!value.to_str().unwrap().contains("CLIENT_"));
    }
    up_task.abort();
    gw_task.abort();
}

#[tokio::test]
async fn official_auxiliary_requests_use_selected_oauth_account_and_private_http_terminal() {
    let dir = TempDir::new().unwrap();
    let auth_path = dir.path().join("auth.json");
    auth(&auth_path);
    let received = Arc::new(Received::default());
    let upstream = Router::new()
        .route("/backend-api/codex/models", get(upstream))
        .route("/backend-api/codex/alpha/search", post(upstream))
        .route("/backend-api/codex/images/generations", post(upstream))
        .route("/backend-api/codex/images/edits", post(upstream))
        .route("/backend-api/codex/realtime/calls", post(realtime_upstream))
        .with_state(received.clone());
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = up_listener.local_addr().unwrap();
    let up_task = tokio::spawn(async move {
        axum::serve(up_listener, upstream).await.unwrap();
    });
    let mut config = GatewayConfig {
        state_dir: dir.path().join("private"),
        base_url: format!("http://{upstream_addr}/backend-api/codex"),
        chatgpt_base_url: format!("http://{upstream_addr}/backend-api"),
        allow_insecure_http: true,
        ..GatewayConfig::default()
    };
    config.telemetry.official_metrics_enabled = false;
    config.accounts = vec![AccountConfig {
        id: "alpha".into(),
        auth_path,
        proxy: None,
        enabled: true,
    }];
    let accounts = AccountPool::from_config(&config).unwrap();
    let state = AppState::new(config, accounts);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = right_codex::auxiliary::router().with_state(state.clone());
    let gw_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let catalog: Value = client
        .get(format!("http://{addr}/v1/models?client_version=0.160.0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(catalog["future_catalog_field"]["kept"], true);
    let search: Value = client
        .post(format!("http://{addr}/v1/alpha/search"))
        .header("thread-id", "client-conversation")
        .header(header::AUTHORIZATION, "Bearer client-only-oauth")
        .header(header::USER_AGENT, "third-party-user-agent")
        .json(&json!({"id":"client-search-id","model":"gpt-test","input":"find this"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search["output"], "found");
    assert_eq!(search["future_search_field"]["source"], "upstream");
    let image: Value = client
        .post(format!("http://{addr}/v1/images/generations"))
        .header("thread-id", "client-conversation")
        .json(&json!({"model":"image-test","prompt":"draw this"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(image["data"][0]["b64_json"], PNG_B64);
    assert!(
        image["data"][0]["generation_id"]
            .as_str()
            .unwrap()
            .starts_with("gen_")
    );
    assert_ne!(image["data"][0]["generation_id"], "gen_real");
    assert_eq!(image["data"][0]["future_data_field"], "kept");
    assert_eq!(image["future_image_field"]["source"], "upstream");
    let edit: Value = client
        .post(format!("http://{addr}/v1/images/edits"))
        .header("thread-id", "client-conversation")
        .json(&json!({"model":"image-test","prompt":"edit this",
            "images":[{"file_id":image["data"][0]["generation_id"]}]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(edit["future_image_field"]["source"], "upstream");
    let blocked_call = client
        .post(format!("http://{addr}/v1/realtime/calls"))
        .header("thread-id", "client-conversation")
        .header(header::CONTENT_TYPE, "application/sdp")
        .body("v=0\r\na=offer\r\n")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked_call.status(), StatusCode::NOT_IMPLEMENTED);
    let error: Value = blocked_call.json().await.unwrap();
    assert_eq!(
        error["error"]["code"],
        "native_realtime_sideband_bypasses_gateway"
    );
    let blocked_live = client
        .post(format!("http://{addr}/v1/live"))
        .header("thread-id", "client-conversation")
        .header(header::CONTENT_TYPE, "application/sdp")
        .body("v=0\r\na=offer\r\n")
        .send()
        .await
        .unwrap();
    assert_eq!(blocked_live.status(), StatusCode::NOT_IMPLEMENTED);

    // This call uses a controlled SDK client. The public gateway routes above
    // still refuse to create a call without an account-scoped sideband path.
    let account = state.accounts.next_enabled().unwrap().unwrap();
    let source = RealtimeSessionConfig {
        instructions: "Speak briefly".into(),
        initial_items: Vec::new(),
        delegation_ack_filler: Some(false),
        model: Some("realtime-test".into()),
        session_id: None,
        event_parser: RealtimeEventParser::FramelessBidi,
        session_mode: RealtimeSessionMode::Conversational,
        output_modality: RealtimeOutputModality::Audio,
        voice: RealtimeVoice::Alloy,
    };
    let session_wire = codex_api::session_update_session_json(source).unwrap();
    let projected = project_realtime_session(&session_wire, &Uuid::new_v4().to_string()).unwrap();
    let identity = OutboundIdentity {
        account_id: account.id().to_owned(),
        workspace_account_id: account.workspace_account_id().to_owned(),
        auth_revision: account.revision().to_owned(),
        thread_id: Uuid::new_v4().to_string(),
        turn_id: Uuid::new_v4().to_string(),
        attempt_id: Uuid::new_v4().to_string(),
        endpoint: "/realtime/calls".into(),
    };
    let telemetry = state
        .metrics
        .for_account(&account, identity.clone(), "realtime-test", "realtime-test")
        .unwrap();
    let provider = Provider {
        name: "OpenAI".into(),
        base_url: state.config.base_url.clone(),
        query_params: None,
        headers: HeaderMap::new(),
        retry: RetryConfig {
            max_attempts: 0,
            base_delay: Duration::from_millis(1),
            retry_429: false,
            retry_5xx: false,
            retry_transport: false,
        },
        stream_idle_timeout: Duration::from_secs(5),
    };
    let sdk = AuxiliaryClient::new(
        &account,
        provider,
        state.ledger.clone(),
        identity,
        telemetry,
    );
    let created = sdk
        .create_realtime_call("v=0\r\na=offer\r\n".into(), Some(projected))
        .await
        .unwrap();
    assert_eq!(created.call_id, "rtc_upstream");
    assert_eq!(created.sdp, "v=0\r\na=answer\r\n");
    sdk.finish(true).unwrap();
    let calls = received.0.lock().unwrap();
    assert_eq!(calls.len(), 5);
    for (_, headers, _) in calls.iter() {
        assert_eq!(
            headers[header::AUTHORIZATION],
            "Bearer synthetic-oauth-secret"
        );
        assert_eq!(headers["chatgpt-account-id"], "workspace-alpha");
    }
    for (_, headers, _) in calls.iter().take(4) {
        assert_ne!(headers[header::USER_AGENT], "third-party-user-agent");
    }
    assert_eq!(
        calls[0].0,
        "/backend-api/codex/models?client_version=0.160.0"
    );
    assert_eq!(calls[1].2["input"], "find this");
    assert_ne!(calls[1].2["id"], "client-search-id");
    assert_eq!(calls[3].0, "/backend-api/codex/images/edits");
    assert_eq!(
        calls[3].2["images"][0]["image_url"],
        format!("data:image/png;base64,{PNG_B64}")
    );
    assert!(!calls[3].2.to_string().contains("gen_real"));
    assert!(calls[4].0.starts_with("/backend-api/codex/realtime/calls?"));
    assert!(calls[4].0.contains("intent=quicksilver"));
    let call_wire: Value = serde_json::from_str(calls[4].2.as_str().unwrap()).unwrap();
    assert_eq!(call_wire["sdp"], "v=0\r\na=offer\r\n");
    assert_eq!(call_wire["session"], session_wire);
    drop(calls);
    let facts = state.ledger.snapshot("alpha").unwrap();
    assert_eq!(facts.len(), 5);
    assert!(
        facts
            .iter()
            .all(|fact| fact.terminal == Some(TerminalKind::HttpCompleted))
    );
    up_task.abort();
    gw_task.abort();
}

#[tokio::test]
async fn oauth_realtime_sideband_is_fenced_before_account_or_upstream() {
    let response = right_codex::auxiliary::router().with_state({
        let dir = TempDir::new().unwrap();
        let config = GatewayConfig {
            state_dir: dir.path().join("private"),
            ..GatewayConfig::default()
        };
        AppState::new(config.clone(), AccountPool::from_config(&config).unwrap())
    });
    use tower::ServiceExt;
    let result = response
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(result.into_body(), 4096)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["error"]["code"],
        "native_realtime_sideband_bypasses_gateway"
    );
}

#[tokio::test]
async fn native_images_turn_only_header_resolves_registered_scope_and_keeps_alias_owner() {
    let dir = TempDir::new().unwrap();
    let auth_path = dir.path().join("auth.json");
    auth(&auth_path);
    let received = Arc::new(Received::default());
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = up_listener.local_addr().unwrap();
    let app = Router::new()
        .route("/backend-api/codex/images/generations", post(upstream))
        .route("/backend-api/codex/images/edits", post(upstream))
        .with_state(received.clone());
    let up_task = tokio::spawn(async move {
        axum::serve(up_listener, app).await.unwrap();
    });
    let mut config = GatewayConfig {
        state_dir: dir.path().join("private"),
        base_url: format!("http://{upstream_addr}/backend-api/codex"),
        allow_insecure_http: true,
        ..GatewayConfig::default()
    };
    config.telemetry.official_metrics_enabled = false;
    config.accounts = vec![AccountConfig {
        id: "alpha".into(),
        auth_path,
        proxy: None,
        enabled: true,
    }];
    let accounts = AccountPool::from_config(&config).unwrap();
    let state = AppState::new(config, accounts);
    let domain: Value =
        serde_json::from_slice(&std::fs::read(state.config.state_dir.join("domain.json")).unwrap())
            .unwrap();
    let mut source_headers = HeaderMap::new();
    source_headers.insert(
        "chatgpt-account-id",
        "CLIENT_WORKSPACE_SECRET".parse().unwrap(),
    );
    let namespace =
        right_codex::admission::local_principal(&source_headers, domain["id"].as_str().unwrap());
    let client_turn = "CLIENT_NATIVE_IMAGE_TURN_SECRET";
    let mut digest = Sha256::new();
    digest.update(namespace.len().to_be_bytes());
    digest.update(namespace.as_bytes());
    digest.update(client_turn.as_bytes());
    let bytes = digest.finalize();
    let logical_turn = Uuid::from_bytes(bytes[..16].try_into().unwrap()).to_string();
    let account = state.accounts.by_id("alpha").unwrap().unwrap();
    let register = |thread: &str| {
        let mut session = Session::new(account.id().into(), account.revision().into());
        let prepared = session
            .prepare_request(
                json!({"model":"gpt-test","input":[{"role":"user","content":"draw this"}],
            "client_metadata":{"thread_id":thread,"turn_id":client_turn}}),
                &HeaderMap::new(),
                &logical_turn,
            )
            .unwrap();
        let scoped = session.commit_request(prepared).unwrap();
        session.mark_sending(&scoped.attempt_id).unwrap();
        let mut completed = json!({"type":"response.completed","response":{"id":"actual-fixture-response","output":[{
            "type":"message","id":"actual-fixture-message","role":"assistant","content":[{"type":"output_text","text":"image tool selected"}]}]}});
        session.rewrite_event(&mut completed).unwrap();
        session
            .finish_attempt(&scoped.attempt_id, &completed)
            .unwrap();
        let key = right_codex::session::SessionStore::local_key(&namespace, thread);
        right_codex::storage::save(&state.config.state_dir.join("sessions"), &key, &session)
            .unwrap();
        state.sessions.insert_restored(key, session).unwrap();
        scoped.upstream_turn_id
    };
    let upstream_turn = register("CLIENT_NATIVE_THREAD_SECRET");
    assert_ne!(upstream_turn, client_turn);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = right_codex::auxiliary::router().with_state(state.clone());
    let gw_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    // Exact native image extension source: a turn header and no canonical,
    // thread-id or client_metadata. OAuth account header remains local.
    let generated = client
        .post(format!("http://{addr}/v1/images/generations"))
        .header("chatgpt-account-id", "CLIENT_WORKSPACE_SECRET")
        .header("x-codex-image-turn-id", client_turn)
        .json(&json!({"model":"image-test","prompt":"draw this"}))
        .send()
        .await
        .unwrap();
    assert_eq!(generated.status(), StatusCode::OK);
    let image: Value = generated.json().await.unwrap();
    let alias = image["data"][0]["generation_id"].as_str().unwrap();
    assert_ne!(alias, "gen_real");
    let edited = client
        .post(format!("http://{addr}/v1/images/edits"))
        .header("chatgpt-account-id", "CLIENT_WORKSPACE_SECRET")
        .header("x-codex-image-turn-id", client_turn)
        .json(&json!({"model":"image-test","prompt":"edit this","images":[{"file_id":alias}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(edited.status(), StatusCode::OK);
    let edited_image: Value = edited.json().await.unwrap();
    let edited_alias = edited_image["data"][0]["generation_id"].as_str().unwrap();
    assert_ne!(edited_alias, "gen_real");
    assert_ne!(edited_alias, alias);
    let edited_again = client
        .post(format!("http://{addr}/v1/images/edits"))
        .header("chatgpt-account-id", "CLIENT_WORKSPACE_SECRET")
        .header("x-codex-image-turn-id", client_turn)
        .json(&json!({"model":"image-test","prompt":"edit again","images":[{"file_id":edited_alias}]}))
        .send().await.unwrap();
    assert_eq!(edited_again.status(), StatusCode::OK);
    for (workspace, turn) in [
        ("OTHER_CLIENT_WORKSPACE", client_turn),
        ("CLIENT_WORKSPACE_SECRET", "unknown-turn"),
    ] {
        let rejected = client
            .post(format!("http://{addr}/v1/images/generations"))
            .header("chatgpt-account-id", workspace)
            .header("x-codex-image-turn-id", turn)
            .json(&json!({"model":"image-test","prompt":"draw this"}))
            .send()
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    }
    register("second-private-thread");
    let ambiguous = client
        .post(format!("http://{addr}/v1/images/generations"))
        .header("chatgpt-account-id", "CLIENT_WORKSPACE_SECRET")
        .header("x-codex-image-turn-id", client_turn)
        .json(&json!({"model":"image-test","prompt":"draw this"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ambiguous.status(), StatusCode::BAD_REQUEST);
    {
        let requests = received.0.lock().unwrap();
        assert_eq!(requests.len(), 3);
        for (_, headers, body) in requests.iter() {
            assert_eq!(
                headers["x-codex-image-turn-id"].to_str().unwrap(),
                upstream_turn
            );
            assert!(!headers.contains_key("x-codex-turn-metadata"));
            assert!(!body.to_string().contains("CLIENT_"));
            for value in headers.values() {
                assert!(!value.to_str().unwrap().contains("CLIENT_"));
            }
        }
        assert!(
            requests[1].2["images"][0]["image_url"]
                .as_str()
                .unwrap()
                .starts_with("data:image/png;base64,")
        );
    }
    let facts = state.ledger.snapshot("alpha").unwrap();
    assert_eq!(facts.len(), 3);
    assert!(
        facts
            .iter()
            .all(|fact| fact.identity.turn_id == upstream_turn
                && fact.terminal == Some(TerminalKind::HttpCompleted))
    );
    up_task.abort();
    gw_task.abort();
}

// Error passthrough fixtures use private synthetic Pro OAuth tokens and
// loopback endpoints. Each client request authorizes one upstream send.
struct RecoveryFixture {
    _directory: TempDir,
    state: Arc<AppState>,
    received: Arc<Received>,
    client: reqwest::Client,
    address: std::net::SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for RecoveryFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn recovery_jwt(account: &str) -> String {
    use base64::Engine;
    let encode = |v: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
    };
    format!(
        "{}.{}.fixture",
        encode(json!({"alg":"none"})),
        encode(json!({
        "email":"fixture@example.invalid","exp":3000000000_u64,
        "https://api.openai.com/auth":{"chatgpt_account_id":format!("workspace-{account}"),
        "chatgpt_user_id":format!("user-{account}"),"chatgpt_plan_type":"pro"}}))
    )
}
fn recovery_reply(status: StatusCode, value: Value) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}
fn recovery_success(path: &str) -> Value {
    if path.ends_with("/models") {
        json!({"models":[]})
    } else if path.ends_with("/alpha/search") {
        json!({"output":"found","encrypted_output":null,"results":[]})
    } else {
        json!({"created":1,"data":[{"b64_json":PNG_B64,"generation_id":"gen_fixture"}]})
    }
}
async fn recovery_fixture<F>(ids: &[&str], handler: F) -> RecoveryFixture
where
    F: Fn(&str, &HeaderMap, &Value, usize) -> axum::response::Response + Send + Sync + 'static,
{
    let directory = TempDir::new().unwrap();
    let received = Arc::new(Received::default());
    let captured = received.clone();
    let handler = Arc::new(handler);
    let upstream = Router::new().fallback(move |request: axum::extract::Request| {
        let captured = captured.clone();
        let handler = handler.clone();
        async move {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let path = parts.uri.path();
            let ordinal = {
                let mut calls = captured.0.lock().unwrap();
                let n = calls.len();
                calls.push((parts.uri.to_string(), parts.headers.clone(), body.clone()));
                n
            };
            handler(path, &parts.headers, &body, ordinal)
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let up_task = tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });
    let mut config = GatewayConfig {
        state_dir: directory.path().join("private"),
        base_url: format!("http://{upstream_addr}/backend-api/codex"),
        oauth_issuer: format!("http://{upstream_addr}"),
        allow_insecure_http: true,
        max_attempts: 3,
        ..GatewayConfig::default()
    };
    config.telemetry.official_metrics_enabled = false;
    config.scheduling.startup_spacing_secs = 0;
    config.accounts = ids
        .iter()
        .map(|id| {
            let auth_path = directory.path().join(format!("{id}.json"));
            std::fs::write(
                &auth_path,
                json!({"auth_mode":"chatgpt","tokens":{
            "id_token":recovery_jwt(id),"access_token":format!("access-{id}"),
            "refresh_token":format!("refresh-{id}"),"account_id":format!("workspace-{id}")},
            "last_refresh":"2026-10-10T00:00:00Z"})
                .to_string(),
            )
            .unwrap();
            AccountConfig {
                id: (*id).into(),
                auth_path,
                proxy: None,
                enabled: true,
            }
        })
        .collect();
    let accounts = AccountPool::from_config(&config).unwrap();
    let state = AppState::new(config, accounts);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = right_codex::auxiliary::router().with_state(state.clone());
    let gw_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    RecoveryFixture {
        _directory: directory,
        state,
        received,
        address,
        client: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        tasks: vec![up_task, gw_task],
    }
}
fn policy_request(fixture: &RecoveryFixture, endpoint: &str) -> reqwest::RequestBuilder {
    let url = format!("http://{}/v1/{endpoint}", fixture.address);
    let request = if endpoint == "models" {
        fixture.client.get(url)
    } else {
        fixture
            .client
            .post(url)
            .json(&if endpoint == "alpha/search" {
                json!({"id":"client-search","model":"test","input":"find"})
            } else if endpoint == "images/edits" {
                json!({"model":"test","prompt":"draw","images":[{"image_url":format!("data:image/png;base64,{PNG_B64}")}]})
            } else {
                json!({"model":"test","prompt":"draw"})
            })
    };
    request.header("thread-id", "native-auxiliary-policy-thread")
}

#[tokio::test]
async fn auxiliary_401_returns_original_error_disables_owner_and_never_refreshes() {
    for endpoint in [
        "alpha/search",
        "images/generations",
        "images/edits",
        "models",
    ] {
        let fixture = recovery_fixture(&["alpha","beta"], |path,headers,_,_| {
            assert_ne!(path, "/oauth/token", "401 must not refresh OAuth tokens");
            match headers[header::AUTHORIZATION].to_str().unwrap() {
                "Bearer access-alpha" => recovery_reply(StatusCode::UNAUTHORIZED,
                    json!({"error":{"code":"invalid_token","message":"原始 token expired","type":"authentication_error"}})),
                "Bearer access-beta" => recovery_reply(StatusCode::OK,recovery_success(path)),
                _ => panic!("unexpected account"),
            }
        }).await;
        let source_path = fixture.state.config.accounts[0].auth_path.clone();
        let source_before = std::fs::read(&source_path).unwrap();
        let response = policy_request(&fixture, endpoint).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{endpoint}");
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({"error":{
            "code":"invalid_token","message":"原始 token expired","type":"authentication_error"}})
        );
        assert_eq!(fixture.received.0.lock().unwrap().len(), 1);
        assert_eq!(std::fs::read(source_path).unwrap(), source_before);
        assert!(
            fixture
                .state
                .accounts
                .lease("alpha", false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fixture.state.ledger.snapshot("alpha").unwrap()[0].terminal,
            Some(TerminalKind::Failed)
        );
        assert!(fixture.state.ledger.snapshot("beta").unwrap().is_empty());
        // Only this later client request permits selecting a new account.
        assert_eq!(
            policy_request(&fixture, endpoint)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let calls = fixture.received.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[header::AUTHORIZATION], "Bearer access-alpha");
        assert_eq!(calls[1].1[header::AUTHORIZATION], "Bearer access-beta");
    }
}

#[tokio::test]
async fn auxiliary_429_with_reset_returns_once_and_cools_only_failed_account() {
    for endpoint in [
        "alpha/search",
        "images/generations",
        "images/edits",
        "models",
    ] {
        let fixture = recovery_fixture(&["alpha", "beta"], |path, headers, _, _| {
            assert_ne!(path, "/oauth/token");
            if headers[header::AUTHORIZATION] == "Bearer access-beta" {
                recovery_reply(StatusCode::OK, recovery_success(path))
            } else {
                let mut response = recovery_reply(StatusCode::TOO_MANY_REQUESTS,
                    json!({"error":{"code":"usage_limit_reached","message":"wait upstream window","resets_in_seconds":120}}));
                response.headers_mut().insert("retry-after", "120".parse().unwrap());
                response.headers_mut().insert("x-request-id", "private-upstream-id".parse().unwrap());
                response
            }
        }).await;
        let response = policy_request(&fixture, endpoint).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "120");
        assert!(!response.headers().contains_key("x-request-id"));
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({"error":{
            "code":"usage_limit_reached","message":"wait upstream window","resets_in_seconds":120}})
        );
        assert_eq!(fixture.received.0.lock().unwrap().len(), 1);
        assert!(
            fixture
                .state
                .accounts
                .by_id("alpha")
                .unwrap()
                .unwrap()
                .availability()
                .unwrap()
                .quota_cooldown
        );
        assert!(
            !fixture
                .state
                .accounts
                .by_id("beta")
                .unwrap()
                .unwrap()
                .availability()
                .unwrap()
                .quota_cooldown
        );
        assert!(fixture.state.ledger.snapshot("beta").unwrap().is_empty());
        assert_eq!(
            policy_request(&fixture, endpoint)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let calls = fixture.received.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[header::AUTHORIZATION], "Bearer access-alpha");
        assert_eq!(calls[1].1[header::AUTHORIZATION], "Bearer access-beta");
    }
}

#[tokio::test]
async fn auxiliary_errors_preserve_json_non_utf8_and_empty_bodies_without_replay() {
    for (status, body, content_type) in [
        (
            StatusCode::FORBIDDEN,
            br#"{ "error": {"code":"access_denied", "message":"source wording"} }"#.to_vec(),
            "application/json",
        ),
        (
            StatusCode::CONFLICT,
            b"upstream is busy".to_vec(),
            "text/plain",
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            vec![0xff, 0, 0x80, 0x61],
            "application/octet-stream",
        ),
        (StatusCode::TOO_MANY_REQUESTS, Vec::new(), "text/plain"),
    ] {
        let original = body.clone();
        let fixture = recovery_fixture(&["alpha", "beta"], move |_, _, _, _| {
            axum::response::Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body.clone()))
                .unwrap()
        })
        .await;
        let response = policy_request(&fixture, "models").send().await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            original.as_slice()
        );
        assert_eq!(fixture.received.0.lock().unwrap().len(), 1);
        assert!(
            !fixture
                .state
                .accounts
                .by_id("alpha")
                .unwrap()
                .unwrap()
                .availability()
                .unwrap()
                .quota_cooldown
        );
        assert!(
            fixture
                .state
                .accounts
                .lease("alpha", false)
                .unwrap()
                .is_some()
        );
        assert!(fixture.state.ledger.snapshot("beta").unwrap().is_empty());
    }
}

#[tokio::test]
async fn auxiliary_incomplete_429_body_is_unknown_and_never_refreshes_or_rotates() {
    // Deliberately send a real partial HTTP response and close the socket.
    // Keep the status and observed prefix, then propagate an incomplete body.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut bytes = [0u8; 16384];
            let _ = stream.read(&mut bytes).await.unwrap();
            stream.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: 2000\r\nConnection: close\r\n\r\n{\"error\":").await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let fixture = recovery_fixture(&["alpha", "beta"], |_, _, _, _| {
        panic!("unexpected fixture request")
    })
    .await;
    // Account revision must be built against this actual partial endpoint.
    let mut config = fixture.state.config.clone();
    config.state_dir = fixture._directory.path().join("partial-private");
    config.base_url = format!("http://{upstream_addr}/backend-api/codex");
    config.oauth_issuer = format!("http://{upstream_addr}");
    let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = right_codex::auxiliary::router().with_state(state.clone());
    let gw_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = fixture
        .client
        .post(format!("http://{addr}/v1/alpha/search"))
        .header("thread-id", "native-search-thread")
        .json(&json!({"id":"search","model":"test","input":"find"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let mut response = response;
    let mut prefix = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => prefix.extend_from_slice(&chunk),
            Err(_) => break,
            Ok(None) => panic!("truncated body must stay incomplete"),
        }
    }
    assert_eq!(prefix, br#"{"error":"#);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        state.ledger.snapshot("alpha").unwrap()[0].terminal,
        Some(TerminalKind::Unknown)
    );
    assert!(state.ledger.snapshot("beta").unwrap().is_empty());
    assert!(
        !state
            .accounts
            .by_id("alpha")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown
    );
    task.abort();
    gw_task.abort();
}

#[tokio::test]
async fn search_quota_returns_once_then_next_request_rejects_foreign_click_reference() {
    let fixture = recovery_fixture(&["alpha","beta"], |path,headers,body,ordinal| {
        assert!(path.ends_with("/alpha/search"));
        assert_eq!(headers[header::AUTHORIZATION],"Bearer access-alpha");
        if ordinal == 0 {
            recovery_reply(StatusCode::OK,json!({"output":"found","encrypted_output":"cipher-only-first-account",
                "results":[{"ref_id":"raw-first-account-ref","url":"https://example.invalid/page"}]}))
        } else {
            assert_eq!(body["commands"]["click"][0]["ref_id"],"raw-first-account-ref");
            recovery_reply(StatusCode::TOO_MANY_REQUESTS,json!({"error":{"code":"usage_limit_reached","resets_in_seconds":120}}))
        }
    }).await;
    let url = format!("http://{}/v1/alpha/search", fixture.address);
    let first: Value = fixture
        .client
        .post(&url)
        .header("thread-id", "search-reference-thread")
        .json(&json!({"id":"search","model":"test","input":"find"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alias = first["results"][0]["ref_id"].as_str().unwrap();
    let response = fixture
        .client
        .post(&url)
        .header("thread-id", "search-reference-thread")
        .json(&json!({"id":"search","model":"test","input":"find",
            "commands":{"click":[{"ref_id":alias,"id":1}]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let response = fixture
        .client
        .post(&url)
        .header("thread-id", "search-reference-thread")
        .json(&json!({"id":"search","model":"test","input":"find",
            "commands":{"click":[{"ref_id":alias,"id":1}]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fixture.received.0.lock().unwrap().len(), 2);
    assert_eq!(fixture.state.ledger.snapshot("alpha").unwrap().len(), 2);
    assert!(fixture.state.ledger.snapshot("beta").unwrap().is_empty());
}
