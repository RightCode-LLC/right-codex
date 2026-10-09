//! Synthetic protocol/control fixtures; these do not claim live Pro acceptance.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use codex_api::{AuthProvider, Compression, Provider, ResponsesClient, RetryConfig};
use codex_client::{HttpTransport, Request, Response, StreamResponse, TransportError};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use right_codex::metadata::CANONICAL_METADATA;
use right_codex::protocol::IdentityKind;
use right_codex::response_projection::{project_response_headers, sanitize_http_error};
use right_codex::session::Session;
use serde_json::{Value, json};

fn controls() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("openai-model", "server-model"),
        ("x-reasoning-included", "false"),
        ("x-models-etag", "models-revision-17"),
        ("etag", "catalog-revision-17"),
        ("retry-after", "7"),
        ("x-codex-primary-used-percent", "42"),
        ("x-codex-primary-window-minutes", "300"),
        ("x-codex-primary-reset-at", "2000000000"),
        ("x-codex-secondary-used-percent", "12"),
        ("x-codex-secondary-window-minutes", "10080"),
        ("x-codex-secondary-reset-at", "2000100000"),
        ("x-codex-other-primary-used-percent", "32"),
        ("x-codex-other-primary-window-minutes", "300"),
        ("x-codex-other-primary-reset-at", "2000000001"),
        ("x-codex-other-limit-name", "Other model allowance"),
        ("x-codex-credits-has-credits", "true"),
        ("x-codex-credits-unlimited", "false"),
        ("x-codex-credits-balance", "4.50"),
        ("x-codex-promo-message", "Business notice"),
        ("x-codex-rate-limit-reached-type", "rate_limit"),
        ("x-codex-safety-buffering-enabled", "false"),
        ("x-codex-safety-buffering-faster-model", "retry-model"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers
}

fn add_private_headers(headers: &mut HeaderMap) {
    for name in [
        "x-request-id",
        "request-id",
        "cf-ray",
        "x-codex-turn-state",
        "chatgpt-account-id",
        "openai-organization",
        "x-route-id",
        "set-cookie",
        "x-codex-other-request-id",
        "x-codex-future-identity",
        "x-private-route-limit-name",
        "traceparent",
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("upstream-private"),
        );
    }
}

#[test]
fn transport_headers_preserve_business_controls_without_prefix_passthrough() {
    let expected = controls();
    let mut upstream = expected.clone();
    add_private_headers(&mut upstream);
    upstream.append(
        "x-codex-primary-used-percent",
        HeaderValue::from_static("43"),
    );
    let mut expected = expected;
    expected.append(
        "x-codex-primary-used-percent",
        HeaderValue::from_static("43"),
    );
    assert_eq!(project_response_headers(&upstream), expected);
}

#[test]
fn metadata_and_nested_error_headers_share_projection_and_keep_safety_semantics() {
    let mut session = Session::new("alpha".into(), "revision-one".into());
    let headers = json!({
        "X-Request-Id":"private-request", "CF-Ray":"private-ray",
        "X-Codex-Turn-State":"private-sticky", "ChatGPT-Account-Id":"private-account",
        "OpenAI-Model":[["server-model"],"unconsumed"],
        "X-Codex-Primary-Used-Percent":42,
        "X-Codex-Safety-Buffering-Enabled":false,
        "X-Codex-Safety-Buffering-Faster-Model":"retry-model",
        "X-Models-Etag":"business-etag", "retry-after":7,
        "x-codex-other-request-id":"private-route",
        "x-openai-model":{"nested":"not-a-header"}
    });
    let expected = json!({
        "OpenAI-Model":"server-model", "X-Codex-Primary-Used-Percent":42,
        "X-Codex-Safety-Buffering-Enabled":false,
        "X-Codex-Safety-Buffering-Faster-Model":"retry-model",
        "X-Models-Etag":"business-etag", "retry-after":7
    });
    for kind in ["codex.response.metadata", "response.metadata", "error"] {
        let metadata = json!({
            "openai_verification_recommendation":["trusted_access_for_cyber"],
            "openai_chatgpt_moderation_metadata":{"risk":"cyber","message":"request_id private-request"},
            "type":"safety_buffering", "use_cases":["cyber"], "reasons":["user_risk"],
            "request_id":"private-request", "headers":headers
        });
        let mut event = json!({"type":kind,"headers":headers,"metadata":metadata,
            "response":{"id":"response-private","headers":headers,
                "error":{"headers":headers,"code":"rate_limit_exceeded","message":"private-request"}},
            "error":{"headers":headers,"code":"quota_exceeded","message":"private-account"}});
        session.rewrite_event(&mut event).unwrap();
        for path in [
            "/headers",
            "/metadata/headers",
            "/response/headers",
            "/response/error/headers",
            "/error/headers",
        ] {
            assert_eq!(event.pointer(path).unwrap(), &expected);
        }
        assert!(event["metadata"].get("request_id").is_none());
        assert_eq!(
            event["metadata"]["openai_chatgpt_moderation_metadata"],
            metadata["openai_chatgpt_moderation_metadata"]
        );
        assert_eq!(
            event["metadata"]["openai_verification_recommendation"],
            metadata["openai_verification_recommendation"]
        );
        assert_eq!(event["response"]["error"]["message"], "private-request");
        assert_eq!(event["error"]["message"], "private-account");
    }
}

#[test]
fn http_failure_removes_only_structured_envelope_identities() {
    let prose = "request_id=req-private; account_id=account-private; /Users/example/resp-private";
    let mut body = json!({"id":"error-private", "request_id":"req-private",
        "error":{"code":"usage_limit_reached","message":prose,"param":"response_id",
            "plan_type":"pro","resets_at":2000000000,"account_id":"account-private",
            "headers":{"x-request-id":"req-private","cf-ray":"ray-private","retry-after":12},
            "response":{"id":"resp-private","previous_response_id":"previous-private",
                "thread_id":"thread-private","error":{"request_id":"nested-private","message":prose},
                "output":[{"id":"item-private","call_id":"call-private","type":"function_call",
                    "arguments":json!({"request_id":"business-data"}).to_string()}]}},
        "instructions":prose,"input":[{"request_id":"business-data","text":prose}]});
    let input = body["input"].clone();
    let arguments = body["error"]["response"]["output"][0]["arguments"].clone();
    sanitize_http_error(&mut body);
    for path in [
        "/id",
        "/request_id",
        "/error/account_id",
        "/error/response/id",
        "/error/response/previous_response_id",
        "/error/response/thread_id",
        "/error/response/error/request_id",
        "/error/response/output/0/id",
        "/error/response/output/0/call_id",
    ] {
        assert!(
            body.pointer(path).is_none(),
            "unexpected identity at {path}"
        );
    }
    assert_eq!(body["error"]["headers"], json!({"retry-after":12}));
    assert_eq!(body["error"]["message"], prose);
    assert_eq!(body["error"]["response"]["error"]["message"], prose);
    assert_eq!(body["error"]["param"], "response_id");
    assert_eq!(body["error"]["plan_type"], "pro");
    assert_eq!(body["error"]["resets_at"], 2000000000_u64);
    assert_eq!(
        body["error"]["response"]["output"][0]["arguments"],
        arguments
    );
    assert_eq!(body["instructions"], prose);
    assert_eq!(body["input"], input);
}

#[test]
fn nested_native_aliases_reuse_session_mapping_and_are_rotated_per_account_revision() {
    let mut session = Session::new("alpha".into(), "revision-one".into());
    let original = json!({"type":"response.completed","response":{"id":"resp-source",
        "output":[{"type":"function_call","id":"item-source","call_id":"call-source",
            "name":"run","arguments":"{\"request_id\":\"literal\"}"}]}});
    let mut completed = original.clone();
    session.rewrite_event(&mut completed).unwrap();
    let item = completed["response"]["output"][0].clone();
    let mut error = json!({"type":"error","response_id":"resp-source","error":{
        "response_id":"resp-source","previous_response_id":"resp-source","item_id":"item-source",
        "call_id":"call-source","response":{"id":"resp-source"}}});
    session.rewrite_event(&mut error).unwrap();
    assert_eq!(error["response_id"], completed["response"]["id"]);
    assert_eq!(error["error"]["response_id"], completed["response"]["id"]);
    assert_eq!(
        error["error"]["previous_response_id"],
        completed["response"]["id"]
    );
    assert_eq!(
        error["error"]["response"]["id"],
        completed["response"]["id"]
    );
    assert_eq!(error["error"]["item_id"], item["id"]);
    assert_eq!(error["error"]["call_id"], item["call_id"]);
    let mut restored = Session::restore(session.snapshot().unwrap()).unwrap();
    let request = json!({"model":"gpt-test","input":[item,
        {"type":"function_call_output","call_id":error["error"]["call_id"],"output":"done"}]});
    let same_account = restored.build_request(request.clone(), "turn-two").unwrap();
    assert_eq!(same_account.body["input"][0]["id"], "item-source");
    assert_eq!(same_account.body["input"][0]["call_id"], "call-source");
    assert_eq!(same_account.body["input"][1]["call_id"], "call-source");
    for (account, revision) in [("alpha", "revision-two"), ("beta", "revision-one")] {
        let mut foreign = Session::restore(session.snapshot().unwrap()).unwrap();
        foreign
            .switch_account(account.into(), revision.into())
            .unwrap();
        assert!(!foreign.identifiers().contains_key(&(
            IdentityKind::Response,
            error["response_id"].as_str().unwrap().to_owned()
        )));
        let outgoing = foreign.build_request(request.clone(), "turn-two").unwrap();
        assert_ne!(outgoing.body["input"][0]["id"], "item-source");
        assert_ne!(outgoing.body["input"][0]["call_id"], "call-source");
        let mut next = original.clone();
        foreign.rewrite_event(&mut next).unwrap();
        assert_ne!(next["response"]["id"], completed["response"]["id"]);
    }
}

#[test]
fn text_and_arbitrary_tool_json_never_enter_the_identity_projection() {
    let content = json!({"request_id":"literal", "headers":{"x-request-id":"literal"},
        "response":{"id":"literal"}, "error":{"account_id":"literal"}});
    let mut event = json!({"type":"response.output_item.done", "request_id":"structured",
        "item":{"type":"tool_search_call","id":"item-source","call_id":null,"execution":"client",
            "arguments":content,"metadata":content},
        "delta":content.to_string(),"text":"request_id=structured /Users/example"});
    let original = event.clone();
    let mut session = Session::new("alpha".into(), "revision".into());
    session.rewrite_event(&mut event).unwrap();
    assert!(event.get("request_id").is_none());
    assert_ne!(event["item"]["id"], original["item"]["id"]);
    assert_eq!(event["item"]["arguments"], content);
    assert_eq!(event["item"]["metadata"], content);
    assert_eq!(event["delta"], original["delta"]);
    assert_eq!(event["text"], original["text"]);
}

#[test]
fn invalid_nested_reference_rolls_back_projection_and_alias_state_together() {
    let mut session = Session::new("alpha".into(), "revision".into());
    let before = session.snapshot().unwrap();
    let mut event = json!({"type":"error","request_id":"private","headers":{"cf-ray":"private"},
        "response_id":"new-response","error":{"response":{"id":"another-response"},"item_id":false}});
    let original = event.clone();
    assert!(session.rewrite_event(&mut event).is_err());
    assert_eq!(event, original);
    assert_eq!(session.snapshot().unwrap(), before);
}

#[test]
fn handshake_metadata_has_no_attempt_and_first_request_reuses_its_turn_alias() {
    let mut session = Session::new("alpha".into(), "revision".into());
    let input = json!({"model":"gpt-test","input":[],"client_metadata":{
        "x-codex-turn-metadata":json!({"request_kind":"turn","turn_id":"client-turn"}).to_string()}});
    let headers = session
        .prepare_handshake_metadata(&input, &HeaderMap::new(), "logical-turn", None)
        .unwrap();
    let canonical: Value =
        serde_json::from_str(headers[CANONICAL_METADATA].to_str().unwrap()).unwrap();
    assert!(
        session.snapshot().unwrap()["attempts"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(session.upstream_turn_for("logical-turn").is_none());
    let prepared = session
        .prepare_request(input, &HeaderMap::new(), "logical-turn")
        .unwrap();
    let scoped = session.commit_request(prepared).unwrap();
    assert_eq!(canonical["turn_id"], scoped.upstream_turn_id);
    assert_ne!(canonical["turn_id"], "client-turn");
    let before = session.snapshot().unwrap();
    assert!(
        session
            .prepare_handshake_metadata(&json!({}), &HeaderMap::new(), "", None)
            .is_err()
    );
    assert_eq!(session.snapshot().unwrap(), before);
}

struct FixtureTransport {
    headers: HeaderMap,
}
impl HttpTransport for FixtureTransport {
    async fn execute(&self, _: Request) -> Result<Response, TransportError> {
        panic!("stream only")
    }
    async fn stream(&self, _: Request) -> Result<StreamResponse, TransportError> {
        let events = [
            json!({"type":"response.metadata","safety_buffering":{"use_cases":["cyber"],"reasons":["user_risk"]},
                "metadata":{"openai_verification_recommendation":["trusted_access_for_cyber"]}}),
            json!({"type":"response.completed","response":{"id":"fixture-response","output":[]}}),
        ];
        let bytes = events
            .into_iter()
            .map(|event| Bytes::from(format!("data: {event}\n\n")))
            .map(Ok);
        Ok(StreamResponse {
            status: StatusCode::OK,
            headers: self.headers.clone(),
            bytes: Box::pin(futures_util::stream::iter(bytes)),
        })
    }
}
struct FixtureAuth;
impl AuthProvider for FixtureAuth {
    fn add_auth_headers(&self, _: &mut HeaderMap) {}
}

async fn official_control_events(
    headers: HeaderMap,
) -> (Vec<String>, Option<String>, Option<String>) {
    let client = ResponsesClient::new(
        FixtureTransport { headers },
        Provider {
            name: "fixture".into(),
            base_url: "https://fixture.invalid/backend-api/codex".into(),
            query_params: None,
            headers: HeaderMap::new(),
            retry: RetryConfig {
                max_attempts: 1,
                base_delay: Duration::ZERO,
                retry_429: false,
                retry_5xx: false,
                retry_transport: false,
            },
            stream_idle_timeout: Duration::from_secs(1),
        },
        Arc::new(FixtureAuth),
    );
    let sticky = Arc::new(OnceLock::new());
    let mut stream = client
        .stream(
            json!({"model":"gpt-test","input":[]}),
            HeaderMap::new(),
            Compression::None,
            Some(sticky.clone()),
        )
        .await
        .unwrap();
    let request_id = stream.upstream_request_id.clone();
    let mut events = Vec::new();
    while let Some(event) = stream.rx_event.recv().await {
        events.push(format!("{:?}", event.unwrap()));
    }
    (events, request_id, sticky.get().cloned())
}

#[tokio::test]
async fn pinned_official_consumer_observes_the_same_business_controls_after_projection() {
    let mut raw = controls();
    add_private_headers(&mut raw);
    let direct = official_control_events(raw.clone()).await;
    let projected = official_control_events(project_response_headers(&raw)).await;
    assert_eq!(direct.0, projected.0);
    for expected in [
        "ServerModel",
        "ServerReasoningIncluded(true)",
        "ModelsEtag",
        "RateLimits",
        "codex_other",
        "SafetyBuffering",
        "retry-model",
        "ModelVerifications",
    ] {
        assert!(
            projected.0.iter().any(|event| event.contains(expected)),
            "missing official event {expected}"
        );
    }
    assert_eq!(direct.1.as_deref(), Some("upstream-private"));
    assert_eq!(direct.2.as_deref(), Some("upstream-private"));
    assert_eq!(projected.1, None);
    assert_eq!(projected.2, None);
}
