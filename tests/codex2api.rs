//! Server-side compatibility checks for Codex2API management. All credentials,
//! OAuth responses, proxies and account profiles are isolated loopback fixtures.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
    response::Response,
};
use base64::Engine;
use right_codex::{
    accounts::AccountPool,
    config::GatewayConfig,
    gateway::{AppState, router},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::sync::{Notify, Semaphore};
use tower::ServiceExt;

const KEY: &str = "fixture-codex2api-admin";
const GENERATE: &str = "/api/admin/oauth/generate-auth-url";
const EXCHANGE: &str = "/api/admin/oauth/exchange-code";
const ACCOUNTS: &str = "/api/admin/accounts?view=lite&channel=codex";

struct Seen {
    path: String,
    headers: HeaderMap,
    form: HashMap<String, String>,
}
struct Reply {
    status: StatusCode,
    body: Value,
    release: Option<Arc<Semaphore>>,
}
impl Reply {
    fn account(workspace: &str, bearer: &str) -> Self {
        Self {
            status: StatusCode::OK,
            body: tokens(workspace, bearer, "pro"),
            release: None,
        }
    }
}
struct Authority {
    seen: Mutex<Vec<Seen>>,
    replies: Mutex<VecDeque<Reply>>,
    entered: Notify,
}
struct Fixture {
    _dir: TempDir,
    config: GatewayConfig,
    state: Arc<AppState>,
    authority: Arc<Authority>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new(replies: Vec<Reply>) -> Self {
        let authority = Arc::new(Authority {
            seen: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
            entered: Notify::new(),
        });
        let captured = authority.clone();
        let app = Router::new().fallback(move |request: Request<Body>| {
            let authority = captured.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, 32 * 1024).await.unwrap();
                authority.seen.lock().unwrap().push(Seen {
                    path: parts.uri.path().to_owned(),
                    headers: parts.headers,
                    form: url::form_urlencoded::parse(&body).into_owned().collect(),
                });
                let reply = authority.replies.lock().unwrap().pop_front().unwrap();
                authority.entered.notify_one();
                if let Some(release) = reply.release {
                    release.acquire().await.unwrap().forget();
                }
                Response::builder()
                    .status(reply.status)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&reply.body).unwrap()))
                    .unwrap()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let config = GatewayConfig {
            state_dir: dir.path().join("private-state"),
            client_api_key: KEY.into(),
            oauth_issuer: format!("http://{address}"),
            allow_insecure_http: true,
            ..GatewayConfig::default()
        };
        let state = AppState::new(config.clone(), AccountPool::from_config(&config).unwrap());
        Self {
            _dir: dir,
            config,
            state,
            authority,
            task,
        }
    }
    async fn request(&self, method: &str, path: &str, body: Option<Value>) -> ReplyBody {
        request(
            self.state.clone(),
            method,
            path,
            body,
            &[("x-admin-key", KEY)],
        )
        .await
    }
    async fn begin(&self, proxy: Option<&str>) -> (Value, HashMap<String, String>) {
        let response = self
            .request("POST", GENERATE, Some(json!({"proxy_url":proxy})))
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        let url = url::Url::parse(response.body["auth_url"].as_str().unwrap()).unwrap();
        assert_eq!(url.path(), "/oauth/authorize");
        (response.body, url.query_pairs().into_owned().collect())
    }
}
struct ReplyBody {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}
async fn request(
    state: Arc<AppState>,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> ReplyBody {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let response = router(state)
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let raw = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    ReplyBody {
        status,
        headers,
        body: serde_json::from_slice(&raw).unwrap(),
    }
}
fn tokens(workspace: &str, bearer: &str, plan: &str) -> Value {
    let encode = |value: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    };
    let id = format!(
        "{}.{}.fixture",
        encode(json!({"alg":"none"})),
        encode(json!({
            "email":"owner@example.invalid","exp":3000000000_u64,
            "https://api.openai.com/auth": {
                "chatgpt_account_id":workspace,"chatgpt_user_id":format!("user-{workspace}"),
                "chatgpt_plan_type":plan
            }
        }))
    );
    json!({"id_token":id,"access_token":bearer,"refresh_token":"private-refresh-fixture"})
}
fn exchange_body(begin: &Value, query: &HashMap<String, String>, code: &str) -> Value {
    json!({"session_id":begin["session_id"],"state":query["state"],"code":code,"name":"Fixture account"})
}
fn assert_error(reply: &ReplyBody, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(reply.body["code"], code);
    assert!(reply.body["error"].as_str().unwrap().contains(" / "));
}

#[tokio::test]
async fn all_compatibility_routes_require_one_exact_admin_key() {
    let f = Fixture::new(vec![]).await;
    for (method, path, body) in [
        ("GET", ACCOUNTS, None),
        ("POST", GENERATE, Some(json!({}))),
        ("POST", EXCHANGE, Some(json!({}))),
    ] {
        for headers in [
            vec![],
            vec![("x-admin-key", "wrong")],
            vec![("authorization", "Bearer wrong")],
            vec![
                ("x-admin-key", "wrong"),
                ("authorization", "Bearer fixture-codex2api-admin"),
            ],
            vec![
                ("authorization", "Bearer fixture-codex2api-admin"),
                ("authorization", "Bearer fixture-codex2api-admin"),
            ],
            vec![("x-admin-key", KEY), ("x-admin-key", KEY)],
        ] {
            let response = request(f.state.clone(), method, path, body.clone(), &headers).await;
            assert_error(&response, StatusCode::UNAUTHORIZED, "admin_auth_required");
        }
    }
    let response = f.request("GET", ACCOUNTS, None).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, json!({"accounts":[]}));
    assert_eq!(
        request(
            f.state.clone(),
            "GET",
            ACCOUNTS,
            None,
            &[("authorization", "Bearer fixture-codex2api-admin")]
        )
        .await
        .status,
        StatusCode::OK
    );
    assert!(f.authority.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn browser_authorization_binds_nonce_pkce_redirect_and_proxy_before_network() {
    let f = Fixture::new(vec![]).await;
    let (first, a) = f
        .begin(Some("http://proxy-user:proxy-pass@127.0.0.1:9999"))
        .await;
    let (second, b) = f.begin(None).await;
    assert_ne!(first["session_id"], second["session_id"]);
    assert_ne!(a["state"], b["state"]);
    assert_ne!(a["code_challenge"], b["code_challenge"]);
    assert_eq!(a["response_type"], "code");
    assert_eq!(a["client_id"], codex_login::oauth_client_id());
    assert_eq!(a["code_challenge_method"], "S256");
    assert_eq!(a["redirect_uri"], "http://localhost:1455/auth/callback");
    assert!(!first.to_string().contains("proxy-pass"));
    let mut body = exchange_body(&first, &b, "wrong-session-state");
    assert_error(
        &f.request("POST", EXCHANGE, Some(body.clone())).await,
        StatusCode::BAD_REQUEST,
        "oauth_state_mismatch",
    );
    body["state"] = json!(a["state"]);
    body["proxy_url"] = json!("");
    assert_error(
        &f.request("POST", EXCHANGE, Some(body)).await,
        StatusCode::BAD_REQUEST,
        "oauth_proxy_mismatch",
    );
    for body in [
        json!({"proxy_url":"file:///private/token"}),
        json!({"proxy_url":"http://127.0.0.1:9999/proxy-path"}),
        json!({"redirect_uri":"https://example.invalid/auth/callback"}),
        json!({"redirect_uri":"http://localhost:9999/auth/callback"}),
        json!({"redirect_uri":"http://localhost:1455/auth/callback?state=foreign"}),
    ] {
        assert_error(
            &f.request("POST", GENERATE, Some(body)).await,
            StatusCode::BAD_REQUEST,
            "invalid_admin_request",
        );
    }
    assert_error(
        &f.request(
            "POST",
            EXCHANGE,
            Some(json!({"session_id":"missing","state":"nonce","code":"code"})),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "oauth_session_expired",
    );
    assert!(f.authority.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exchange_uses_native_pkce_once_and_returns_a_durable_sanitized_integer_id() {
    let f = Fixture::new(vec![Reply::account("workspace-one", "private-bearer-one")]).await;
    let (begin, query) = f.begin(None).await;
    let body = exchange_body(&begin, &query, "private-authorization-code");
    let first = f.request("POST", EXCHANGE, Some(body.clone())).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert!(first.body["id"].as_u64().unwrap() > 0);
    assert_eq!(first.body["updated"], false);
    assert_eq!(first.body["email"], "owner@example.invalid");
    assert_eq!(first.body["plan_type"], "pro");
    let replay = f.request("POST", EXCHANGE, Some(body)).await;
    assert_eq!(replay.body, first.body);
    let mut different = exchange_body(&begin, &query, "different-code");
    different["name"] = json!("Do not rename on rejected replay");
    assert_error(
        &f.request("POST", EXCHANGE, Some(different)).await,
        StatusCode::CONFLICT,
        "oauth_session_consumed",
    );
    {
        let seen = f.authority.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/oauth/token");
        assert_eq!(seen[0].form["code"], "private-authorization-code");
        assert_eq!(seen[0].form["grant_type"], "authorization_code");
        assert_eq!(seen[0].form["redirect_uri"], query["redirect_uri"]);
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(seen[0].form["code_verifier"].as_bytes())),
            query["code_challenge"]
        );
        for header in [
            "x-admin-key",
            "authorization",
            "chatgpt-account-id",
            "originator",
            "user-agent",
        ] {
            assert!(!seen[0].headers.contains_key(header), "forwarded {header}");
        }
    }
    let listed = f.request("GET", ACCOUNTS, None).await;
    let row = &listed.body["accounts"][0];
    assert_eq!(row["id"], first.body["id"]);
    assert_eq!(row["name"], "Fixture account");
    assert_eq!(row["status"], "active");
    assert_eq!(row["enabled"], true);
    for flag in [
        "openai_responses_api",
        "grok_api",
        "claude_api",
        "antigravity_api",
        "at_only",
        "agent_identity",
    ] {
        assert_eq!(row[flag], false, "{flag}");
    }
    for private in [
        "private-bearer-one",
        "private-refresh-fixture",
        "workspace-one",
        "private-authorization-code",
        "code_verifier",
        "auth_path",
        "proxy_url",
    ] {
        assert!(
            !listed.body.to_string().contains(private),
            "leaked {private}"
        );
        assert!(
            !first.body.to_string().contains(private),
            "leaked {private}"
        );
    }
    let restored = AppState::new(
        f.config.clone(),
        AccountPool::from_config(&f.config).unwrap(),
    );
    let after = request(restored, "GET", ACCOUNTS, None, &[("x-admin-key", KEY)]).await;
    assert_eq!(after.body, listed.body);
}

#[tokio::test]
async fn duplicate_exchange_is_serialized_and_survives_the_original_request_disconnecting() {
    let gate = Arc::new(Semaphore::new(0));
    let mut reply = Reply::account("workspace-one", "private-bearer-one");
    reply.release = Some(gate.clone());
    let f = Fixture::new(vec![reply]).await;
    let (begin, query) = f.begin(None).await;
    let body = exchange_body(&begin, &query, "one-time-code");
    let state = f.state.clone();
    let payload = body.clone();
    let original = tokio::spawn(async move {
        request(
            state,
            "POST",
            EXCHANGE,
            Some(payload),
            &[("x-admin-key", KEY)],
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(3), f.authority.entered.notified())
        .await
        .unwrap();
    let concurrent = f.request("POST", EXCHANGE, Some(body.clone())).await;
    assert_error(
        &concurrent,
        StatusCode::CONFLICT,
        "oauth_exchange_in_progress",
    );
    assert_eq!(concurrent.headers["retry-after"], "1");
    original.abort();
    let _ = original.await;
    gate.add_permits(1);
    let completed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let result = f.request("POST", EXCHANGE, Some(body.clone())).await;
            if result.status != StatusCode::CONFLICT {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.body);
    assert_eq!(f.authority.seen.lock().unwrap().len(), 1);
    assert_eq!(f.state.accounts.all().unwrap().len(), 1);
}

#[tokio::test]
async fn reconnect_updates_the_same_account_keeps_cooldown_and_enabled_choice() {
    let f = Fixture::new(vec![
        Reply::account("workspace-one", "private-bearer-one"),
        Reply::account("workspace-one", "private-bearer-two"),
    ])
    .await;
    let (begin, query) = f.begin(None).await;
    let first = f
        .request(
            "POST",
            EXCHANGE,
            Some(exchange_body(&begin, &query, "first-code")),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK);
    let old = f.state.accounts.all().unwrap().pop().unwrap();
    let mut advice = HeaderMap::new();
    advice.insert("retry-after", "600".parse().unwrap());
    right_codex::upstream_policy::observe_http(&f.state.accounts, &old, 429, Some(&advice), None)
        .unwrap();
    right_codex::upstream_policy::observe_http(&f.state.accounts, &old, 401, None, None).unwrap();
    f.state.accounts.set_enabled(old.id(), false).unwrap();
    let rejected = f.request("GET", ACCOUNTS, None).await;
    assert_eq!(rejected.body["accounts"][0]["status"], "unauthorized");
    assert_eq!(rejected.body["accounts"][0]["enabled"], false);
    let (begin, query) = f.begin(None).await;
    let mut body = exchange_body(&begin, &query, "second-code");
    body["name"] = json!("Updated label");
    let second = f.request("POST", EXCHANGE, Some(body)).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(second.body["id"], first.body["id"]);
    assert_eq!(second.body["updated"], true);
    let all = f.state.accounts.all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id(), old.id());
    assert_ne!(all[0].revision(), old.revision());
    assert_eq!(all[0].created_at_unix_ms(), old.created_at_unix_ms());
    assert!(all[0].availability().unwrap().quota_cooldown);
    assert!(!all[0].availability().unwrap().auth_invalid);
    assert!(!all[0].admin_enabled().unwrap());
    let row = f.request("GET", ACCOUNTS, None).await;
    assert_eq!(row.body["accounts"][0]["status"], "disabled");
    assert_eq!(row.body["accounts"][0]["name"], "Updated label");
    f.state.accounts.set_enabled(old.id(), true).unwrap();
    let row = f.request("GET", ACCOUNTS, None).await;
    assert_eq!(row.body["accounts"][0]["status"], "rate_limited");
    let restored = AppState::new(
        f.config.clone(),
        AccountPool::from_config(&f.config).unwrap(),
    );
    assert_eq!(
        request(restored, "GET", ACCOUNTS, None, &[("x-admin-key", KEY)])
            .await
            .body["accounts"][0]["status"],
        "rate_limited"
    );
}

#[tokio::test]
async fn rejected_or_non_pro_oauth_never_registers_an_account_or_replays_the_code() {
    for (reply, expected_status, expected_code) in [
        (
            Reply {
                status: StatusCode::BAD_REQUEST,
                body: json!({"error":"private-upstream-diagnostic"}),
                release: None,
            },
            StatusCode::BAD_GATEWAY,
            "oauth_exchange_failed",
        ),
        (
            Reply {
                status: StatusCode::OK,
                body: tokens("workspace-one", "private-bearer", "plus"),
                release: None,
            },
            StatusCode::BAD_REQUEST,
            "pro_oauth_required",
        ),
    ] {
        let f = Fixture::new(vec![reply]).await;
        let (begin, query) = f.begin(None).await;
        let body = exchange_body(&begin, &query, "one-time-code");
        let response = f.request("POST", EXCHANGE, Some(body.clone())).await;
        assert_error(&response, expected_status, expected_code);
        let again = f.request("POST", EXCHANGE, Some(body)).await;
        assert_eq!(again.body, response.body);
        assert!(
            !response
                .body
                .to_string()
                .contains("private-upstream-diagnostic")
        );
        assert_eq!(f.authority.seen.lock().unwrap().len(), 1);
        assert!(f.state.accounts.all().unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(f.config.state_dir.join("accounts"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[tokio::test]
async fn list_validates_filters_and_fails_closed_for_corrupt_integer_id_storage() {
    let f = Fixture::new(vec![]).await;
    for path in [
        "/api/admin/accounts?view=full",
        "/api/admin/accounts?channel=other",
        "/api/admin/accounts?unexpected=true",
    ] {
        assert_error(
            &f.request("GET", path, None).await,
            StatusCode::BAD_REQUEST,
            "invalid_admin_request",
        );
    }
    std::fs::write(
        f.config.state_dir.join("codex2api-ids.json"),
        br#"{"accounts":{"one":{"id":1,"name":"One"},"two":{"id":1,"name":"Two"}}}"#,
    )
    .unwrap();
    assert_error(
        &f.request("GET", ACCOUNTS, None).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "admin_unavailable",
    );
}

#[tokio::test]
async fn oauth_exchange_uses_bound_proxy_and_reauthorization_can_clear_it() {
    let f = Fixture::new(vec![Reply::account("workspace-one", "direct-bearer")]).await;
    // A second loopback server acts as the HTTP proxy. It returns the token
    // reply itself, so accidental direct routing would hit the wrong fixture.
    let proxy = Fixture::new(vec![Reply::account("workspace-one", "proxied-bearer")]).await;
    let (begin, query) = f.begin(Some(&proxy.config.oauth_issuer)).await;
    let first = f
        .request(
            "POST",
            EXCHANGE,
            Some(exchange_body(&begin, &query, "proxied-code")),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(proxy.authority.seen.lock().unwrap().len(), 1);
    assert!(f.authority.seen.lock().unwrap().is_empty());
    let old = f.state.accounts.all().unwrap().pop().unwrap();
    let normalized_proxy = format!("{}/", proxy.config.oauth_issuer);
    assert_eq!(old.proxy(), Some(normalized_proxy.as_str()));
    assert_eq!(
        f.request("GET", ACCOUNTS, None).await.body["accounts"][0]["proxy_configured"],
        true
    );
    let (begin, query) = f.begin(None).await;
    let mut body = exchange_body(&begin, &query, "direct-code");
    body["proxy_url"] = json!("");
    let second = f.request("POST", EXCHANGE, Some(body)).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(second.body["id"], first.body["id"]);
    assert_eq!(second.body["updated"], true);
    let new = f.state.accounts.all().unwrap().pop().unwrap();
    assert_eq!(new.proxy(), None);
    assert_ne!(new.revision(), old.revision());
    assert_eq!(proxy.authority.seen.lock().unwrap().len(), 1);
    assert_eq!(f.authority.seen.lock().unwrap().len(), 1);
    assert_eq!(
        f.request("GET", ACCOUNTS, None).await.body["accounts"][0]["proxy_configured"],
        false
    );
}

#[tokio::test]
async fn rest_and_draining_are_visible_and_reauthentication_does_not_cancel_deletion() {
    let f = Fixture::new(vec![
        Reply::account("workspace-one", "first-bearer"),
        Reply::account("workspace-one", "new-bearer"),
    ])
    .await;
    let (begin, query) = f.begin(None).await;
    assert_eq!(
        f.request(
            "POST",
            EXCHANGE,
            Some(exchange_body(&begin, &query, "first-code"))
        )
        .await
        .status,
        StatusCode::OK
    );
    let account = f.state.accounts.all().unwrap().pop().unwrap();
    f.state
        .accounts
        .rest(account.id(), Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        f.request("GET", ACCOUNTS, None).await.body["accounts"][0]["status"],
        "paused"
    );
    let lease = f
        .state
        .accounts
        .lease(account.id(), false)
        .unwrap()
        .unwrap();
    assert!(!f.state.accounts.delete_draining(account.id()).unwrap());
    assert_eq!(
        f.request("GET", ACCOUNTS, None).await.body["accounts"][0]["status"],
        "deleting"
    );
    let (begin, query) = f.begin(None).await;
    let result = f
        .request(
            "POST",
            EXCHANGE,
            Some(exchange_body(&begin, &query, "new-code")),
        )
        .await;
    assert_error(&result, StatusCode::CONFLICT, "account_deleting");
    assert_eq!(f.state.accounts.all().unwrap().len(), 1);
    assert_eq!(
        f.state.accounts.all().unwrap()[0].revision(),
        account.revision()
    );
    drop(lease);
    assert_eq!(
        f.request("GET", ACCOUNTS, None).await.body["accounts"],
        json!([])
    );
}

#[tokio::test]
async fn successful_token_exchange_survives_local_commit_failure_without_reposting_the_code() {
    for (blocked_file, registered_before_recovery) in
        [("account_registry.json", 0), ("codex2api-ids.json", 1)]
    {
        let gate = Arc::new(Semaphore::new(0));
        let mut reply = Reply::account("workspace-one", "one-time-bearer");
        reply.release = Some(gate.clone());
        let f = Fixture::new(vec![reply]).await;
        let (begin, query) = f.begin(None).await;
        let body = exchange_body(&begin, &query, "one-time-code");
        let state = f.state.clone();
        let payload = body.clone();
        let first = tokio::spawn(async move {
            request(
                state,
                "POST",
                EXCHANGE,
                Some(payload),
                &[("x-admin-key", KEY)],
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(3), f.authority.entered.notified())
            .await
            .unwrap();
        let blocked = f.config.state_dir.join(blocked_file);
        std::fs::create_dir(&blocked).unwrap();
        gate.add_permits(1);
        let failed = first.await.unwrap();
        assert_error(
            &failed,
            StatusCode::SERVICE_UNAVAILABLE,
            "admin_unavailable",
        );
        assert_eq!(f.authority.seen.lock().unwrap().len(), 1);
        assert_eq!(
            f.state.accounts.all().unwrap().len(),
            registered_before_recovery
        );
        // The one-time token response must survive until local persistence can
        // finish; failure must never clean the sole successful login copy.
        let staged: Vec<_> = std::fs::read_dir(f.config.state_dir.join("accounts"))
            .unwrap()
            .map(|entry| entry.unwrap().path().join("home/auth.json"))
            .filter(|path| path.is_file())
            .collect();
        assert_eq!(
            staged.len(),
            1,
            "{blocked_file} lost the completed OAuth login"
        );
        std::fs::remove_dir(blocked).unwrap();
        let recovered = f.request("POST", EXCHANGE, Some(body.clone())).await;
        assert_eq!(
            recovered.status,
            StatusCode::OK,
            "{blocked_file}: {}",
            recovered.body
        );
        assert_eq!(
            recovered.body["updated"], false,
            "first import became a reauthorization during local retry"
        );
        assert!(recovered.body["id"].as_u64().unwrap() > 0);
        assert_eq!(f.state.accounts.all().unwrap().len(), 1);
        assert_eq!(
            f.authority.seen.lock().unwrap().len(),
            1,
            "reposted one-time OAuth code"
        );
        let cached = f.request("POST", EXCHANGE, Some(body)).await;
        assert_eq!(cached.body, recovered.body);
        let restored = AppState::new(
            f.config.clone(),
            AccountPool::from_config(&f.config).unwrap(),
        );
        let listed = request(restored, "GET", ACCOUNTS, None, &[("x-admin-key", KEY)]).await;
        assert_eq!(listed.body["accounts"][0]["id"], recovered.body["id"]);
    }
}
