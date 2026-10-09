use base64::Engine;
use http::HeaderMap;
use right_codex::{accounts::AccountPool, config::GatewayConfig, upstream_policy};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

fn auth(path: &Path, account: &str, token: &str) {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "exp": 3000000000_u64, "https://api.openai.com/auth": {
            "chatgpt_account_id": account, "chatgpt_user_id": format!("user-{account}"), "chatgpt_plan_type": "pro"
        }
    })).unwrap());
    std::fs::write(path, serde_json::to_vec(&json!({"auth_mode":"chatgpt","tokens":{
        "id_token":format!("e30.{encoded}.fixture"),"access_token":token,"refresh_token":"synthetic-refresh","account_id":account
    },"last_refresh":"2026-10-09T00:00:00Z"})).unwrap()).unwrap();
}
fn fixture(upstream: &str) -> (TempDir, GatewayConfig, AccountPool) {
    let dir = TempDir::new().unwrap();
    auth(
        &dir.path().join("one.json"),
        "workspace-one",
        "synthetic-one",
    );
    auth(
        &dir.path().join("two.json"),
        "workspace-two",
        "synthetic-two",
    );
    let cfg: GatewayConfig = serde_json::from_value(json!({
        "listen":"127.0.0.1:18184","state_dir":dir.path().join("state"),"client_api_key":"synthetic-secret",
        "base_url":format!("{upstream}/v1"),"chatgpt_base_url":format!("{upstream}/backend-api"),
        "oauth_issuer":upstream,"allow_insecure_http":true,"accounts":[
            {"id":"one","auth_path":dir.path().join("one.json"),"enabled":true},
            {"id":"two","auth_path":dir.path().join("two.json"),"enabled":true}
        ]
    })).unwrap();
    let pool = AccountPool::from_config(&cfg).unwrap();
    (dir, cfg, pool)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn unauthorized_stops_new_work_survives_restart_and_new_credentials_recover() {
    let (dir, cfg, pool) = fixture("http://127.0.0.1:9");
    let old = pool.by_id("one").unwrap().unwrap();
    let lease = pool.lease("one", true).unwrap().unwrap();
    upstream_policy::observe_http(&pool, &old, 401, None, None).unwrap();
    assert!(old.availability().unwrap().auth_invalid);
    assert!(pool.by_id("one").unwrap().is_none());
    assert!(pool.lease("one", false).unwrap().is_none());
    assert_eq!(pool.next_enabled().unwrap().unwrap().id(), "two");
    assert_eq!(lease.account().id(), "one");
    assert_eq!(pool.all().unwrap().len(), 2);
    assert!(!pool.reload_auth("one").unwrap());
    pool.set_enabled("one", true).unwrap();
    assert!(pool.by_id("one").unwrap().is_none());
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert!(
        restored
            .managed("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    auth(
        &dir.path().join("one.json"),
        "workspace-one",
        "synthetic-replacement",
    );
    assert!(restored.reload_auth("one").unwrap());
    let replacement = restored.by_id("one").unwrap().unwrap();
    assert_ne!(replacement.revision(), old.revision());
    upstream_policy::observe_http(&restored, &old, 401, None, None).unwrap();
    upstream_policy::observe_http(
        &restored,
        &old,
        429,
        None,
        Some(&json!({"error":{"resets_at":now()+3600}})),
    )
    .unwrap();
    assert!(!replacement.availability().unwrap().auth_invalid);
    assert!(!replacement.availability().unwrap().quota_cooldown);
    assert!(
        AccountPool::from_config(&cfg)
            .unwrap()
            .by_id("one")
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn actual_reset_is_persistent_and_usage_poll_cannot_clear_it() {
    let app = axum::Router::new().fallback(|| async { axum::Json(json!({"account_id":"workspace-one","plan_type":"pro","rate_limit":{
        "allowed":true,"limit_reached":false,"primary_window":{"used_percent":0,"limit_window_seconds":300,"reset_after_seconds":60,"reset_at":2000000000}
    }})) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (_dir, cfg, pool) = fixture(&url);
    let one = pool.by_id("one").unwrap().unwrap();
    let reset = now() + 3600;
    upstream_policy::observe_http(
        &pool,
        &one,
        429,
        None,
        Some(&json!({"error":{"resets_at":reset}})),
    )
    .unwrap();
    assert_eq!(
        one.availability().unwrap().quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    assert_eq!(pool.next_enabled().unwrap().unwrap().id(), "two");
    pool.refresh_quota("one").await.unwrap();
    pool.clear_quota_cooldown("one").unwrap();
    assert_eq!(
        one.availability().unwrap().quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert_eq!(
        restored
            .by_id("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    assert!(restored.lease("one", false).unwrap().is_none());
    server.abort();
}

#[test]
fn missing_past_invalid_resets_and_other_errors_do_not_change_scheduling() {
    let (_dir, _cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    for body in [
        json!({"error":{"code":"rate_limit_exceeded"}}),
        json!({"error":{"resets_at":now()-1}}),
        json!({"error":{"resets_at":-1}}),
        json!({"error":{"resets_at":"tomorrow"}}),
        json!({"error":{"message":"try again in 60s"}}),
    ] {
        upstream_policy::observe_http(&pool, &one, 429, None, Some(&body)).unwrap();
        assert!(!one.availability().unwrap().quota_cooldown);
    }
    for status in [400, 403, 408, 409, 500, 502, 503] {
        upstream_policy::observe_http(
            &pool,
            &one,
            status,
            None,
            Some(&json!({"error":{"resets_at":now()+3600}})),
        )
        .unwrap();
        assert!(!one.availability().unwrap().quota_cooldown);
        assert!(!one.availability().unwrap().auth_invalid);
    }
    upstream_policy::observe_event(
        &pool,
        &one,
        &json!({"type":"response.output_text.delta","delta":"401","error":{"status":401}}),
    )
    .unwrap();
    assert!(!one.availability().unwrap().auth_invalid);
}

#[test]
fn streamed_failures_use_real_status_and_headers_without_touching_the_event() {
    let (_dir, _cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    let event = json!({"type":"error","status":429,"error":{"message":"verbatim","code":"rate_limit_exceeded"},"headers":{"retry-after":120}});
    let original = event.clone();
    upstream_policy::observe_event(&pool, &one, &event).unwrap();
    assert_eq!(event, original);
    let deadline = one
        .availability()
        .unwrap()
        .quota_cooldown_until_unix_ms
        .unwrap();
    assert!(deadline >= (now() + 119) * 1000 && deadline <= (now() + 121) * 1000);
    let two = pool.by_id("two").unwrap().unwrap();
    upstream_policy::observe_event(&pool, &two, &json!({"type":"response.failed","response":{"status":"failed","error":{"status_code":401}}})).unwrap();
    assert!(pool.next_enabled().unwrap().is_none());
}

#[test]
fn retry_after_http_date_and_reset_header_are_honored() {
    let (_dir, _cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "retry-after",
        "Fri, 01 Jan 2038 00:00:00 GMT".parse().unwrap(),
    );
    upstream_policy::observe_http(&pool, &one, 429, Some(&headers), None).unwrap();
    assert!(
        one.availability()
            .unwrap()
            .quota_cooldown_until_unix_ms
            .unwrap()
            > (now() + 3600) * 1000
    );
    let two = pool.by_id("two").unwrap().unwrap();
    headers.clear();
    let reset = now() + 60;
    headers.insert(
        "x-codex-primary-reset-at",
        reset.to_string().parse().unwrap(),
    );
    upstream_policy::observe_http(&pool, &two, 429, Some(&headers), None).unwrap();
    assert_eq!(
        two.availability().unwrap().quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
}

#[test]
fn disk_failure_keeps_live_account_blocked_and_expired_persistence_is_ignored() {
    let (dir, cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    let path = dir.path().join("state/accounts/one/admission.json");
    std::fs::create_dir(&path).unwrap();
    assert!(upstream_policy::observe_http(&pool, &one, 401, None, None).is_err());
    assert!(pool.by_id("one").unwrap().is_none());
    std::fs::remove_dir(&path).unwrap();
    let value: Value =
        json!({"revision":one.revision(),"unauthorized":false,"quota_reset_unix_ms":1});
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert!(restored.lease("one", true).unwrap().is_some());
}

struct ErrorUpstream {
    url: String,
    raw: Vec<u8>,
    seen: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ErrorUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn error_upstream(status: u16, reset: Option<u64>) -> ErrorUpstream {
    let error = match reset {
        Some(reset) => json!({"error":{"message":"Observed upstream rejection","resets_at":reset}}),
        None => json!({"error":{"message":"Observed upstream rejection"}}),
    };
    let raw = format!("{}\n", serde_json::to_string_pretty(&error).unwrap()).into_bytes();
    let body = raw.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let app =
        axum::Router::new().fallback(move |request: axum::http::Request<axum::body::Body>| {
            let body = body.clone();
            let captured = captured.clone();
            async move {
                captured
                    .lock()
                    .unwrap()
                    .push(request.uri().path().to_owned());
                axum::response::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    ErrorUpstream {
        url,
        raw,
        seen,
        task,
    }
}

#[tokio::test]
async fn actual_usage_http_failures_change_only_the_observed_account() {
    for (status, reset) in [
        (401, None),
        (429, Some(now() + 900)),
        (429, None),
        (503, Some(now() + 900)),
    ] {
        let upstream = error_upstream(status, reset).await;
        let (_dir, _cfg, pool) = fixture(&upstream.url);
        let one = pool.by_id("one").unwrap().unwrap();
        let error = pool.refresh_quota("one").await.unwrap_err();
        match error {
            right_codex::routing::RoutingError::Upstream(raw) => {
                assert_eq!(raw.status.as_u16(), status);
                assert_eq!(raw.body, upstream.raw);
            }
            _ => panic!("upstream usage rejection was replaced"),
        }
        let availability = one.availability().unwrap();
        assert_eq!(availability.auth_invalid, status == 401);
        assert_eq!(
            availability.quota_cooldown,
            status == 429 && reset.is_some()
        );
        if status == 429
            && let Some(reset) = reset
        {
            assert_eq!(
                availability.quota_cooldown_until_unix_ms,
                Some(reset * 1000)
            );
        }
        let two = pool.by_id("two").unwrap().unwrap().availability().unwrap();
        assert!(!two.auth_invalid && !two.quota_cooldown);
        if status == 401 {
            assert!(pool.refresh_quota("one").await.is_err());
            assert!(pool.lease("one", false).unwrap().is_none());
        }
        assert_eq!(
            *upstream.seen.lock().unwrap(),
            vec!["/backend-api/wham/usage"]
        );
    }
}

#[tokio::test]
async fn actual_route_failures_are_returned_once_without_submitting_responses() {
    for (status, reset) in [
        (401, None),
        (429, Some(now() + 900)),
        (429, None),
        (503, Some(now() + 900)),
    ] {
        let upstream = error_upstream(status, reset).await;
        let (_dir, mut cfg, _) = fixture(&upstream.url);
        cfg.base_url = format!("{}/backend-api/codex", upstream.url);
        cfg.scheduling.startup_spacing_secs = 0;
        cfg.telemetry.official_metrics_enabled = false;
        let state = right_codex::gateway::AppState::new(
            cfg.clone(),
            AccountPool::from_config(&cfg).unwrap(),
        );
        let one = state.accounts.by_id("one").unwrap().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/v1/responses", listener.local_addr().unwrap());
        let app = right_codex::gateway::router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let response = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().unwrap()
            .post(url).bearer_auth("synthetic-client-oauth").header("thread-id", "route-error-scope")
            .json(&json!({"model":"fixture-model","stream":true,"input":[{"role":"user","content":"hi"}]}))
            .send().await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            upstream.raw.as_slice()
        );
        let availability = one.availability().unwrap();
        assert_eq!(availability.auth_invalid, status == 401);
        assert_eq!(
            availability.quota_cooldown,
            status == 429 && reset.is_some()
        );
        let two = state
            .accounts
            .by_id("two")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap();
        assert!(!two.auth_invalid && !two.quota_cooldown);
        assert_eq!(
            *upstream.seen.lock().unwrap(),
            vec!["/backend-api/wham/accounts/check"]
        );
        server.abort();
    }
}

#[tokio::test]
async fn elapsed_cooldown_recovers_without_polling_or_management_actions() {
    let (_dir, cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    upstream_policy::observe_http(
        &pool,
        &one,
        429,
        None,
        Some(&json!({"error":{"resets_in_seconds":1}})),
    )
    .unwrap();
    assert!(pool.lease("one", false).unwrap().is_none());
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert!(restored.lease("one", false).unwrap().is_none());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!one.availability().unwrap().quota_cooldown);
    assert_eq!(
        one.availability().unwrap().quota_cooldown_until_unix_ms,
        None
    );
    assert!(pool.lease("one", false).unwrap().is_some());
    assert!(restored.lease("one", false).unwrap().is_some());
    assert!(
        AccountPool::from_config(&cfg)
            .unwrap()
            .lease("one", true)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn runtime_usage_poll_skips_invalid_credentials_but_polls_healthy_accounts() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let ready = Arc::new(tokio::sync::Notify::new());
    let captured = seen.clone();
    let signal = ready.clone();
    let app = axum::Router::new().fallback(move |request: axum::http::Request<axum::body::Body>| {
        let captured = captured.clone();
        let signal = signal.clone();
        async move {
            let account = request.headers().get("chatgpt-account-id").unwrap().to_str().unwrap().to_owned();
            captured.lock().unwrap().push((request.uri().path().to_owned(), account.clone()));
            signal.notify_one();
            axum::Json(json!({"account_id":account,"plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false}}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (_dir, mut cfg, pool) = fixture(&url);
    cfg.telemetry.official_metrics_enabled = false;
    let one = pool.by_id("one").unwrap().unwrap();
    upstream_policy::observe_http(&pool, &one, 401, None, None).unwrap();
    let state = right_codex::gateway::AppState::new(cfg, pool);
    let runtime = right_codex::runtime::start(state);
    tokio::time::timeout(Duration::from_secs(3), ready.notified())
        .await
        .unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("/backend-api/wham/usage".into(), "workspace-two".into())]
    );
    runtime.abort();
    server.abort();
}

#[test]
fn admission_follows_actual_bearer_across_json_and_transport_revisions() {
    let (dir, mut cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    let two = pool.by_id("two").unwrap().unwrap();
    let reset = now() + 900;
    upstream_policy::observe_http(&pool, &one, 401, None, None).unwrap();
    upstream_policy::observe_http(
        &pool,
        &two,
        429,
        None,
        Some(&json!({"error":{"resets_at":reset}})),
    )
    .unwrap();
    for id in ["one", "two"] {
        let source = dir.path().join(format!("{id}.json"));
        let mut auth: Value = serde_json::from_slice(&std::fs::read(&source).unwrap()).unwrap();
        auth["last_refresh"] = json!("2026-10-10T00:00:00Z");
        auth["tokens"]["refresh_token"] = json!("synthetic-rotated-refresh");
        auth["tokens"]["id_token"] = json!(format!(
            "{}-rotated",
            auth["tokens"]["id_token"].as_str().unwrap()
        ));
        std::fs::write(source, serde_json::to_vec_pretty(&auth).unwrap()).unwrap();
        assert!(pool.reload_auth(id).unwrap());
    }
    assert_ne!(
        pool.managed("one").unwrap().unwrap().revision(),
        one.revision()
    );
    assert!(
        pool.managed("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    assert_eq!(
        pool.managed("two")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    cfg.accounts[0].proxy = Some("http://127.0.0.1:10".into());
    cfg.base_url = "http://127.0.0.1:11/v1".into();
    cfg.oauth_issuer = "http://127.0.0.1:12".into();
    cfg.chatgpt_base_url = "http://127.0.0.1:13/backend-api".into();
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert!(
        restored
            .managed("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    assert_eq!(
        restored
            .managed("two")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    assert!(restored.next_enabled().unwrap().is_none());
    auth(
        &dir.path().join("one.json"),
        "workspace-one",
        "synthetic-new-bearer-one",
    );
    auth(
        &dir.path().join("two.json"),
        "workspace-two",
        "synthetic-new-bearer-two",
    );
    assert!(restored.reload_auth("one").unwrap());
    assert!(restored.reload_auth("two").unwrap());
    assert!(
        !restored
            .managed("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    assert_eq!(
        restored
            .managed("two")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    assert!(restored.lease("two", false).unwrap().is_none());
    assert_eq!(
        AccountPool::from_config(&cfg)
            .unwrap()
            .managed("two")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
    assert!(
        AccountPool::from_config(&cfg)
            .unwrap()
            .next_enabled()
            .unwrap()
            .is_some()
    );
}

#[test]
fn legacy_rejection_state_is_not_unlocked_by_an_unrelated_revision_change() {
    let (dir, mut cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    upstream_policy::observe_http(&pool, &one, 401, None, None).unwrap();
    let path = dir.path().join("state/accounts/one/admission.json");
    let mut persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    persisted
        .as_object_mut()
        .unwrap()
        .remove("credential_fingerprint");
    std::fs::write(&path, serde_json::to_vec(&persisted).unwrap()).unwrap();
    cfg.accounts[0].proxy = Some("http://127.0.0.1:10".into());
    let restored = AccountPool::from_config(&cfg).unwrap();
    assert!(
        restored
            .managed("one")
            .unwrap()
            .unwrap()
            .availability()
            .unwrap()
            .auth_invalid
    );
    let migrated: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        migrated["credential_fingerprint"].as_str().unwrap().len(),
        64
    );
}

#[tokio::test]
async fn delayed_error_body_does_not_restart_header_retry_after() {
    let (_dir, _cfg, pool) = fixture("http://127.0.0.1:9");
    let one = pool.by_id("one").unwrap().unwrap();
    let two = pool.by_id("two").unwrap().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("retry-after", "1".parse().unwrap());
    let mut response = right_codex::transport::RawHttpError {
        status: http::StatusCode::TOO_MANY_REQUESTS,
        retry_after: codex_http_client::RetryAfter::from_headers(&headers),
        headers,
        body: br#"{"error":{"code":"rate_limit_exceeded"}}"#.to_vec(),
        complete: true,
    };
    // Time spent reading the body must consume, not restart, the advice.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    upstream_policy::observe_raw_http(&pool, &one, &response).unwrap();
    assert!(!one.availability().unwrap().quota_cooldown);
    let reset = now() + 600;
    response.body = serde_json::to_vec(&json!({"error":{"resets_at":reset}})).unwrap();
    upstream_policy::observe_raw_http(&pool, &two, &response).unwrap();
    assert_eq!(
        two.availability().unwrap().quota_cooldown_until_unix_ms,
        Some(reset * 1000)
    );
}
