use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use base64::Engine;
use http::HeaderMap;
use right_codex::accounts::{AccountError, AccountPool, oauth_login_client};
use right_codex::config::GatewayConfig;
use right_codex::oauth::OAuthLogin;
use right_codex::oauth_contract::OAuthError;
use right_codex::routing::RoutingError;
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

struct Seen {
    path: String,
    body: Vec<u8>,
    headers: HeaderMap,
}
fn assert_codex_defaults(headers: &HeaderMap) {
    for (name, value) in codex_login::default_client::default_headers().iter() {
        assert_eq!(
            headers.get(name),
            Some(value),
            "official default header {name}"
        );
    }
}
fn assert_raw_login(headers: &HeaderMap) {
    for name in [
        "authorization",
        "chatgpt-account-id",
        "originator",
        "user-agent",
        codex_login::default_client::RESIDENCY_HEADER_NAME,
    ] {
        assert!(
            !headers.contains_key(name),
            "raw login carried API header {name}"
        );
    }
}
struct Server {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    handler: impl Fn(&str, &[u8], usize) -> (StatusCode, Value) + Send + Sync + 'static,
) -> Server {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let handler = Arc::new(handler);
    let app = Router::new().fallback(move |request: Request<Body>| {
        let captured = captured.clone();
        let handler = handler.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 128 * 1024).await.unwrap();
            let path = parts.uri.path().to_owned();
            let number = {
                let mut seen = captured.lock().unwrap();
                let number = seen.len();
                seen.push(Seen {
                    path: path.clone(),
                    body: body.to_vec(),
                    headers: parts.headers,
                });
                number
            };
            let (status, value) = handler(&path, &body, number);
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server { url, seen, task }
}
fn jwt(account: &str, user: &str) -> String {
    let encode = |v: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
    };
    format!(
        "{}.{}.fixture",
        encode(json!({"alg":"none"})),
        encode(
            json!({"email":"fixture@example.invalid","exp":3000000000_u64,
        "https://api.openai.com/auth":{"chatgpt_account_id":account,"chatgpt_user_id":user,"chatgpt_plan_type":"plus"}})
        )
    )
}
fn auth(path: &Path, account: &str, user: &str, token: &str) {
    std::fs::write(path,serde_json::to_vec(&json!({"auth_mode":"chatgpt","tokens":{
        "id_token":jwt(account,user),"access_token":token,"refresh_token":format!("refresh-{account}"),"account_id":account},
        "last_refresh":"2026-10-09T00:00:00Z"})).unwrap()).unwrap();
}
fn cfg(dir: &TempDir, issuer: &str) -> GatewayConfig {
    serde_json::from_value(
        json!({"listen":"127.0.0.1:18184","state_dir":dir.path().join("private-state"),
        "client_api_key":"admin-fixture-secret","base_url":format!("{issuer}/v1"),"chatgpt_base_url":format!("{issuer}/backend-api"),
        "oauth_issuer":issuer,"allow_insecure_http":true,"accounts":[
        {"id":"one","auth_path":dir.path().join("one.json"),"enabled":true},
        {"id":"two","auth_path":dir.path().join("two.json"),"enabled":true}]}),
    )
    .unwrap()
}
fn sources(dir: &TempDir) {
    auth(
        &dir.path().join("one.json"),
        "workspace-one",
        "user-one",
        "access-one",
    );
    auth(
        &dir.path().join("two.json"),
        "workspace-two",
        "user-two",
        "access-two",
    );
}

#[test]
fn restored_private_auth_does_not_reopen_missing_import_sources() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, "http://127.0.0.1:9");
    let original = AccountPool::from_config(&config).unwrap();
    let account = original.by_id("one").unwrap().unwrap();
    let revision = account.revision().to_owned();
    let private_before = std::fs::read(account.private_home().join("auth.json")).unwrap();
    std::fs::remove_file(dir.path().join("one.json")).unwrap();
    std::fs::remove_file(dir.path().join("two.json")).unwrap();
    let restored = AccountPool::from_config(&config).unwrap();
    assert_eq!(restored.by_id("one").unwrap().unwrap().revision(), revision);
    assert!(matches!(
        restored.reload_auth("one"),
        Err(AccountError::AuthRead)
    ));
    assert_eq!(
        std::fs::read(account.private_home().join("auth.json")).unwrap(),
        private_before
    );
}

#[test]
fn explicit_source_reload_rejects_identity_change_after_private_restore() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, "http://127.0.0.1:9");
    let original = AccountPool::from_config(&config).unwrap();
    let account = original.by_id("one").unwrap().unwrap();
    let private_before = std::fs::read(account.private_home().join("auth.json")).unwrap();
    auth(
        &dir.path().join("one.json"),
        "foreign-workspace",
        "foreign-user",
        "foreign-bearer",
    );
    // Restart is private-state restoration, never an implicit source import.
    let restored = AccountPool::from_config(&config).unwrap();
    assert_eq!(
        restored.by_id("one").unwrap().unwrap().revision(),
        account.revision()
    );
    assert!(matches!(
        restored.reload_auth("one"),
        Err(AccountError::IdentityChanged)
    ));
    assert_eq!(
        std::fs::read(account.private_home().join("auth.json")).unwrap(),
        private_before
    );
}

fn copy_private_fixture_tree(source: &Path, destination: &Path) {
    std::fs::create_dir(destination).unwrap();
    std::fs::set_permissions(
        destination,
        std::fs::metadata(source).unwrap().permissions(),
    )
    .unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        assert!(!entry.file_type().unwrap().is_symlink());
        if entry.file_type().unwrap().is_dir() {
            copy_private_fixture_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn gateway_owned_dynamic_source_rebases_only_its_explicit_private_registry_record() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let mut config = cfg(&dir, "http://127.0.0.1:9");
    let original = AccountPool::from_config(&config).unwrap();
    let home = config.state_dir.join("accounts/dynamic/home");
    std::fs::create_dir_all(&home).unwrap();
    auth(
        &home.join("auth.json"),
        "workspace-dynamic",
        "user-dynamic",
        "dynamic-bearer",
    );
    let account = original.add_from_home("dynamic", None).unwrap();
    let revision = account.revision().to_owned();
    let created = account.created_at_unix_ms();
    let registry: Value = serde_json::from_slice(
        &std::fs::read(config.state_dir.join("account_registry.json")).unwrap(),
    )
    .unwrap();
    let dynamic = registry
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "dynamic")
        .unwrap();
    assert_eq!(dynamic["gateway_owned_source"], true);
    assert_eq!(dynamic["auth_path"], "accounts/dynamic/home/auth.json");
    assert_eq!(registry[0]["gateway_owned_source"], false);
    assert_eq!(
        registry[0]["auth_path"],
        config.accounts[0].auth_path.to_str().unwrap()
    );
    let relocated = dir.path().join("relocated-state");
    copy_private_fixture_tree(&config.state_dir, &relocated);
    std::fs::rename(&config.state_dir, dir.path().join("retired-state")).unwrap();
    std::fs::remove_file(dir.path().join("one.json")).unwrap();
    std::fs::remove_file(dir.path().join("two.json")).unwrap();
    config.state_dir = relocated.clone();
    config.accounts.clear();
    let restored = AccountPool::from_config(&config).unwrap();
    let current = restored.by_id("dynamic").unwrap().unwrap();
    assert_eq!(current.revision(), revision);
    assert_eq!(current.created_at_unix_ms(), created);
    assert_eq!(
        current.private_home(),
        relocated.join("accounts/dynamic/home")
    );
    assert_eq!(restored.reload_auth("dynamic"), Ok(false));
    // An external source remains external; explicit reload does not silently
    // substitute its private home after the original path has disappeared.
    assert!(matches!(
        restored.reload_auth("one"),
        Err(AccountError::AuthRead)
    ));
}

#[tokio::test]
async fn official_route_and_usage_401_preserve_original_body_without_reposting() {
    let upstream = server(|path, _, _| {
        assert!(matches!(
            path,
            "/backend-api/wham/accounts/check" | "/backend-api/wham/usage"
        ));
        // The status is authoritative even when a rejected response body is not
        // shaped like an OAuth/backend JSON object.
        (
            StatusCode::UNAUTHORIZED,
            json!({"error":"fixture-token-expired"}),
        )
    })
    .await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, &upstream.url);
    let pool = AccountPool::from_config(&config).unwrap();
    let account = pool.by_id("one").unwrap().unwrap();
    let base = format!("{}/backend-api/codex", upstream.url);
    assert!(matches!(
        account.responses_route(&base).await,
        Err(RoutingError::Upstream(ref source)) if source.status==StatusCode::UNAUTHORIZED && source.body==br#"{"error":"fixture-token-expired"}"#
    ));
    assert!(matches!(
        account.quota_snapshot().await,
        Err(RoutingError::Upstream(ref source)) if source.status==StatusCode::UNAUTHORIZED && source.body==br#"{"error":"fixture-token-expired"}"#
    ));
    let seen = upstream.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|s| s.path != "/oauth/token"));
    assert_eq!(
        account.revision(),
        pool.by_id("one").unwrap().unwrap().revision()
    );
}
fn tokens(account: &str, user: &str, token: &str) -> Value {
    json!({"id_token":jwt(account,user),"access_token":token,"refresh_token":format!("rotated-{account}")})
}

#[tokio::test]
async fn parallel_401_refresh_uses_one_post_private_home_and_immutable_auth_snapshot() {
    let issuer = server(|path, _, _| {
        assert_eq!(path, "/oauth/token");
        (
            StatusCode::OK,
            tokens("workspace-one", "user-one", "new-access-one"),
        )
    })
    .await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, &issuer.url);
    let before = std::fs::read(dir.path().join("one.json")).unwrap();
    let pool = AccountPool::from_config(&config).unwrap();
    let original = pool.by_id("one").unwrap().unwrap();
    let old_auth = original.auth_provider();
    let rev = original.revision().to_owned();
    let (one, two) = tokio::join!(
        pool.refresh_once("one", &rev),
        pool.refresh_once("one", &rev)
    );
    let one = one.unwrap();
    let two = two.unwrap();
    assert!(Arc::ptr_eq(&one, &two));
    assert_ne!(one.revision(), rev);
    assert_eq!(one.workspace_account_id(), "workspace-one");
    let mut headers = HeaderMap::new();
    old_auth.add_auth_headers(&mut headers);
    assert_eq!(headers["authorization"], "Bearer access-one");
    one.auth_provider().add_auth_headers(&mut headers);
    assert_eq!(headers["authorization"], "Bearer new-access-one");
    let hits = issuer.seen.lock().unwrap();
    assert_eq!(hits.len(), 1);
    assert_codex_defaults(&hits[0].headers);
    assert!(!hits[0].headers.contains_key("authorization"));
    assert!(!hits[0].headers.contains_key("chatgpt-account-id"));
    let body: Value = serde_json::from_slice(&hits[0].body).unwrap();
    assert_eq!(body["grant_type"], "refresh_token");
    assert_eq!(body["client_id"], codex_login::oauth_client_id());
    assert_eq!(body["refresh_token"], "refresh-workspace-one");
    drop(hits);
    assert_eq!(std::fs::read(dir.path().join("one.json")).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(one.private_home())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(one.private_home().join("auth.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let restarted = AccountPool::from_config(&config).unwrap();
    let mut h = HeaderMap::new();
    restarted
        .by_id("one")
        .unwrap()
        .unwrap()
        .authorize_headers(&mut h)
        .unwrap();
    assert_eq!(h["authorization"], "Bearer new-access-one");
}

#[tokio::test]
async fn per_account_proxy_keeps_refresh_tokens_on_distinct_transports_and_rejects_identity_change()
{
    let direct = server(|_, _, _| panic!("refresh bypassed configured account proxy")).await;
    let first = server(|_, _, _| {
        (
            StatusCode::OK,
            tokens("workspace-one", "user-one", "proxy-access-one"),
        )
    })
    .await;
    let second = server(|_, _, _| {
        (
            StatusCode::OK,
            tokens("workspace-two", "foreign-user", "foreign-access"),
        )
    })
    .await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let mut config = cfg(&dir, &direct.url);
    config.accounts[0].proxy = Some(first.url.clone());
    config.accounts[1].proxy = Some(second.url.clone());
    let pool = AccountPool::from_config(&config).unwrap();
    let one = pool.by_id("one").unwrap().unwrap();
    let two = pool.by_id("two").unwrap().unwrap();
    let before_two = std::fs::read(two.private_home().join("auth.json")).unwrap();
    pool.refresh_once("one", one.revision()).await.unwrap();
    assert!(matches!(
        pool.refresh_once("two", two.revision()).await,
        Err(AccountError::IdentityChanged)
    ));
    assert_eq!(
        std::fs::read(two.private_home().join("auth.json")).unwrap(),
        before_two
    );
    // A second 401 for the failed revision does not repeat the token POST.
    auth(
        &dir.path().join("two.json"),
        "foreign-workspace",
        "foreign-user",
        "foreign-source-access",
    );
    assert!(matches!(
        pool.reload_auth("two"),
        Err(AccountError::IdentityChanged)
    ));
    assert!(matches!(
        pool.refresh_once("two", two.revision()).await,
        Err(AccountError::RefreshFailed)
    ));
    assert_eq!(first.seen.lock().unwrap().len(), 1);
    assert_eq!(second.seen.lock().unwrap().len(), 1);
    assert_codex_defaults(&first.seen.lock().unwrap()[0].headers);
    assert_codex_defaults(&second.seen.lock().unwrap()[0].headers);
    assert!(direct.seen.lock().unwrap().is_empty());
    let a: Value = serde_json::from_slice(&first.seen.lock().unwrap()[0].body).unwrap();
    let b: Value = serde_json::from_slice(&second.seen.lock().unwrap()[0].body).unwrap();
    assert_eq!(a["refresh_token"], "refresh-workspace-one");
    assert_eq!(b["refresh_token"], "refresh-workspace-two");
}

#[tokio::test]
async fn official_workspace_and_usage_are_account_scoped_and_only_responses_use_selected_origin() {
    let mode = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let current = mode.clone();
    let upstream=server(move |path,_,_| {use std::sync::atomic::Ordering;
        let response=if path.ends_with("accounts/check") {let origin=if current.load(Ordering::Relaxed)==0 {"https://workspace.example.invalid:8443"}else{"https://evil.example.invalid/path"};
            json!({"accounts":[{"id":"workspace-two","workspace_backend_origin":"https://foreign.example.invalid","account_routing_override":"us"},
            {"id":"workspace-one","workspace_backend_origin":origin,"account_routing_override":"us_cr"}],"default_account_id":"workspace-two"})
        } else {assert!(path.ends_with("wham/usage"));json!({"account_id":"workspace-one","plan_type":"plus","rate_limit":{"allowed":false,"limit_reached":true,
            "primary_window":{"used_percent":100,"limit_window_seconds":301,"reset_after_seconds":60,"reset_at":1900000000}},
            "additional_rate_limits":[{"metered_feature":"image_gen","limit_name":"Images","normal_model_slug":"image-model","rate_limit":{"allowed":true,"limit_reached":false}}]})};
        (StatusCode::OK,response)
    }).await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, &upstream.url);
    let pool = AccountPool::from_config(&config).unwrap();
    let a = pool.by_id("one").unwrap().unwrap();
    let base = format!("{}/backend-api/codex", upstream.url);
    let route = a.responses_route(&base).await.unwrap();
    assert_eq!(
        route.base_url,
        "https://workspace.example.invalid:8443/backend-api/codex"
    );
    assert_eq!(route.account_routing_override.as_deref(), Some("us_cr"));
    let custom = "https://operator.example.invalid/backend-api/codex";
    assert_eq!(a.responses_route(custom).await.unwrap().base_url, custom);
    assert_eq!(
        a.responses_route(&config.base_url).await.unwrap().base_url,
        config.base_url
    );
    assert_eq!(upstream.seen.lock().unwrap().len(), 1);
    let usage = pool.refresh_quota("one").await.unwrap();
    assert_eq!(usage[0].primary.as_ref().unwrap().window_minutes, Some(6));
    assert_eq!(usage[1].normal_model_slug.as_deref(), Some("image-model"));
    assert!(a.availability().unwrap().quota_cooldown);
    let selected = pool.next_enabled().unwrap().unwrap();
    assert_eq!(selected.id(), "two");
    for seen in upstream.seen.lock().unwrap().iter() {
        assert_codex_defaults(&seen.headers);
        assert_eq!(seen.headers["chatgpt-account-id"], "workspace-one");
        assert_eq!(seen.headers["authorization"], "Bearer access-one");
    }
    mode.store(1, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        a.refresh_workspace_route(true).await,
        Err(RoutingError::InvalidRoute)
    ));
}

#[tokio::test]
async fn official_no_constraint_backend_retains_effective_origin_and_validates_independent_override()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mode = Arc::new(AtomicUsize::new(0));
    let current = mode.clone();
    let upstream = server(move |path, _, _| {
        assert!(path.ends_with("/wham/accounts/check"));
        let (backend, routing) = match current.load(Ordering::Relaxed) {
            0 => (json!("NO_CONSTRAINT"), "NO_CONSTRAINT"),
            1 => (json!("NO_CONSTRAINT"), "us"),
            2 => (json!("NO_CONSTRAINT"), "us_cr"),
            3 => (json!("NO_CONSTRAINT"), "unknown"),
            4 => (json!(" https://workspace.example.invalid"), "us"),
            _ => (Value::Null, "us"),
        };
        (StatusCode::OK, json!({
            "account_ordering":["workspace-two","workspace-one"],
            "accounts":[
                {"id":"workspace-two","workspace_backend_origin":"https://foreign.example.invalid","account_routing_override":"us"},
                {"id":"workspace-one","workspace_backend_origin":backend,"account_routing_override":routing}
            ],
            "default_account_id":"workspace-two"
        }))
    }).await;
    let directory = TempDir::new().unwrap();
    sources(&directory);
    let config = cfg(&directory, &upstream.url);
    let pool = AccountPool::from_config(&config).unwrap();
    let account = pool.by_id("one").unwrap().unwrap();
    let base = format!("{}/backend-api/codex", upstream.url);
    for (mode_value, expected) in [(0, None), (1, Some("us")), (2, Some("us_cr"))] {
        mode.store(mode_value, Ordering::Relaxed);
        account.refresh_workspace_route(true).await.unwrap();
        let route = account.responses_route(&base).await.unwrap();
        assert_eq!(route.base_url, base);
        assert_eq!(route.account_routing_override.as_deref(), expected);
    }
    for mode_value in [3, 4, 5] {
        mode.store(mode_value, Ordering::Relaxed);
        assert!(matches!(
            account.refresh_workspace_route(true).await,
            Err(RoutingError::InvalidRoute)
        ));
    }
    let seen = upstream.seen.lock().unwrap();
    assert_eq!(seen.len(), 6);
    assert!(
        seen.iter()
            .all(|request| request.headers["chatgpt-account-id"] == "workspace-one")
    );
}

#[tokio::test]
async fn pkce_device_cancel_and_browser_completion_write_only_the_private_home() {
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = polls.clone();
    let issuer=server(move |path,body,_| {use std::sync::atomic::Ordering;
        match path {
            "/api/accounts/deviceauth/usercode"=>(StatusCode::OK,json!({"device_auth_id":"device-one","usercode":"CODE-ONE","interval":"0"})),
            "/api/accounts/deviceauth/token"=>{let value:Value=serde_json::from_slice(body).unwrap();assert_eq!(value["device_auth_id"],"device-one");
                if counter.fetch_add(1,Ordering::Relaxed)==0 {(StatusCode::FORBIDDEN,json!({}))}else{(StatusCode::OK,json!({"authorization_code":"device-code","code_verifier":"device-verifier","code_challenge":"device-challenge"}))}},
            "/oauth/token"=>(StatusCode::OK,tokens("workspace-one","user-one","login-access-one")),
            _=>panic!("unexpected OAuth path")
        }
    }).await;
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("private-home");
    let login = OAuthLogin::new(
        &home,
        oauth_login_client(None).unwrap(),
        &issuer.url,
        None,
        true,
    )
    .unwrap();
    let invalid = login
        .begin_browser("http://127.0.0.1:1455/auth/callback")
        .unwrap();
    let url = url::Url::parse(&invalid.auth_url).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query["scope"],
        "openid profile email offline_access api.connectors.read api.connectors.invoke"
    );
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["client_id"], codex_login::oauth_client_id());
    assert_eq!(
        invalid.complete("wrong-state", "code").await,
        Err(OAuthError::InvalidResponse)
    );
    assert!(issuer.seen.lock().unwrap().is_empty());
    let cancelled = login
        .begin_browser("http://127.0.0.1:1455/auth/callback")
        .unwrap();
    let state = url::Url::parse(&cancelled.auth_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    cancelled.cancellation().cancel();
    assert_eq!(
        cancelled.complete(&state, "code").await,
        Err(OAuthError::Cancelled)
    );
    assert!(!home.join("auth.json").exists());
    let device = login.begin_device().await.unwrap();
    assert_eq!(device.user_code, "CODE-ONE");
    assert_eq!(
        device.verification_url,
        format!("{}/codex/device", issuer.url)
    );
    device.complete().await.unwrap();
    let original = std::fs::read(home.join("auth.json")).unwrap();
    let browser = login
        .begin_browser("http://127.0.0.1:1455/auth/callback")
        .unwrap();
    let state = url::Url::parse(&browser.auth_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let browser_challenge = url::Url::parse(&browser.auth_url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code_challenge")
        .unwrap()
        .1
        .into_owned();
    browser.complete(&state, "browser-code").await.unwrap();
    assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 2);
    let seen = issuer.seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|s| s.path == "/oauth/token").count(), 2);
    for request in seen.iter() {
        assert_raw_login(&request.headers);
    }
    let last = &seen.last().unwrap().body;
    let form: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(last).into_owned().collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "browser-code");
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(form["code_verifier"].as_bytes())),
        browser_challenge
    );
    drop(seen);
    assert!(!original.is_empty());
}

#[test]
fn rest_capacity_quota_and_delete_drain_preserve_existing_requests_and_source() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, "http://127.0.0.1:1");
    let before = std::fs::read(dir.path().join("one.json")).unwrap();
    let pool = AccountPool::from_config(&config).unwrap();
    pool.set_capacity("one", 1).unwrap();
    let lease = pool.lease("one", true).unwrap().unwrap();
    assert!(pool.lease("one", false).unwrap().is_none());
    drop(lease);
    pool.rest("one", Duration::from_secs(60)).unwrap();
    assert!(pool.lease("one", true).unwrap().is_none());
    let existing = pool.lease("one", false).unwrap().unwrap();
    let home = existing.account().private_home().to_owned();
    let mut excluded = HashSet::new();
    excluded.insert("two".to_owned());
    assert!(pool.next_eligible_excluding(&excluded).unwrap().is_none());
    pool.mark_quota_cooldown("one", Duration::from_secs(60))
        .unwrap();
    drop(existing);
    assert!(pool.lease("one", false).unwrap().is_none());
    pool.clear_quota_cooldown("one").unwrap();
    let draining = pool.lease("one", false).unwrap().unwrap();
    assert!(!pool.delete_draining("one").unwrap());
    assert!(pool.by_id("one").unwrap().is_none());
    assert!(home.join("auth.json").exists());
    let mut headers = HeaderMap::new();
    draining.account().authorize_headers(&mut headers).unwrap();
    assert_eq!(headers["authorization"], "Bearer access-one");
    drop(draining);
    assert!(!home.join("auth.json").exists());
    let restarted = AccountPool::from_config(&config).unwrap();
    assert!(restarted.by_id("one").unwrap().is_none());
    assert_eq!(std::fs::read(dir.path().join("one.json")).unwrap(), before);
}

async fn admin_request(
    state: &Arc<right_codex::gateway::AppState>,
    path: &str,
    method: &str,
    body: Option<Value>,
    authenticated: bool,
) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut builder = Request::builder().uri(path).method(method);
    if authenticated {
        builder = builder.header("authorization", "Bearer admin-fixture-secret");
    }
    let body = if let Some(value) = body {
        builder = builder.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value).unwrap())
    } else {
        Body::empty()
    };
    let response = right_codex::admin::router()
        .with_state(state.clone())
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let raw = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&raw).unwrap_or_else(|_| json!({"html":true})),
    )
}
#[tokio::test]
async fn admin_pkce_registers_a_new_private_account_and_disabled_metadata_survives_restart() {
    let issuer = server(|path, _, _| {
        assert_eq!(path, "/oauth/token");
        (
            StatusCode::OK,
            tokens("new-workspace", "new-user", "new-login-access"),
        )
    })
    .await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, &issuer.url);
    let pool = AccountPool::from_config(&config).unwrap();
    let state = right_codex::gateway::AppState::new(config.clone(), pool);
    assert_eq!(
        admin_request(&state, "/admin/api/accounts", "GET", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let begin = admin_request(
        &state,
        "/admin/api/oauth/browser",
        "POST",
        Some(json!({"proxy":null})),
        true,
    )
    .await;
    assert_eq!(begin.0, StatusCode::OK);
    let job = begin.1["job_id"].as_str().unwrap();
    let id = begin.1["account_id"].as_str().unwrap();
    let auth_url = url::Url::parse(begin.1["authorization_url"].as_str().unwrap()).unwrap();
    let redirect = auth_url
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .unwrap()
        .1
        .into_owned();
    let redirect_url = url::Url::parse(&redirect).unwrap();
    assert_eq!(redirect_url.host_str(), Some("127.0.0.1"));
    assert!(matches!(redirect_url.port(), Some(1455 | 1457)));
    let callback_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let nonce = auth_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        callback_client
            .get(format!("{redirect}?state=wrong&code=fixture"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(issuer.seen.lock().unwrap().is_empty());
    let callback = format!("/auth/callback?state={nonce}&code=fixture");
    assert_eq!(
        callback_client
            .get(format!("{redirect}?state={nonce}&code=fixture"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        admin_request(&state, &callback, "GET", None, false).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(issuer.seen.lock().unwrap().len(), 1);
    assert_raw_login(&issuer.seen.lock().unwrap()[0].headers);
    let status = admin_request(
        &state,
        &format!("/admin/api/oauth/{job}"),
        "GET",
        None,
        true,
    )
    .await;
    assert_eq!(status.1["status"], "completed");
    let account = state.accounts.by_id(id).unwrap().unwrap();
    let created = account.created_at_unix_ms();
    assert_eq!(account.workspace_account_id(), "new-workspace");
    assert!(account.private_home().starts_with(&config.state_dir));
    assert_eq!(
        admin_request(
            &state,
            &format!("/admin/api/accounts/{id}"),
            "PATCH",
            Some(json!({"enabled":false})),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(state.accounts.by_id(id).unwrap().is_none());
    assert!(state.accounts.all().unwrap().iter().any(|a| a.id() == id));
    let restarted = AccountPool::from_config(&config).unwrap();
    let disabled = restarted.managed(id).unwrap().unwrap();
    assert!(!disabled.availability().unwrap().enabled);
    assert_eq!(disabled.created_at_unix_ms(), created);
    restarted.set_enabled(id, true).unwrap();
    assert!(restarted.by_id(id).unwrap().is_some());
    assert!(matches!(
        restarted.add_from_home("../escape", None),
        Err(AccountError::InvalidConfiguration)
    ));
}
#[tokio::test]
async fn admin_cancelled_browser_callback_cannot_consume_code_or_create_account() {
    let issuer = server(|_, _, _| panic!("cancelled login contacted issuer")).await;
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, &issuer.url);
    let state = right_codex::gateway::AppState::new(
        config.clone(),
        AccountPool::from_config(&config).unwrap(),
    );
    let begin = admin_request(
        &state,
        "/admin/api/oauth/browser",
        "POST",
        Some(json!({"proxy":null})),
        true,
    )
    .await;
    assert_eq!(begin.0, StatusCode::OK);
    let job = begin.1["job_id"].as_str().unwrap();
    let account = begin.1["account_id"].as_str().unwrap();
    let nonce = url::Url::parse(begin.1["authorization_url"].as_str().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        admin_request(
            &state,
            &format!("/admin/api/oauth/{job}"),
            "DELETE",
            None,
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let callback = format!("/auth/callback?state={nonce}&code=fixture");
    assert_eq!(
        admin_request(&state, &callback, "GET", None, false).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(state.accounts.by_id(account).unwrap().is_none());
    assert!(issuer.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn admin_scheduling_is_authenticated_persistent_and_fact_filter_is_read_only() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let config = cfg(&dir, "http://127.0.0.1:1");
    let state = right_codex::gateway::AppState::new(
        config.clone(),
        AccountPool::from_config(&config).unwrap(),
    );
    assert_eq!(
        admin_request(&state, "/admin/api/settings", "GET", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let first = admin_request(&state, "/admin/api/settings", "GET", None, true).await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(
        first.1["max_sessions_by_account_age"],
        json!([2, 4, 8, 16, 32])
    );
    let patched = admin_request(
        &state,
        "/admin/api/settings",
        "PATCH",
        Some(json!({"idle_timeout_secs":77,"max_sessions_by_account_age":[1,3,5,7,9]})),
        true,
    )
    .await;
    assert_eq!(patched.0, StatusCode::OK);
    assert_eq!(patched.1["startup_spacing_secs"], 2);
    assert_eq!(
        admin_request(
            &state,
            "/admin/api/settings",
            "PATCH",
            Some(json!({"rest_percent":101})),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin_request(
            &state,
            "/admin/api/settings",
            "PATCH",
            Some(json!({"foreign_setting":true})),
            true
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let original = state.facts.snapshot().len();
    assert_eq!(
        admin_request(
            &state,
            "/admin/api/telemetry/deliveries?account_id=one",
            "DELETE",
            None,
            false
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let deliveries = admin_request(
        &state,
        "/admin/api/telemetry/deliveries?account_id=one",
        "GET",
        None,
        true,
    )
    .await;
    assert_eq!(deliveries.0, StatusCode::OK);
    assert_eq!(deliveries.1["accounts"][0]["account_id"], "one");
    let clear = admin_request(
        &state,
        "/admin/api/telemetry/deliveries?account_id=one",
        "DELETE",
        None,
        true,
    )
    .await;
    assert_eq!(clear.0, StatusCode::OK);
    assert_eq!(clear.1["business_facts_unchanged"], true);

    let filtered =
        admin_request(&state, "/admin/api/facts?account_id=one", "GET", None, true).await;
    assert_eq!(filtered.0, StatusCode::OK);
    assert!(filtered.1["facts"].as_array().unwrap().is_empty());
    assert_eq!(state.facts.snapshot().len(), original);
    let restored = right_codex::gateway::AppState::new(
        config.clone(),
        AccountPool::from_config(&config).unwrap(),
    );
    assert_eq!(restored.scheduling().idle_timeout_secs, 77);
    assert_eq!(
        restored.scheduling().max_sessions_by_account_age,
        [1, 3, 5, 7, 9]
    );
}

#[test]
fn oauth_issuer_and_workspace_discovery_config_changes_retire_the_account_revision() {
    let dir = TempDir::new().unwrap();
    sources(&dir);
    let original = cfg(&dir, "http://127.0.0.1:1");
    let before = AccountPool::from_config(&original)
        .unwrap()
        .by_id("one")
        .unwrap()
        .unwrap();
    let mut config = original.clone();
    config.oauth_issuer = "http://127.0.0.1:2".into();
    let changed = AccountPool::from_config(&config)
        .unwrap()
        .by_id("one")
        .unwrap()
        .unwrap();
    assert_ne!(before.revision(), changed.revision());
    config = original;
    config.chatgpt_base_url = "http://127.0.0.1:3/backend-api".into();
    let changed = AccountPool::from_config(&config)
        .unwrap()
        .by_id("one")
        .unwrap()
        .unwrap();
    assert_ne!(before.revision(), changed.revision());
}

#[test]
fn eligibility_probes_never_advance_round_robin_and_use_the_actual_selection_gate() {
    let directory = TempDir::new().unwrap();
    sources(&directory);
    auth(
        &directory.path().join("three.json"),
        "workspace-three",
        "user-three",
        "access-three",
    );
    let mut config = cfg(&directory, "http://127.0.0.1:1");
    config.accounts.push(right_codex::config::AccountConfig {
        id: "three".to_owned(),
        auth_path: directory.path().join("three.json"),
        proxy: None,
        enabled: true,
    });
    let pool = AccountPool::from_config(&config).unwrap();
    let none = HashSet::new();
    for expected in ["one", "two", "three", "one", "two", "three"] {
        for _ in 0..7 {
            assert!(pool.has_eligible_excluding(&none).unwrap());
        }
        assert_eq!(
            pool.next_eligible_excluding(&none).unwrap().unwrap().id(),
            expected
        );
    }
    pool.set_capacity("one", 1).unwrap();
    let lease = pool.lease("one", false).unwrap().unwrap();
    pool.rest("two", Duration::from_secs(60)).unwrap();
    pool.mark_quota_cooldown("three", Duration::from_secs(60))
        .unwrap();
    assert!(!pool.has_eligible_excluding(&none).unwrap());
    assert!(pool.next_eligible_excluding(&none).unwrap().is_none());
    drop(lease);
    assert!(pool.has_eligible_excluding(&none).unwrap());
    assert!(
        !pool
            .has_eligible_excluding(&HashSet::from(["one".to_owned()]))
            .unwrap()
    );
    assert_eq!(
        pool.next_eligible_excluding(&none).unwrap().unwrap().id(),
        "one"
    );
}
