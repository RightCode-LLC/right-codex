//! Synthetic Pro OAuth accounts and a child-process-only OTel environment.
//! Every inspected body was received by the loopback OTLP collector.
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use base64::Engine;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, EntityRef, KeyValue, any_value};
use opentelemetry_sdk::resource::{ResourceDetector, TelemetryResourceDetector};
use prost::Message;
use right_codex::accounts::{Account, AccountPool};
use right_codex::config::{AccountConfig, GatewayConfig};
use right_codex::observability::TelemetryRegistry;
use right_codex::telemetry::OutboundIdentity;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const CHILD: &str = "CODEX_TEST_METRIC_RESOURCE_CHILD";
const ENV_RESOURCE: &str = "host.id=RESOURCE_SENTINEL_SHARED_HOST,service.instance.id=RESOURCE_SENTINEL_SHARED_INSTANCE,container.id=RESOURCE_SENTINEL_CONTAINER,user.account_id=RESOURCE_SENTINEL_OTHER_ACCOUNT,custom.identity=RESOURCE_SENTINEL_CUSTOM,service.name=RESOURCE_SENTINEL_SERVICE,service.version=RESOURCE_SENTINEL_VERSION,env=RESOURCE_SENTINEL_ENV,os=RESOURCE_SENTINEL_OS,os_version=RESOURCE_SENTINEL_OS_VERSION,telemetry.sdk.name=RESOURCE_SENTINEL_SDK,telemetry.sdk.language=RESOURCE_SENTINEL_LANGUAGE,telemetry.sdk.version=RESOURCE_SENTINEL_SDK_VERSION";

#[test]
fn environment_and_cold_queue_resources_are_isolated_for_two_pro_accounts() {
    if std::env::var_os(CHILD).is_none() {
        let home = TempDir::new().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "environment_and_cold_queue_resources_are_isolated_for_two_pro_accounts",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env(CHILD, "1")
            .env("OTEL_RESOURCE_ATTRIBUTES", ENV_RESOURCE)
            .env("OTEL_SERVICE_NAME", "RESOURCE_SENTINEL_SERVICE_NAME")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated metric child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    tokio::runtime::Runtime::new().unwrap().block_on(exercise());
}

#[derive(Default)]
struct Collector {
    bodies: Mutex<Vec<ExportMetricsServiceRequest>>,
}

async fn collect(
    State(collector): State<Arc<Collector>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    assert_eq!(headers["content-type"], "application/x-protobuf");
    assert!(!headers.contains_key("authorization"));
    assert!(!headers.contains_key("chatgpt-account-id"));
    collector
        .bodies
        .lock()
        .unwrap()
        .push(ExportMetricsServiceRequest::decode(body).unwrap());
    StatusCode::OK
}

fn pro_auth(path: &Path, id: &str) {
    let claims = json!({
        "email":format!("{id}@fixture.invalid"),"exp":3000000000_u64,
        "https://api.openai.com/auth":{
            "chatgpt_account_id":format!("workspace-{id}"),
            "chatgpt_user_id":format!("user-{id}"),"chatgpt_plan_type":"pro"
        }
    });
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&claims).unwrap());
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "auth_mode":"chatgpt","tokens":{
                "id_token":format!("eyJhbGciOiJub25lIn0.{payload}.synthetic"),
                "access_token":format!("synthetic-access-{id}"),
                "refresh_token":format!("synthetic-refresh-{id}"),
                "account_id":format!("workspace-{id}")
            },"last_refresh":"2026-10-10T00:00:00Z"
        }))
        .unwrap(),
    )
    .unwrap();
}

fn identity(account: &Account) -> OutboundIdentity {
    OutboundIdentity {
        account_id: account.id().to_owned(),
        workspace_account_id: account.workspace_account_id().to_owned(),
        auth_revision: account.revision().to_owned(),
        thread_id: Uuid::new_v4().to_string(),
        turn_id: Uuid::new_v4().to_string(),
        attempt_id: Uuid::new_v4().to_string(),
        endpoint: "/responses".to_owned(),
    }
}

fn expected_attributes() -> BTreeMap<String, String> {
    let mut expected: BTreeMap<String, String> = TelemetryResourceDetector
        .detect()
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    expected.extend([
        (
            "service.name".into(),
            codex_login::default_client::originator().value,
        ),
        ("service.version".into(), right_codex::CODEX_VERSION.into()),
        ("env".into(), "dev".into()),
    ]);
    let os = os_info::get();
    for (key, value) in [
        ("os", os.os_type().to_string()),
        ("os_version", os.version().to_string()),
    ] {
        let value = codex_otel::sanitize_metric_tag_value(&value);
        if value != "unspecified" {
            expected.insert(key.to_owned(), value);
        }
    }
    expected
}

fn assert_isolated(export: &ExportMetricsServiceRequest, expected_kind: &str, other_kind: &str) {
    assert!(!export.resource_metrics.is_empty());
    let expected = expected_attributes();
    for metrics in &export.resource_metrics {
        assert!(metrics.schema_url.is_empty());
        let resource = metrics.resource.as_ref().unwrap();
        assert!(resource.entity_refs.is_empty());
        assert_eq!(resource.dropped_attributes_count, 0);
        let actual: BTreeMap<String, String> = resource
            .attributes
            .iter()
            .map(|attribute| {
                let Some(any_value::Value::StringValue(value)) =
                    attribute.value.as_ref().and_then(|v| v.value.as_ref())
                else {
                    panic!("only the actual static string resource fields are expected");
                };
                (attribute.key.clone(), value.clone())
            })
            .collect();
        assert_eq!(
            actual.len(),
            resource.attributes.len(),
            "resource keys must be unique"
        );
        assert_eq!(actual, expected);
    }
    let wire = serde_json::to_string(export).unwrap();
    assert!(!wire.contains("RESOURCE_SENTINEL"));
    assert!(!wire.contains("COLD_SENTINEL"));
    assert!(!wire.contains("synthetic-access"));
    assert!(!wire.contains("workspace-alpha"));
    assert!(!wire.contains("workspace-beta"));
    assert!(wire.contains(expected_kind));
    assert!(!wire.contains(other_kind));
}

fn poisoned_queue(account: &Account, endpoint: &str, original: &ExportMetricsServiceRequest) {
    let mut export = original.clone();
    // Include several ResourceMetrics entries to ensure the boundary visits
    // every resource, including old schema and entity-reference metadata.
    export
        .resource_metrics
        .push(export.resource_metrics[0].clone());
    for metrics in &mut export.resource_metrics {
        metrics.schema_url = "COLD_SENTINEL_SCHEMA".into();
        let resource = metrics.resource.as_mut().unwrap();
        resource.attributes.extend(
            ["host.id", "service.instance.id", "user.account_id"]
                .into_iter()
                .map(|key| KeyValue {
                    key: key.into(),
                    value: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(
                            "COLD_SENTINEL_SHARED_ID".into(),
                        )),
                    }),
                }),
        );
        for attribute in &mut resource.attributes {
            attribute.value = Some(AnyValue {
                value: Some(any_value::Value::StringValue(
                    "COLD_SENTINEL_FAKE_STATIC_OR_UNIQUE".into(),
                )),
            });
        }
        resource.dropped_attributes_count = 71;
        resource.entity_refs.push(EntityRef {
            schema_url: "COLD_SENTINEL_ENTITY".into(),
            ..Default::default()
        });
    }
    let mut hash = Sha256::new();
    hash.update([2]);
    hash.update(endpoint.as_bytes());
    let route = format!("{:x}", hash.finalize());
    let directory = account
        .private_home()
        .join("official-metrics")
        .join(account.revision())
        .join(route);
    let body = export.encode_to_vec();
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut bytes = b"OTM1".to_vec();
    bytes.extend(created.to_be_bytes());
    bytes.push(2);
    bytes.extend((body.len() as u32).to_be_bytes());
    bytes.extend(body);
    std::fs::write(directory.join(format!("{created:020}-cold.pending")), bytes).unwrap();
}

async fn exercise() {
    let directory = TempDir::new().unwrap();
    let collector = Arc::new(Collector::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1/metrics", listener.local_addr().unwrap());
    let server = tokio::spawn({
        let collector = collector.clone();
        async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/v1/metrics", post(collect))
                    .with_state(collector),
            )
            .await
            .unwrap();
        }
    });
    let mut config = GatewayConfig {
        allow_insecure_http: true,
        state_dir: directory.path().join("state"),
        ..GatewayConfig::default()
    };
    for id in ["alpha", "beta"] {
        let auth_path = directory.path().join(format!("{id}.json"));
        pro_auth(&auth_path, id);
        config.accounts.push(AccountConfig {
            id: id.into(),
            auth_path,
            proxy: None,
            enabled: true,
        });
    }
    config.telemetry.otlp_endpoint = Some(endpoint.clone());
    config.telemetry.allow_loopback_http = true;
    config.telemetry.max_batch = 1;
    let pool = AccountPool::from_config(&config).unwrap();
    let accounts = [
        pool.by_id("alpha").unwrap().unwrap(),
        pool.by_id("beta").unwrap().unwrap(),
    ];
    let kinds = ["response.completed", "response.created"];
    let registry = TelemetryRegistry::new(config.telemetry.clone()).unwrap();
    for (index, account) in accounts.iter().enumerate() {
        let hook = registry
            .for_account(account, identity(account), "gpt-5", "gpt-5")
            .unwrap();
        hook.sse_hook().on_sse_poll(
            &Ok(Some(Ok(eventsource_stream::Event {
                event: kinds[index].into(),
                ..Default::default()
            }))),
            Duration::from_millis(11 + index as u64),
        );
        assert_eq!(
            registry.flush_account(account).await.unwrap().acked_batches,
            1
        );
    }
    let fresh = collector.bodies.lock().unwrap().clone();
    assert_eq!(fresh.len(), 2);
    for (index, export) in fresh.iter().enumerate() {
        assert_isolated(export, kinds[index], kinds[1 - index]);
    }
    drop(registry);
    for (index, account) in accounts.iter().enumerate() {
        poisoned_queue(account, &endpoint, &fresh[index]);
    }
    let restored = TelemetryRegistry::new(config.telemetry).unwrap();
    for account in &accounts {
        assert_eq!(
            restored.flush_account(account).await.unwrap().acked_batches,
            1
        );
    }
    let restored_bodies = collector.bodies.lock().unwrap();
    assert_eq!(restored_bodies.len(), 4);
    for index in 0..2 {
        assert_eq!(restored_bodies[index + 2].resource_metrics.len(), 2);
        assert_isolated(&restored_bodies[index + 2], kinds[index], kinds[1 - index]);
    }
    server.abort();
}
