//! Read-only network diagnostics; output excludes credentials and account IDs.
use right_codex::{accounts::AccountPool, config::GatewayConfig};
use serde_json::json;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("config required"))?;
    let config = GatewayConfig::load(std::path::Path::new(&path))?;
    let pool = AccountPool::from_config(&config)?;
    let account = pool
        .next_enabled()?
        .ok_or_else(|| anyhow::anyhow!("account required"))?;
    let route = account.responses_route(&config.base_url).await;
    println!(
        "{}",
        json!({"route_result":route.as_ref().map(|r|url::Url::parse(&r.base_url).ok().map(|u|u.origin().ascii_serialization())).map_err(|e|format!("{e:?}")),"proxy_configured":account.proxy().is_some()})
    );
    let mut headers = http::HeaderMap::new();
    account.authorize_headers(&mut headers)?;
    let response = account
        .client()
        .get(format!(
            "{}/wham/accounts/check",
            account.chatgpt_base_url().trim_end_matches('/')
        ))
        .headers(headers)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = response.bytes().await?;
    let parsed = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    let decoded =
        serde_json::from_slice::<codex_backend_client::AccountsCheckResponse>(&bytes).ok();
    let selected = decoded.as_ref().and_then(|response| {
        response
            .accounts
            .iter()
            .find(|entry| entry.id == account.workspace_account_id())
    });
    let origin = selected.and_then(|entry| entry.workspace_backend_origin.as_deref());
    let origin_url = origin.and_then(|origin| url::Url::parse(origin).ok());
    let public_override = selected
        .and_then(|entry| entry.account_routing_override.as_deref())
        .map(|v| match v {
            "NO_CONSTRAINT" | "us" | "us_cr" => v,
            _ => "other",
        });
    println!(
        "{}",
        json!({"status":status,"content_type":content_type,"body_bytes":bytes.len(),"top_keys":parsed.as_ref().and_then(|v|v.as_object()).map(|o|o.keys().collect::<Vec<_>>()),"error_present":parsed.as_ref().is_some_and(|v|!v["error"].is_null()),"official_dto_decoded":decoded.is_some(),"selected_workspace_present":selected.is_some(),"backend_present":origin.is_some(),"backend_no_constraint":origin==Some("NO_CONSTRAINT"),"backend_url_parsed":origin_url.is_some(),"backend_https":origin_url.as_ref().is_some_and(|u|u.scheme()=="https"),"backend_root_path":origin_url.as_ref().is_some_and(|u|u.path()=="/"),"backend_has_credentials":origin_url.as_ref().is_some_and(|u|!u.username().is_empty()||u.password().is_some()),"backend_has_query_or_fragment":origin_url.as_ref().is_some_and(|u|u.query().is_some()||u.fragment().is_some()),"routing_override_kind":public_override,"proxy_environment_names":(["HTTPS_PROXY","HTTP_PROXY","ALL_PROXY","https_proxy","http_proxy","all_proxy"].iter().filter(|n|std::env::var_os(n).is_some()).collect::<Vec<_>>())})
    );
    Ok(())
}
