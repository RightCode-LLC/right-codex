// Derived from OpenAI Codex, Copyright OpenAI; Apache-2.0.
// Fixed source: a956835d020762cb2b570053af06f643a11c0ecc.
// Sources: login/src/oauth/{client,authorization,pkce}.rs,
// login/src/device_code_auth.rs, login/src/auth/manager.rs.
// See vendor/codex/LICENSE and vendor/codex/NOTICE for upstream notices.
// This small adaptation gives the upstream wire rules an instance-owned
// reqwest client and issuer; it never changes process environment variables.

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

const MAX_REPLY: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("OAuth transport failed")]
    Transport,
    #[error("OAuth authority rejected the request")]
    Rejected,
    #[error("OAuth response is invalid")]
    InvalidResponse,
    #[error("OAuth operation was cancelled")]
    Cancelled,
    #[error("OAuth operation expired")]
    Expired,
    #[error("OAuth private storage is unavailable")]
    Storage,
    #[error("OAuth account identity changed")]
    IdentityChanged,
    #[error("OAuth issuer is invalid")]
    InvalidIssuer,
}

pub(crate) struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Self {
        // Four independently random UUIDv4 values supply > 43 verifier chars;
        // RFC7636 S256 encoding is the same rule as the pinned source.
        let mut bytes = Vec::with_capacity(64);
        for _ in 0..4 {
            bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        }
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier,
            challenge,
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct Tokens {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

pub(crate) fn issuer(value: &str, allow_insecure: bool) -> Result<String, OAuthError> {
    let url = Url::parse(value).map_err(|_| OAuthError::InvalidIssuer)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https"
            || (allow_insecure
                && url.scheme() == "http"
                && url.host_str().is_some_and(|h| {
                    h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
                })))
    {
        return Err(OAuthError::InvalidIssuer);
    }
    Ok(value.trim_end_matches('/').to_owned())
}

pub(crate) fn authorization_url(
    issuer: &str,
    redirect: &str,
    pkce: &Pkce,
    state: &str,
    workspace: Option<&str>,
) -> Result<String, OAuthError> {
    let mut url =
        Url::parse(&format!("{issuer}/oauth/authorize")).map_err(|_| OAuthError::InvalidIssuer)?;
    let client_id = codex_login::oauth_client_id();
    let originator = codex_login::default_client::originator().value;
    let mut q = url.query_pairs_mut();
    q.extend_pairs([
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect),
        (
            "scope",
            "openid profile email offline_access api.connectors.read api.connectors.invoke",
        ),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
        ("originator", originator.as_str()),
    ]);
    if let Some(workspace) = workspace {
        q.append_pair("allowed_workspace_id", workspace);
    }
    drop(q);
    Ok(url.into())
}

pub(crate) async fn json_reply<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, OAuthError> {
    if !response.status().is_success() {
        return Err(OAuthError::Rejected);
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| OAuthError::Transport)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_REPLY {
            return Err(OAuthError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| OAuthError::InvalidResponse)
}

pub(crate) async fn exchange(
    client: &reqwest::Client,
    issuer: &str,
    redirect: &str,
    verifier: &str,
    code: &str,
) -> Result<Tokens, OAuthError> {
    let client_id = codex_login::oauth_client_id();
    let response = client
        .post(format!("{issuer}/oauth/token"))
        .timeout(Duration::from_secs(30))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("code", code),
            ("redirect_uri", redirect),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .map_err(|_| OAuthError::Transport)?;
    json_reply(response).await
}

pub(crate) async fn refresh(
    client: &reqwest::Client,
    issuer: &str,
    refresh_token: &str,
) -> Result<Tokens, OAuthError> {
    let response = client
        .post(format!("{issuer}/oauth/token"))
        .timeout(Duration::from_secs(30))
        .json(&serde_json::json!({"grant_type":"refresh_token",
            "client_id":codex_login::oauth_client_id(), "refresh_token":refresh_token}))
        .send()
        .await
        .map_err(|_| OAuthError::Transport)?;
    json_reply(response).await
}
