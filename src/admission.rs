//! Model ingress assumes the official OAuth client and admits configured peers.
//! Bearer contents are never used as an upstream credential or logged. Trust is
//! provided by the explicit network policy, not by decoding an unverified JWT.
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http::{HeaderMap, StatusCode, header};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::gateway::{AppState, error};

pub async fn require_oauth_peer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let trusted = peer.is_some_and(|ip| {
        state
            .config
            .trusted_networks
            .iter()
            .filter_map(|value| value.parse::<ipnet::IpNet>().ok())
            .any(|network| network.contains(&ip))
    });
    if !trusted {
        return error(
            StatusCode::FORBIDDEN,
            "untrusted_client_network",
            "This client network is not allowed",
            "客户端网络未获准入",
        );
    }
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !bearer.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 16384
            && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }) {
        return error(
            StatusCode::UNAUTHORIZED,
            "oauth_header_required",
            "A native OAuth authorization header is required",
            "需要原版 OAuth 认证头",
        );
    }
    next.run(request).await
}

/// OAuth refresh changes the access token, so it must not key the conversation.
/// Account labels remain strictly local and are salted by the gateway domain.
pub fn local_principal(headers: &HeaderMap, domain: &str) -> String {
    let account = headers
        .get("chatgpt-account-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("trusted-peer");
    let mut hash = Sha256::new();
    hash.update(domain.len().to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update(account.as_bytes());
    format!("{:x}", hash.finalize())
}

pub fn admin_authorized(headers: &HeaderMap, key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| Sha256::digest(value.as_bytes()) == Sha256::digest(key.as_bytes()))
}
