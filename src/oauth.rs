//! Instance-owned OAuth login. No subprocess, browser launch, process-env
//! mutation, or writes to the source CODEX_HOME are performed.
use crate::accounts::{create_private_directory, read_private_auth, write_private_auth};
use crate::oauth_contract::{self, OAuthError, Pkce, Tokens};
use codex_login::AuthDotJson;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const LOGIN_DURATION: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct LoginCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}
impl Default for LoginCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }
}
impl LoginCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_one();
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    async fn wait(&self) {
        if !self.is_cancelled() {
            self.notify.notified().await;
        }
    }
}

/// The client is the account's own raw login client. Device and code-exchange
/// endpoints do not inherit Codex API headers or a model bearer. Refresh uses
/// the separate default-client branch defined in the pinned auth manager.
pub struct OAuthLogin {
    home: PathBuf,
    issuer: String,
    client: reqwest::Client,
    workspace: Option<String>,
}
impl OAuthLogin {
    pub fn new(
        home: &Path,
        client: reqwest::Client,
        issuer: &str,
        workspace: Option<String>,
        allow_insecure: bool,
    ) -> Result<Self, OAuthError> {
        create_private_directory(home).map_err(|_| OAuthError::Storage)?;
        Ok(Self {
            home: home.to_owned(),
            issuer: oauth_contract::issuer(issuer, allow_insecure)?,
            client,
            workspace,
        })
    }
    pub fn begin_browser(&self, redirect_uri: &str) -> Result<BrowserLogin, OAuthError> {
        let redirect = url::Url::parse(redirect_uri).map_err(|_| OAuthError::InvalidResponse)?;
        if redirect.scheme() != "http"
            || !matches!(
                redirect.host_str(),
                Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
            )
            || redirect.path() != "/auth/callback"
            || redirect.query().is_some()
            || redirect.fragment().is_some()
            || !redirect.username().is_empty()
            || redirect.password().is_some()
        {
            return Err(OAuthError::InvalidResponse);
        }
        let pkce = Pkce::new();
        let state = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let auth_url = oauth_contract::authorization_url(
            &self.issuer,
            redirect_uri,
            &pkce,
            &state,
            self.workspace.as_deref(),
        )?;
        Ok(BrowserLogin {
            auth_url,
            state,
            pkce,
            redirect: redirect_uri.to_owned(),
            home: self.home.clone(),
            issuer: self.issuer.clone(),
            client: self.client.clone(),
            workspace: self.workspace.clone(),
            cancellation: LoginCancellation::default(),
            expires: Instant::now() + LOGIN_DURATION,
        })
    }
    pub async fn begin_device(&self) -> Result<DeviceLogin, OAuthError> {
        let response = self
            .client
            .post(format!("{}/api/accounts/deviceauth/usercode", self.issuer))
            .timeout(Duration::from_secs(30))
            .json(&serde_json::json!({"client_id":codex_login::oauth_client_id()}))
            .send()
            .await
            .map_err(|_| OAuthError::Transport)?;
        let reply: DeviceReply = oauth_contract::json_reply(response).await?;
        if reply.device_auth_id.is_empty() || reply.user_code.is_empty() || reply.interval > 900 {
            return Err(OAuthError::InvalidResponse);
        }
        Ok(DeviceLogin {
            verification_url: format!("{}/codex/device", self.issuer),
            user_code: reply.user_code,
            device_id: reply.device_auth_id,
            interval: reply.interval,
            home: self.home.clone(),
            issuer: self.issuer.clone(),
            client: self.client.clone(),
            workspace: self.workspace.clone(),
            expires: Instant::now() + LOGIN_DURATION,
            cancellation: LoginCancellation::default(),
        })
    }
}

pub struct BrowserLogin {
    pub auth_url: String,
    state: String,
    pkce: Pkce,
    redirect: String,
    home: PathBuf,
    issuer: String,
    client: reqwest::Client,
    workspace: Option<String>,
    cancellation: LoginCancellation,
    expires: Instant,
}
impl BrowserLogin {
    pub fn cancellation(&self) -> LoginCancellation {
        self.cancellation.clone()
    }
    /// Consumes the attempt before a one-time code POST. A lost reply is never
    /// automatically replayed. The web caller mounts the loopback callback.
    pub async fn complete(self, state: &str, code: &str) -> Result<(), OAuthError> {
        if state != self.state || code.is_empty() {
            return Err(OAuthError::InvalidResponse);
        }
        check(&self.cancellation, self.expires)?;
        let tokens = tokio::select! {
            biased;
            _ = self.cancellation.wait() => return Err(OAuthError::Cancelled),
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires),
                oauth_contract::exchange(&self.client, &self.issuer, &self.redirect, &self.pkce.verifier, code))
                => result.map_err(|_| OAuthError::Expired)??,
        };
        check(&self.cancellation, self.expires)?;
        persist_login(&self.home, tokens, self.workspace.as_deref())
    }
}

#[derive(Deserialize)]
struct DeviceReply {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(default, deserialize_with = "interval")]
    interval: u64,
}
fn interval<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    // The pinned device API uses a string interval (with whitespace tolerated).
    let value = String::deserialize(d)?;
    value.trim().parse().map_err(serde::de::Error::custom)
}

#[derive(Deserialize)]
struct DeviceCodeReply {
    authorization_code: String,
    code_verifier: String,
    code_challenge: String,
}

pub struct DeviceLogin {
    pub verification_url: String,
    pub user_code: String,
    device_id: String,
    interval: u64,
    home: PathBuf,
    issuer: String,
    client: reqwest::Client,
    workspace: Option<String>,
    expires: Instant,
    cancellation: LoginCancellation,
}
impl DeviceLogin {
    pub fn cancellation(&self) -> LoginCancellation {
        self.cancellation.clone()
    }
    pub async fn complete(self) -> Result<(), OAuthError> {
        loop {
            check(&self.cancellation, self.expires)?;
            let response = tokio::select! {
                biased;
                _ = self.cancellation.wait() => return Err(OAuthError::Cancelled),
                r = tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires),
                    self.client.post(format!("{}/api/accounts/deviceauth/token", self.issuer))
                    .timeout(Duration::from_secs(30))
                    .json(&serde_json::json!({"device_auth_id":self.device_id,"user_code":self.user_code})).send())
                    => r.map_err(|_| OAuthError::Expired)?.map_err(|_| OAuthError::Transport)?,
            };
            if response.status() == reqwest::StatusCode::FORBIDDEN
                || response.status() == reqwest::StatusCode::NOT_FOUND
            {
                let duration = Duration::from_secs(self.interval)
                    .min(self.expires.saturating_duration_since(Instant::now()));
                tokio::select! { biased; _ = self.cancellation.wait() => return Err(OAuthError::Cancelled), _ = tokio::time::sleep(duration) => {} }
                continue;
            }
            let reply: DeviceCodeReply = oauth_contract::json_reply(response).await?;
            if reply.authorization_code.is_empty()
                || reply.code_verifier.is_empty()
                || reply.code_challenge.is_empty()
            {
                return Err(OAuthError::InvalidResponse);
            }
            let redirect = format!("{}/deviceauth/callback", self.issuer);
            let tokens = tokio::select! { biased;
                _ = self.cancellation.wait() => return Err(OAuthError::Cancelled),
                result = tokio::time::timeout_at(tokio::time::Instant::from_std(self.expires),
                    oauth_contract::exchange(&self.client, &self.issuer, &redirect, &reply.code_verifier, &reply.authorization_code))
                    => result.map_err(|_| OAuthError::Expired)??,
            };
            check(&self.cancellation, self.expires)?;
            return persist_login(&self.home, tokens, self.workspace.as_deref());
        }
    }
}

fn check(cancel: &LoginCancellation, expires: Instant) -> Result<(), OAuthError> {
    if cancel.is_cancelled() {
        Err(OAuthError::Cancelled)
    } else if Instant::now() >= expires {
        Err(OAuthError::Expired)
    } else {
        Ok(())
    }
}

fn persist_login(home: &Path, tokens: Tokens, expected: Option<&str>) -> Result<(), OAuthError> {
    let id = tokens.id_token.ok_or(OAuthError::InvalidResponse)?;
    let info = codex_login::token_data::parse_chatgpt_jwt_claims(&id)
        .map_err(|_| OAuthError::InvalidResponse)?;
    let account = info
        .chatgpt_account_id
        .as_deref()
        .ok_or(OAuthError::InvalidResponse)?;
    if expected.is_some_and(|v| v != account) {
        return Err(OAuthError::IdentityChanged);
    }
    if let Some(old) = read_private_auth(home).map_err(|_| OAuthError::Storage)?
        && old
            .tokens
            .as_ref()
            .and_then(|t| t.account_id.as_deref())
            .is_some_and(|v| v != account)
    {
        return Err(OAuthError::IdentityChanged);
    }
    let access_token = tokens
        .access_token
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::InvalidResponse)?;
    let refresh_token = tokens
        .refresh_token
        .filter(|s| !s.is_empty())
        .ok_or(OAuthError::InvalidResponse)?;
    let auth: AuthDotJson = serde_json::from_value(serde_json::json!({"auth_mode":"chatgpt","tokens":{
        "id_token":id,"access_token":access_token,"refresh_token":refresh_token,"account_id":account},
        "last_refresh":chrono::Utc::now()})).map_err(|_| OAuthError::InvalidResponse)?;
    write_private_auth(
        home,
        &serde_json::to_vec(&auth).map_err(|_| OAuthError::Storage)?,
    )
    .map_err(|_| OAuthError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn expired_and_cancelled_browser_attempts_never_post_or_write() {
        let directory = tempfile::tempdir().unwrap();
        let login = OAuthLogin::new(
            directory.path(),
            crate::accounts::oauth_login_client(None).unwrap(),
            "http://127.0.0.1:1",
            None,
            true,
        )
        .unwrap();
        let mut expired = login
            .begin_browser("http://127.0.0.1:1455/auth/callback")
            .unwrap();
        let state = expired.state.clone();
        expired.expires = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            expired.complete(&state, "code").await,
            Err(OAuthError::Expired)
        );
        let cancelled = login
            .begin_browser("http://127.0.0.1:1455/auth/callback")
            .unwrap();
        let state = cancelled.state.clone();
        cancelled.cancellation().cancel();
        assert_eq!(
            cancelled.complete(&state, "code").await,
            Err(OAuthError::Cancelled)
        );
        assert!(!directory.path().join("auth.json").exists());
    }
    #[test]
    fn device_interval_matches_official_string_contract() {
        let good: DeviceReply = serde_json::from_value(
            serde_json::json!({"device_auth_id":"d","user_code":"u","interval":" 5 "}),
        )
        .unwrap();
        assert_eq!(good.interval, 5);
        assert!(
            serde_json::from_value::<DeviceReply>(
                serde_json::json!({"device_auth_id":"d","user_code":"u","interval":5})
            )
            .is_err()
        );
    }
}
