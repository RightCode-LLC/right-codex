use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Deserialized configuration. This type deliberately has no Debug or Serialize
/// implementation: it contains the administration secret and private paths.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    /// Legacy name retained only for existing administration configuration.
    /// Model ingress uses trusted networks and the client's OAuth header.
    #[serde(default, alias = "admin_token")]
    pub client_api_key: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_chatgpt_base_url")]
    pub chatgpt_base_url: String,
    #[serde(default = "default_oauth_issuer")]
    pub oauth_issuer: String,
    #[serde(default = "default_trusted_networks")]
    pub trusted_networks: Vec<String>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub scheduling: SchedulingConfig,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_queue_timeout")]
    pub queue_timeout_secs: u64,
    /// Legacy configuration accepted but ignored: business requests never replay.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: usize,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Explicitly permits a plaintext upstream URL in an isolated test.
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub private_dir: Option<PathBuf>,
    pub collector_endpoint: Option<String>,
    pub otlp_endpoint: Option<String>,
    pub official_metrics_enabled: bool,
    pub allow_loopback_http: bool,
    pub max_batch: usize,
    pub ttl_seconds: u64,
    pub retry_backoff_seconds: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            private_dir: None,
            collector_endpoint: None,
            otlp_endpoint: None,
            official_metrics_enabled: true,
            allow_loopback_http: false,
            max_batch: 128,
            ttl_seconds: 86400,
            retry_backoff_seconds: 5,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulingConfig {
    pub max_sessions_by_account_age: [usize; 5],
    pub idle_timeout_secs: u64,
    pub startup_spacing_secs: u64,
    pub rest_interval_minutes: u64,
    pub rest_percent: u8,
    pub rest_duration_minutes: u64,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            max_sessions_by_account_age: [2, 4, 8, 16, 32],
            idle_timeout_secs: 300,
            startup_spacing_secs: 2,
            rest_interval_minutes: 0,
            rest_percent: 0,
            rest_duration_minutes: 0,
        }
    }
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("state")
}
fn default_chatgpt_base_url() -> String {
    "https://chatgpt.com/backend-api".into()
}
fn default_oauth_issuer() -> String {
    "https://auth.openai.com".into()
}
fn default_trusted_networks() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1/128".into()]
}
fn default_request_timeout() -> u64 {
    300
}
fn default_queue_timeout() -> u64 {
    60
}
fn default_max_attempts() -> usize {
    1
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18184".parse().expect("fixed socket"),
            client_api_key: String::new(),
            state_dir: default_state_dir(),
            chatgpt_base_url: default_chatgpt_base_url(),
            oauth_issuer: default_oauth_issuer(),
            trusted_networks: default_trusted_networks(),
            telemetry: TelemetryConfig::default(),
            scheduling: SchedulingConfig::default(),
            request_timeout_secs: default_request_timeout(),
            queue_timeout_secs: default_queue_timeout(),
            max_attempts: default_max_attempts(),
            base_url: default_base_url(),
            allow_insecure_http: false,
            accounts: Vec::new(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    pub id: String,
    pub auth_path: PathBuf,
    #[serde(default)]
    pub proxy: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("configuration cannot be read")]
    Read,
    #[error("configuration exceeds size limit")]
    TooLarge,
    #[error("configuration JSON is invalid")]
    InvalidJson,
    #[error("client API key is invalid")]
    InvalidClientKey,
    #[error("upstream base URL is invalid")]
    InvalidBaseUrl,
    #[error("plaintext upstream requires an explicit test setting")]
    PlaintextNotAllowed,
    #[error("account configuration is invalid")]
    InvalidAccount,
    #[error("account identifiers must be unique")]
    DuplicateAccount,
    #[error("account proxy URL is invalid")]
    InvalidProxy,
    #[error("trusted ingress networks are invalid")]
    InvalidTrustedNetworks,
    #[error("runtime limits are invalid")]
    InvalidLimits,
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_owned()
}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(path).map_err(|_| ConfigError::Read)?;
        let metadata = file.metadata().map_err(|_| ConfigError::Read)?;
        if !metadata.is_file() {
            return Err(ConfigError::Read);
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::Read)?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let mut config: Self =
            serde_json::from_slice(&bytes).map_err(|_| ConfigError::InvalidJson)?;
        // Relative paths are interpreted against this config, never the process cwd.
        let config_file = path.canonicalize().map_err(|_| ConfigError::Read)?;
        let parent = config_file.parent().ok_or(ConfigError::Read)?;
        if config.state_dir.is_relative() {
            config.state_dir = parent.join(&config.state_dir);
        }
        if let Some(path) = &mut config.telemetry.private_dir
            && path.is_relative()
        {
            *path = parent.join(&*path);
        }
        for account in &mut config.accounts {
            if account.auth_path.is_relative() {
                account.auth_path = parent.join(&account.auth_path);
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self
            .client_api_key
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ConfigError::InvalidClientKey);
        }
        if self.trusted_networks.is_empty()
            || self
                .trusted_networks
                .iter()
                .any(|network| network.parse::<ipnet::IpNet>().is_err())
        {
            return Err(ConfigError::InvalidTrustedNetworks);
        }
        if self.request_timeout_secs == 0
            || self.queue_timeout_secs == 0
            || self.telemetry.max_batch == 0
            || self.telemetry.max_batch > 1024
            || self.scheduling.rest_percent > 100
            || self.scheduling.idle_timeout_secs == 0
            || self
                .scheduling
                .max_sessions_by_account_age
                .iter()
                .any(|n| *n > 4096)
            || (self.scheduling.rest_interval_minutes > 0
                && self.scheduling.rest_percent > 0
                && self.scheduling.rest_duration_minutes == 0)
        {
            return Err(ConfigError::InvalidLimits);
        }
        for value in [
            Some(self.chatgpt_base_url.as_str()),
            Some(self.oauth_issuer.as_str()),
            self.telemetry.otlp_endpoint.as_deref(),
            self.telemetry.collector_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let url = Url::parse(value).map_err(|_| ConfigError::InvalidBaseUrl)?;
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || !matches!(url.scheme(), "https" | "http")
                || (url.scheme() == "http" && !self.allow_insecure_http)
            {
                return Err(ConfigError::InvalidBaseUrl);
            }
        }
        let url = Url::parse(&self.base_url).map_err(|_| ConfigError::InvalidBaseUrl)?;
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ConfigError::InvalidBaseUrl);
        }
        match url.scheme() {
            "https" => {}
            "http" if self.allow_insecure_http => {}
            "http" => return Err(ConfigError::PlaintextNotAllowed),
            _ => return Err(ConfigError::InvalidBaseUrl),
        }
        let mut ids = HashSet::new();
        for account in &self.accounts {
            if account.id.is_empty()
                || account.id.len() > 128
                || account.id.chars().any(char::is_control)
                || account.id.trim() != account.id
                || matches!(account.id.as_str(), "." | "..")
                || account.id.contains(['/', '\\'])
                || account.auth_path.as_os_str().is_empty()
            {
                return Err(ConfigError::InvalidAccount);
            }
            if !ids.insert(account.id.as_str()) {
                return Err(ConfigError::DuplicateAccount);
            }
            if let Some(proxy) = &account.proxy {
                let proxy_url = Url::parse(proxy).map_err(|_| ConfigError::InvalidProxy)?;
                if proxy_url.host_str().is_none()
                    || !matches!(proxy_url.scheme(), "http" | "https" | "socks5" | "socks5h")
                    || proxy_url.query().is_some()
                    || proxy_url.fragment().is_some()
                {
                    return Err(ConfigError::InvalidProxy);
                }
            }
        }
        Ok(())
    }

    pub fn parsed_base_url(&self) -> Result<Url, ConfigError> {
        self.validate()?;
        Url::parse(&self.base_url).map_err(|_| ConfigError::InvalidBaseUrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("codex-http-config-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn production_url_is_default_and_plaintext_requires_test_switch() {
        let dir = TestDir::new();
        let path = dir.0.join("gateway.json");
        fs::write(
            &path,
            r#"{"listen":"127.0.0.1:18183","client_api_key":"123456","accounts":[]}"#,
        )
        .unwrap();
        let config = GatewayConfig::load(&path).unwrap();
        assert_eq!(config.base_url, DEFAULT_BASE_URL);
        assert_eq!(config.listen.port(), 18183);
        fs::write(&path, r#"{"listen":"127.0.0.1:18183","client_api_key":"123456","base_url":"http://127.0.0.1:8080","accounts":[]}"#).unwrap();
        assert!(matches!(
            GatewayConfig::load(&path),
            Err(ConfigError::PlaintextNotAllowed)
        ));
        fs::write(&path, r#"{"listen":"127.0.0.1:18183","client_api_key":"123456","base_url":"http://127.0.0.1:8080","allow_insecure_http":true,"accounts":[]}"#).unwrap();
        assert!(GatewayConfig::load(&path).is_ok());
    }

    #[test]
    fn account_paths_resolve_from_config_and_ids_are_unique() {
        let dir = TestDir::new();
        let path = dir.0.join("gateway.json");
        fs::write(&path, r#"{"listen":"127.0.0.1:18183","client_api_key":"123456","accounts":[{"id":"one","auth_path":"one/auth.json","enabled":true}]}"#).unwrap();
        let config = GatewayConfig::load(&path).unwrap();
        let config_parent = path.canonicalize().unwrap();
        assert_eq!(
            config.accounts[0].auth_path,
            config_parent.parent().unwrap().join("one/auth.json")
        );
        let mut socks = config.clone();
        socks.accounts[0].proxy = Some("socks5h://127.0.0.1:9050".to_owned());
        assert!(socks.validate().is_ok());
        fs::write(&path, r#"{"listen":"127.0.0.1:18183","client_api_key":"123456","accounts":[{"id":"one","auth_path":"a","enabled":true},{"id":"one","auth_path":"b","enabled":false}]}"#).unwrap();
        assert!(matches!(
            GatewayConfig::load(&path),
            Err(ConfigError::DuplicateAccount)
        ));
    }

    #[test]
    fn errors_do_not_include_secret_or_private_path() {
        let dir = TestDir::new();
        let path = dir.0.join("private-sentinel.json");
        fs::write(&path, r#"{"listen":"127.0.0.1:18183","client_api_key":"secret-sentinel","base_url":"http://remote.test","accounts":[]}"#).unwrap();
        let error = GatewayConfig::load(&path).err().unwrap();
        let message = format!("{error:?} {error}");
        assert!(!message.contains("secret-sentinel"));
        assert!(!message.contains("private-sentinel"));
    }
}
