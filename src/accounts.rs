use crate::config::{AccountConfig, GatewayConfig};
use crate::oauth_contract;
use codex_api::{AuthProvider, SharedAuthProvider};
use codex_login::{
    AuthCredentialsStoreMode, AuthDotJson, AuthKeyringBackendKind, AuthManager, AuthRouteConfig,
};
use http::HeaderMap;
use http::HeaderValue;
use http::header::AUTHORIZATION;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

const MAX_AUTH_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum AccountError {
    #[error("account configuration is invalid")]
    InvalidConfiguration,
    #[error("account auth file cannot be read")]
    AuthRead,
    #[error("account auth file exceeds size limit")]
    AuthTooLarge,
    #[error("account auth JSON is invalid")]
    InvalidAuthJson,
    #[error("account requires ChatGPT OAuth auth.json")]
    UnsupportedAuthMode,
    #[error("account OAuth token fields are invalid")]
    InvalidTokens,
    #[error("the same OAuth account was configured more than once")]
    DuplicateOAuthAccount,
    #[error("account HTTP client cannot be built")]
    ClientBuild,
    #[error("account is not enabled")]
    NotEnabled,
    #[error("account identity changed during auth reload")]
    IdentityChanged,
    #[error("account registry is unavailable")]
    RegistryUnavailable,
    #[error("account private state is unavailable")]
    PrivateState,
    #[error("account OAuth refresh failed")]
    RefreshFailed,
    #[error("account is draining deletion")]
    Deleting,
    #[error("account OAuth profile is missing or invalid")]
    InvalidProfile,
    #[error("account requires the ChatGPT Pro plan")]
    ProPlanRequired,
}

/// Relevant fields from the official 0.160.0 auth file. ID-token display
/// claims are frozen separately from the selected workspace and OAuth bearer.
#[derive(Deserialize)]
struct AuthFile {
    #[serde(default)]
    auth_mode: Option<String>,
    tokens: TokenFile,
}

#[derive(Deserialize)]
struct TokenFile {
    #[serde(default)]
    id_token: Option<String>,
    access_token: String,
    refresh_token: String,
    account_id: Option<String>,
}

/// One OAuth identity, one auth revision, one HTTP connection pool.
/// No Debug or Serialize implementation is provided for the token-bearing type.
pub struct Account {
    id: String,
    workspace_account_id: String,
    access_token: String,
    _refresh_token: String,
    revision: String,
    credential_fingerprint: String,
    profile: Result<(String, String), AccountError>,
    client: reqwest::Client,
    home: PathBuf,
    created_at_unix_ms: u64,
    proxy: Option<String>,
    issuer: String,
    chatgpt_base_url: String,
    allow_insecure: bool,
    manager: OnceCell<Arc<AuthManager>>,
    runtime: Arc<Mutex<RuntimeState>>,
    refresh_gate: Arc<AsyncMutex<()>>,
    pub(crate) routing: AsyncMutex<Option<crate::routing::WorkspaceRoute>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountAvailability {
    pub enabled: bool,
    pub auth_invalid: bool,
    pub deleting: bool,
    pub active_requests: usize,
    pub max_concurrent_requests: usize,
    pub resting: bool,
    pub quota_cooldown: bool,
    pub quota_cooldown_until_unix_ms: Option<u64>,
}
struct RuntimeState {
    enabled: bool,
    deleting: bool,
    active: usize,
    capacity: usize,
    rest_until: Option<Instant>,
    quota_until: Option<Instant>,
    admission: PersistedAdmission,
    refresh_attempted_revision: Option<String>,
}
/// Upstream rejection state is separate from administrator enablement and
/// advisory usage polling. It belongs to one immutable credential revision.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAdmission {
    revision: String,
    #[serde(default)]
    credential_fingerprint: String,
    unauthorized: bool,
    quota_reset_unix_ms: Option<u64>,
}
impl PersistedAdmission {
    fn bind_credentials(mut self, account: &Account) -> Self {
        // Legacy files have no credential hash. Keep their rejection state on
        // migration instead of treating an unrelated transport change as login.
        if !self.credential_fingerprint.is_empty()
            && self.credential_fingerprint != account.credential_fingerprint
        {
            // A fresh bearer repairs authorization, not this account's quota.
            self.unauthorized = false;
        }
        self.revision = account.revision.clone();
        self.credential_fingerprint = account.credential_fingerprint.clone();
        self
    }
}
impl RuntimeState {
    fn snapshot(&self) -> AccountAvailability {
        let now = Instant::now();
        let now_ms = unix_ms();
        let advisory_reset = self
            .quota_until
            .filter(|t| *t > now)
            .and_then(|t| u64::try_from(t.saturating_duration_since(now).as_millis()).ok())
            .and_then(|remaining| now_ms.checked_add(remaining));
        let rejection_reset = self.admission.quota_reset_unix_ms.filter(|t| *t > now_ms);
        let quota_reset = advisory_reset.into_iter().chain(rejection_reset).max();
        AccountAvailability {
            enabled: self.enabled && !self.admission.unauthorized,
            auth_invalid: self.admission.unauthorized,
            deleting: self.deleting,
            active_requests: self.active,
            max_concurrent_requests: self.capacity,
            resting: self.rest_until.is_some_and(|t| t > now),
            quota_cooldown: quota_reset.is_some(),
            quota_cooldown_until_unix_ms: quota_reset,
        }
    }
    fn eligible(&self, new_session: bool) -> bool {
        let s = self.snapshot();
        s.enabled
            && !s.deleting
            && !s.quota_cooldown
            && (!new_session || !s.resting)
            && self.active < self.capacity
    }
}

impl Account {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn workspace_account_id(&self) -> &str {
        &self.workspace_account_id
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
    pub fn private_home(&self) -> &Path {
        &self.home
    }
    pub fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }
    pub fn chatgpt_base_url(&self) -> &str {
        &self.chatgpt_base_url
    }
    pub fn allows_insecure_test(&self) -> bool {
        self.allow_insecure
    }
    pub(crate) fn verify_private_identity(&self) -> Result<(), AccountError> {
        let auth = read_private_auth(&self.home)?.ok_or(AccountError::InvalidTokens)?;
        let tokens = auth.tokens.ok_or(AccountError::InvalidTokens)?;
        if tokens.account_id.as_deref() != Some(self.workspace_account_id())
            || tokens.access_token != self.access_token
        {
            return Err(AccountError::IdentityChanged);
        }
        Ok(())
    }
    pub fn availability(&self) -> Result<AccountAvailability, AccountError> {
        Ok(self
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .snapshot())
    }
    /// Safe display metadata is frozen with the credential snapshot.
    pub fn oauth_profile(&self) -> Result<(String, String), AccountError> {
        self.profile.clone()
    }
    /// Administrative enablement is independent of a rejected bearer.
    pub fn admin_enabled(&self) -> Result<bool, AccountError> {
        Ok(self
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .enabled)
    }
    pub fn auth_provider(&self) -> SharedAuthProvider {
        Arc::new(SnapshotAuth {
            token: self.access_token.clone(),
            account: self.workspace_account_id.clone(),
        })
    }
    /// Official cache/parser only. Network refresh is routed through our
    /// instance-owned OAuth adapter; callers must not invoke manager.auth().
    pub async fn auth_manager(&self) -> Result<Arc<AuthManager>, AccountError> {
        self.manager
            .get_or_try_init(|| async {
                if std::env::var_os(codex_login::CODEX_ACCESS_TOKEN_ENV_VAR).is_some() {
                    return Err(AccountError::UnsupportedAuthMode);
                }
                let factory = codex_http_client::HttpClientFactory::new(
                    codex_http_client::OutboundProxyPolicy::ReqwestDefault,
                );
                let m = Arc::new(
                    AuthManager::new(
                        self.home.clone(),
                        false,
                        AuthCredentialsStoreMode::File,
                        Some(vec![self.workspace_account_id.clone()]),
                        Some(self.chatgpt_base_url.clone()),
                        AuthKeyringBackendKind::default(),
                        AuthRouteConfig::from_http_client_factory(factory),
                    )
                    .await,
                );
                let a = m.auth_cached().ok_or(AccountError::InvalidTokens)?;
                if !a.is_chatgpt_auth()
                    || a.get_account_id().as_deref() != Some(self.workspace_account_id.as_str())
                    || a.get_token().map_err(|_| AccountError::InvalidTokens)? != self.access_token
                {
                    return Err(AccountError::IdentityChanged);
                }
                Ok(m)
            })
            .await
            .cloned()
    }
    pub fn oauth_login(&self) -> Result<crate::oauth::OAuthLogin, oauth_contract::OAuthError> {
        crate::oauth::OAuthLogin::new(
            &self.home,
            oauth_login_client(self.proxy()).map_err(|_| oauth_contract::OAuthError::Transport)?,
            &self.issuer,
            Some(self.workspace_account_id.clone()),
            self.allow_insecure,
        )
    }

    /// Attach the bearer to a request made with this account's own client.
    pub fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(&self.access_token)
    }

    /// Attach this account's OAuth identity to an official SDK request.
    /// Construct both values before mutating the map so an invalid value never
    /// leaves a partially authorized request behind.
    pub fn authorize_headers(&self, headers: &mut HeaderMap) -> Result<(), AccountError> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.access_token))
            .map_err(|_| AccountError::InvalidTokens)?;
        let mut account = HeaderValue::from_str(&self.workspace_account_id)
            .map_err(|_| AccountError::InvalidTokens)?;
        authorization.set_sensitive(true);
        account.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        headers.insert("chatgpt-account-id", account);
        Ok(())
    }

    fn load(
        config: &AccountConfig,
        gateway: &GatewayConfig,
        home: &Path,
        runtime: Arc<Mutex<RuntimeState>>,
        refresh_gate: Arc<AsyncMutex<()>>,
        import: bool,
    ) -> Result<Self, AccountError> {
        create_private_directory(home)?;
        // Read the source once, never open it for writes. Private refreshes
        // survive restarts; explicit reload is the sole source re-import.
        let private = home.join("auth.json");
        if let Ok(m) = fs::symlink_metadata(&private)
            && (!m.is_file() || m.file_type().is_symlink())
        {
            return Err(AccountError::PrivateState);
        }
        let source = read_auth_bytes(if import || !private.exists() {
            &config.auth_path
        } else {
            &private
        })?;
        let account = Self::from_auth_bytes(config, gateway, home, runtime, refresh_gate, &source)?;
        if import || !private.exists() {
            if private.exists() {
                let old: AuthFile = serde_json::from_slice(&read_auth_bytes(&private)?)
                    .map_err(|_| AccountError::InvalidAuthJson)?;
                if old.tokens.account_id.as_deref() != Some(account.workspace_account_id()) {
                    return Err(AccountError::IdentityChanged);
                }
            }
            write_private_auth(home, &source)?;
        }
        Ok(account)
    }

    fn from_auth_bytes(
        config: &AccountConfig,
        gateway: &GatewayConfig,
        home: &Path,
        runtime: Arc<Mutex<RuntimeState>>,
        refresh_gate: Arc<AsyncMutex<()>>,
        raw: &[u8],
    ) -> Result<Self, AccountError> {
        let auth: AuthFile =
            serde_json::from_slice(raw).map_err(|_| AccountError::InvalidAuthJson)?;
        if auth
            .auth_mode
            .as_deref()
            .is_some_and(|mode| mode != "chatgpt")
        {
            return Err(AccountError::UnsupportedAuthMode);
        }
        let account_id = auth.tokens.account_id.ok_or(AccountError::InvalidTokens)?;
        if account_id.trim().is_empty()
            || auth.tokens.access_token.trim().is_empty()
            || auth.tokens.refresh_token.trim().is_empty()
            || auth.tokens.access_token.chars().any(char::is_whitespace)
            || account_id.chars().any(char::is_control)
        {
            return Err(AccountError::InvalidTokens);
        }
        let profile = oauth_profile(auth.tokens.id_token.as_deref(), &account_id);

        // A revision is scoped to the local account ID and transport settings.
        // Replacing auth.json creates a new Client instead of reusing a pool.
        let mut hasher = Sha256::new();
        for field in [
            config.id.as_bytes(),
            gateway.base_url.as_bytes(),
            gateway.oauth_issuer.as_bytes(),
            gateway.chatgpt_base_url.as_bytes(),
            config.proxy.as_deref().unwrap_or("").as_bytes(),
            raw,
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        let revision = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // Rejection eligibility follows the actual bearer, not transport,
        // JSON formatting, refresh token rotation or last_refresh metadata.
        let mut credentials = Sha256::new();
        for field in [account_id.as_bytes(), auth.tokens.access_token.as_bytes()] {
            credentials.update((field.len() as u64).to_be_bytes());
            credentials.update(field);
        }
        let credential_fingerprint = format!("{:x}", credentials.finalize());

        // Each call constructs a new client. No cookie jar or shared connection
        // pool is passed between accounts or authentication revisions.
        let client = account_client(config.proxy.as_deref())?;
        Ok(Self {
            id: config.id.clone(),
            workspace_account_id: account_id,
            access_token: auth.tokens.access_token,
            _refresh_token: auth.tokens.refresh_token,
            revision,
            credential_fingerprint,
            profile,
            client,
            created_at_unix_ms: creation_time(
                home.parent().ok_or(AccountError::PrivateState)?,
                &config.id,
            )?,
            home: home.to_owned(),
            proxy: config.proxy.clone(),
            issuer: oauth_contract::issuer(&gateway.oauth_issuer, gateway.allow_insecure_http)
                .map_err(|_| AccountError::InvalidConfiguration)?,
            chatgpt_base_url: gateway.chatgpt_base_url.clone(),
            allow_insecure: gateway.allow_insecure_http,
            manager: OnceCell::new(),
            runtime,
            refresh_gate,
            routing: AsyncMutex::new(None),
        })
    }
}

/// Retains managed accounts including disabled entries; selection rotates
/// only through current eligible accounts and excludes draining owners.
pub struct AccountPool {
    configs: RwLock<Vec<AccountConfig>>,
    config: GatewayConfig,
    state_dir: PathBuf,
    accounts: Arc<RwLock<Vec<Arc<Account>>>>,
    next: AtomicUsize,
    reload: Mutex<()>,
}

impl AccountPool {
    pub fn from_config(config: &GatewayConfig) -> Result<Self, AccountError> {
        Self::from_config_with_state_dir(config, &config.state_dir)
    }
    pub fn from_config_with_state_dir(
        config: &GatewayConfig,
        directory: &Path,
    ) -> Result<Self, AccountError> {
        config
            .validate()
            .map_err(|_| AccountError::InvalidConfiguration)?;
        let mut configs = config.accounts.clone();
        for saved in read_registry(directory)? {
            if let Some(original) = configs.iter_mut().find(|c| c.id == saved.id) {
                *original = saved;
            } else {
                configs.push(saved);
            }
        }
        let mut effective = config.clone();
        effective.accounts = configs.clone();
        effective
            .validate()
            .map_err(|_| AccountError::InvalidConfiguration)?;
        let mut accounts = Vec::new();
        let mut oauth_ids = HashSet::new();
        create_private_directory(directory)?;
        let account_directory = directory.join("accounts");
        create_private_directory(&account_directory)?;
        for entry in &configs {
            if !valid_local_id(&entry.id) {
                return Err(AccountError::InvalidConfiguration);
            }
            {
                let owner = account_directory.join(&entry.id);
                create_private_directory(&owner)?;
                if owner.join("deleted").exists() {
                    remove_private_credentials(&owner.join("home"))?;
                    continue;
                }
                let runtime = Arc::new(Mutex::new(RuntimeState {
                    enabled: entry.enabled,
                    deleting: false,
                    active: 0,
                    capacity: 1024,
                    rest_until: None,
                    quota_until: None,
                    admission: PersistedAdmission::default(),
                    refresh_attempted_revision: None,
                }));
                let account = Account::load(
                    entry,
                    config,
                    &owner.join("home"),
                    runtime,
                    Arc::new(AsyncMutex::new(())),
                    false,
                )?;
                let admission_path = owner.join("admission.json");
                let saved_admission = read_admission(&admission_path)?;
                let admission = saved_admission.clone().bind_credentials(&account);
                if saved_admission != admission && admission_path.exists() {
                    write_admission(directory, &entry.id, &admission)?;
                }
                account
                    .runtime
                    .lock()
                    .map_err(|_| AccountError::RegistryUnavailable)?
                    .admission = admission;
                if !oauth_ids.insert(account.workspace_account_id.clone()) {
                    return Err(AccountError::DuplicateOAuthAccount);
                }
                accounts.push(Arc::new(account));
            }
        }
        Ok(Self {
            configs: RwLock::new(configs),
            config: config.clone(),
            state_dir: directory.to_owned(),
            accounts: Arc::new(RwLock::new(accounts)),
            next: AtomicUsize::new(0),
            reload: Mutex::new(()),
        })
    }

    pub fn enabled_count(&self) -> Result<usize, AccountError> {
        Ok(self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .iter()
            .filter(|a| a.availability().is_ok_and(|s| s.enabled && !s.deleting))
            .count())
    }

    pub fn next_enabled(&self) -> Result<Option<Arc<Account>>, AccountError> {
        self.next_eligible_excluding(&HashSet::new())
    }
    fn eligible_excluding(
        account: &Account,
        excluded: &HashSet<String>,
    ) -> Result<bool, AccountError> {
        if excluded.contains(account.id()) {
            return Ok(false);
        }
        Ok(account
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .eligible(true))
    }
    /// Availability probing must not change the round-robin selection cursor.
    pub fn has_eligible_excluding(&self, excluded: &HashSet<String>) -> Result<bool, AccountError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        for account in accounts.iter() {
            if Self::eligible_excluding(account, excluded)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn next_eligible_excluding(
        &self,
        excluded: &HashSet<String>,
    ) -> Result<Option<Arc<Account>>, AccountError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if accounts.is_empty() {
            return Ok(None);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) % accounts.len();
        for offset in 0..accounts.len() {
            let a = &accounts[(start + offset) % accounts.len()];
            if Self::eligible_excluding(a, excluded)? {
                return Ok(Some(a.clone()));
            }
        }
        Ok(None)
    }

    pub fn by_id(&self, id: &str) -> Result<Option<Arc<Account>>, AccountError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        Ok(accounts
            .iter()
            .find(|account| {
                account.id == id
                    && account
                        .availability()
                        .is_ok_and(|s| s.enabled && !s.deleting)
            })
            .map(Arc::clone))
    }

    /// Reload only one enabled account. Old in-flight holders retain their old
    /// client and revision; new selections see the replacement. A changed
    /// selected workspace needs a newly configured account, never an in-place
    /// identity swap.
    pub fn reload_auth(&self, id: &str) -> Result<bool, AccountError> {
        let _serial = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let config = self
            .configs
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .iter()
            .find(|item| item.id == id && item.enabled)
            .cloned()
            .ok_or(AccountError::NotEnabled)?;
        let old = self.managed(id)?.ok_or(AccountError::NotEnabled)?;
        if old.availability()?.deleting {
            return Err(AccountError::Deleting);
        }
        let replacement = Account::load(
            &config,
            &self.config,
            &old.home,
            old.runtime.clone(),
            old.refresh_gate.clone(),
            true,
        )?;
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let index = accounts
            .iter()
            .position(|account| account.id == id)
            .ok_or(AccountError::NotEnabled)?;
        if accounts[index].workspace_account_id != replacement.workspace_account_id {
            return Err(AccountError::IdentityChanged);
        }
        // Only a successfully validated explicit import unlocks an ambiguous
        // refresh attempt. A rejected source must never authorize another POST.
        accounts[index]
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .refresh_attempted_revision = None;
        if accounts[index].revision == replacement.revision {
            return Ok(false);
        }
        let admission = old
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .admission
            .clone()
            .bind_credentials(&replacement);
        write_admission(&self.state_dir, id, &admission)?;
        {
            let mut state = replacement
                .runtime
                .lock()
                .map_err(|_| AccountError::RegistryUnavailable)?;
            state.admission = admission;
        }
        accounts[index] = Arc::new(replacement);
        Ok(true)
    }
    pub fn lease(&self, id: &str, new_session: bool) -> Result<Option<AccountLease>, AccountError> {
        let Some(account) = self.by_id(id)? else {
            return Ok(None);
        };
        {
            let mut s = account
                .runtime
                .lock()
                .map_err(|_| AccountError::RegistryUnavailable)?;
            if !s.eligible(new_session) {
                return Ok(None);
            }
            s.active += 1;
        }
        Ok(Some(AccountLease {
            account,
            registry: Arc::downgrade(&self.accounts),
        }))
    }
    fn modify(
        &self,
        id: &str,
        f: impl FnOnce(&mut RuntimeState) -> Result<(), AccountError>,
    ) -> Result<(), AccountError> {
        let account = {
            let accounts = self
                .accounts
                .read()
                .map_err(|_| AccountError::RegistryUnavailable)?;
            accounts
                .iter()
                .find(|a| a.id() == id)
                .cloned()
                .ok_or(AccountError::NotEnabled)?
        };
        let mut state = account
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        f(&mut state)
    }
    pub fn all(&self) -> Result<Vec<Arc<Account>>, AccountError> {
        Ok(self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .clone())
    }
    pub fn managed(&self, id: &str) -> Result<Option<Arc<Account>>, AccountError> {
        Ok(self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .iter()
            .find(|a| a.id() == id)
            .cloned())
    }
    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), AccountError> {
        let _serial = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let account = self.managed(id)?.ok_or(AccountError::NotEnabled)?;
        let mut state = account
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if state.deleting {
            return Err(AccountError::Deleting);
        }
        let mut configs = self
            .configs
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let mut saved = configs.clone();
        saved
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(AccountError::NotEnabled)?
            .enabled = enabled;
        write_registry(&self.state_dir, &saved)?;
        *configs = saved;
        state.enabled = enabled;
        Ok(())
    }
    /// Load a completed OAuth login from a private home. The caller has no
    /// facility to replace another account's home or selected workspace.
    pub fn add_from_home(
        &self,
        id: &str,
        proxy: Option<String>,
    ) -> Result<Arc<Account>, AccountError> {
        if !valid_local_id(id) {
            return Err(AccountError::InvalidConfiguration);
        }
        let _serial = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let mut configs = self
            .configs
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if configs.iter().any(|c| c.id == id) {
            return Err(AccountError::InvalidConfiguration);
        }
        let owner = self.state_dir.join("accounts").join(id);
        let entry = AccountConfig {
            id: id.to_owned(),
            auth_path: owner.join("home/auth.json"),
            proxy,
            enabled: true,
        };
        let mut updated = configs.clone();
        updated.push(entry.clone());
        let mut gateway = self.config.clone();
        gateway.accounts = updated.clone();
        gateway
            .validate()
            .map_err(|_| AccountError::InvalidConfiguration)?;
        if owner.join("deleted").exists() {
            return Err(AccountError::Deleting);
        }
        let runtime = Arc::new(Mutex::new(RuntimeState {
            enabled: true,
            deleting: false,
            active: 0,
            capacity: 1024,
            rest_until: None,
            quota_until: None,
            admission: PersistedAdmission::default(),
            refresh_attempted_revision: None,
        }));
        let account = Arc::new(Account::load(
            &entry,
            &self.config,
            &owner.join("home"),
            runtime,
            Arc::new(AsyncMutex::new(())),
            false,
        )?);
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if accounts
            .iter()
            .any(|a| a.workspace_account_id() == account.workspace_account_id())
        {
            return Err(AccountError::DuplicateOAuthAccount);
        }
        write_registry(&self.state_dir, &updated)?;
        *configs = updated;
        accounts.push(account.clone());
        Ok(account)
    }
    /// Register a completed, isolated OAuth login. The boolean is true only
    /// for a newly created pool account. Reauthorization matches the selected
    /// workspace, never the caller's display name or an email string.
    pub fn upsert_from_home(
        &self,
        staging_id: &str,
        proxy: Option<String>,
    ) -> Result<(Arc<Account>, bool), AccountError> {
        if !valid_local_id(staging_id) {
            return Err(AccountError::InvalidConfiguration);
        }
        let _serial = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let mut configs = self
            .configs
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if configs.iter().any(|c| c.id == staging_id) {
            return Err(AccountError::InvalidConfiguration);
        }
        let owner = self.state_dir.join("accounts").join(staging_id);
        if owner.join("deleted").exists() {
            return Err(AccountError::Deleting);
        }
        let staged_home = owner.join("home");
        create_private_directory(&owner)?;
        create_private_directory(&staged_home)?;
        let auth_path = staged_home.join("auth.json");
        let metadata = fs::symlink_metadata(&auth_path).map_err(|_| AccountError::AuthRead)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AccountError::PrivateState);
        }
        let raw = read_auth_bytes(&auth_path)?;
        let staged: AuthFile =
            serde_json::from_slice(&raw).map_err(|_| AccountError::InvalidAuthJson)?;
        let workspace = staged
            .tokens
            .account_id
            .as_deref()
            .ok_or(AccountError::InvalidTokens)?;
        let (_, plan) = oauth_profile(staged.tokens.id_token.as_deref(), workspace)?;
        if plan != "pro" {
            return Err(AccountError::ProPlanRequired);
        }
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let existing = accounts
            .iter()
            .position(|a| a.workspace_account_id() == workspace);
        let old = existing.map(|i| accounts[i].clone());
        let id = old.as_ref().map_or(staging_id, |a| a.id());
        let home = old
            .as_ref()
            .map_or(staged_home.as_path(), |a| a.home.as_path());
        let runtime = old.as_ref().map(|a| a.runtime.clone()).unwrap_or_else(|| {
            Arc::new(Mutex::new(RuntimeState {
                enabled: true,
                deleting: false,
                active: 0,
                capacity: 1024,
                rest_until: None,
                quota_until: None,
                admission: PersistedAdmission::default(),
                refresh_attempted_revision: None,
            }))
        });
        let mut state = runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if state.deleting {
            return Err(AccountError::Deleting);
        }
        // Take ownership of the imported source. A later explicit reload must
        // never restore the old read-only host credential or its old proxy.
        let entry = AccountConfig {
            id: id.to_owned(),
            auth_path: home.join("auth.json"),
            proxy,
            enabled: state.enabled,
        };
        let mut updated = configs.clone();
        if let Some(cfg) = updated.iter_mut().find(|c| c.id == id) {
            *cfg = entry.clone();
        } else {
            updated.push(entry.clone());
        }
        let mut gateway = self.config.clone();
        gateway.accounts = updated.clone();
        gateway
            .validate()
            .map_err(|_| AccountError::InvalidConfiguration)?;
        let replacement = Arc::new(Account::from_auth_bytes(
            &entry,
            &self.config,
            home,
            runtime.clone(),
            old.as_ref()
                .map(|a| a.refresh_gate.clone())
                .unwrap_or_else(|| Arc::new(AsyncMutex::new(()))),
            &raw,
        )?);
        let admission = state.admission.clone().bind_credentials(&replacement);
        if old.is_some() {
            let prior_auth = read_auth_bytes(&home.join("auth.json"))?;
            let prior_admission = state.admission.clone();
            // Publication is serialized with refresh/reload/deletion. Prepare
            // the replacement client first; ordinary write errors restore the
            // prior credentials. Each individual private file is atomic.
            if let Err(error) = (|| {
                write_private_auth(home, &raw)?;
                write_admission(&self.state_dir, id, &admission)?;
                write_registry(&self.state_dir, &updated)
            })() {
                let restore_auth = write_private_auth(home, &prior_auth);
                let restore_admission = write_admission(&self.state_dir, id, &prior_admission);
                if restore_auth.is_err() || restore_admission.is_err() {
                    return Err(AccountError::PrivateState);
                }
                return Err(error);
            }
        } else {
            // The staged home already holds the validated credentials. Nothing
            // after the registry commit fails or borrows a caller-owned source.
            write_registry(&self.state_dir, &updated)?;
        }
        state.admission = admission;
        state.refresh_attempted_revision = None;
        *configs = updated;
        if let Some(index) = existing {
            accounts[index] = replacement.clone();
        } else {
            accounts.push(replacement.clone());
        }
        Ok((replacement, existing.is_none()))
    }
    pub fn set_capacity(&self, id: &str, maximum: usize) -> Result<(), AccountError> {
        if maximum == 0 || maximum > 65536 {
            return Err(AccountError::InvalidConfiguration);
        }
        self.modify(id, |s| {
            s.capacity = maximum;
            Ok(())
        })
    }
    pub fn rest(&self, id: &str, duration: Duration) -> Result<(), AccountError> {
        let until = Instant::now()
            .checked_add(duration)
            .ok_or(AccountError::InvalidConfiguration)?;
        self.modify(id, |s| {
            s.rest_until = Some(until);
            Ok(())
        })
    }
    pub fn mark_quota_cooldown(&self, id: &str, duration: Duration) -> Result<(), AccountError> {
        let until = Instant::now()
            .checked_add(duration)
            .ok_or(AccountError::InvalidConfiguration)?;
        self.modify(id, |s| {
            s.quota_until = Some(until);
            Ok(())
        })
    }
    pub fn clear_quota_cooldown(&self, id: &str) -> Result<(), AccountError> {
        self.modify(id, |s| {
            s.quota_until = None;
            Ok(())
        })
    }
    /// Apply actual upstream rejection advice, ignoring old in-flight revisions.
    /// Returning healthy usage data never clears this separate deadline.
    pub(crate) fn upstream_rejection(
        &self,
        id: &str,
        revision: &str,
        unauthorized: bool,
        quota_reset_unix_ms: Option<u64>,
    ) -> Result<(), AccountError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let Some(account) = accounts
            .iter()
            .find(|a| a.id() == id && a.revision() == revision)
        else {
            return Ok(());
        };
        let mut state = account
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if state.deleting {
            return Ok(());
        }
        state.admission.revision = revision.to_owned();
        state.admission.credential_fingerprint = account.credential_fingerprint.clone();
        state.admission.unauthorized |= unauthorized;
        if let Some(until) = quota_reset_unix_ms.filter(|t| *t > unix_ms()) {
            state.admission.quota_reset_unix_ms =
                Some(state.admission.quota_reset_unix_ms.unwrap_or(0).max(until));
        }
        write_admission(&self.state_dir, id, &state.admission)
    }
    pub(crate) fn quota_for_revision(
        &self,
        id: &str,
        revision: &str,
        duration: Option<Duration>,
    ) -> Result<(), AccountError> {
        let accounts = self
            .accounts
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let a = accounts
            .iter()
            .find(|a| a.id() == id && a.revision() == revision)
            .ok_or(AccountError::IdentityChanged)?;
        let mut state = a
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if state.deleting || !state.enabled {
            return Err(AccountError::NotEnabled);
        }
        state.quota_until = duration
            .map(|v| {
                Instant::now()
                    .checked_add(v)
                    .ok_or(AccountError::InvalidConfiguration)
            })
            .transpose()?;
        Ok(())
    }

    pub fn delete_draining(&self, id: &str) -> Result<bool, AccountError> {
        let _publication = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let i = accounts
            .iter()
            .position(|a| a.id() == id)
            .ok_or(AccountError::NotEnabled)?;
        let account = accounts[i].clone();
        let mut state = account
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let marker = self.state_dir.join("accounts").join(id).join("deleted");
        if !marker.exists() {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(marker)
                .map_err(|_| AccountError::PrivateState)?;
            file.write_all(b"draining\n")
                .map_err(|_| AccountError::PrivateState)?;
            file.sync_all().map_err(|_| AccountError::PrivateState)?;
        }
        state.enabled = false;
        state.deleting = true;
        let drained = state.active == 0;
        if drained {
            remove_private_credentials(&account.home)?;
        }
        // Keep draining state visible to administration. The last lease
        // removes the pool snapshot after credentials have been removed.
        if drained {
            accounts.remove(i);
        }
        Ok(drained)
    }
    /// Explicit credential refreshes share one account lock. Business request
    /// errors must not call this method or cause automatic token POSTs.
    pub async fn refresh_once(
        &self,
        id: &str,
        observed_revision: &str,
    ) -> Result<Arc<Account>, AccountError> {
        let old = self.by_id(id)?.ok_or(AccountError::NotEnabled)?;
        let _serial = old.refresh_gate.lock().await;
        let current = self.by_id(id)?.ok_or(AccountError::NotEnabled)?;
        if current.revision() != observed_revision {
            return Ok(current);
        }
        let _manager = current.auth_manager().await?;
        let mut auth = read_private_auth(&current.home)?.ok_or(AccountError::InvalidTokens)?;
        let prior = auth
            .tokens
            .as_ref()
            .ok_or(AccountError::InvalidTokens)?
            .clone();
        if prior.account_id.as_deref() != Some(current.workspace_account_id())
            || prior.access_token != current.access_token
        {
            return Err(AccountError::IdentityChanged);
        }
        {
            let mut state = current
                .runtime
                .lock()
                .map_err(|_| AccountError::RegistryUnavailable)?;
            if state.refresh_attempted_revision.as_deref() == Some(current.revision()) {
                return Err(AccountError::RefreshFailed);
            }
            if !state.enabled || state.deleting || state.admission.unauthorized {
                return Err(AccountError::NotEnabled);
            }
            // An ambiguous token POST is never repeated for this revision.
            // An explicit source reload resets it.
            state.refresh_attempted_revision = Some(current.revision().to_owned());
        }
        let reply =
            oauth_contract::refresh(current.client(), &current.issuer, &current._refresh_token)
                .await
                .map_err(|_| AccountError::RefreshFailed)?;
        let mut tokens = prior.clone();
        if let Some(id_token) = reply.id_token {
            let parsed = codex_login::token_data::parse_chatgpt_jwt_claims(&id_token)
                .map_err(|_| AccountError::InvalidTokens)?;
            if prior.id_token.chatgpt_user_id.is_some()
                && parsed.chatgpt_user_id != prior.id_token.chatgpt_user_id
            {
                return Err(AccountError::IdentityChanged);
            }
            tokens.id_token = parsed;
        }
        if let Some(v) = reply.access_token {
            if v.is_empty() || v.chars().any(char::is_whitespace) {
                return Err(AccountError::InvalidTokens);
            }
            tokens.access_token = v;
        }
        if let Some(v) = reply.refresh_token {
            if v.is_empty() {
                return Err(AccountError::InvalidTokens);
            }
            tokens.refresh_token = v;
        }
        // Management replacement/deletion during the POST must not resurrect
        // an old epoch. The synchronous import lock protects disk publication.
        let _publication = self
            .reload
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let mut accounts = self
            .accounts
            .write()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        let runtime = current
            .runtime
            .lock()
            .map_err(|_| AccountError::RegistryUnavailable)?;
        if !runtime.enabled || runtime.deleting || runtime.admission.unauthorized {
            return Err(AccountError::NotEnabled);
        }
        let i = accounts
            .iter()
            .position(|a| a.id == id)
            .ok_or(AccountError::NotEnabled)?;
        if accounts[i].revision() != current.revision() {
            return Ok(accounts[i].clone());
        }
        current.verify_private_identity()?;
        auth.tokens = Some(tokens);
        auth.last_refresh = Some(chrono::Utc::now());
        write_private_auth(
            &current.home,
            &serde_json::to_vec(&auth).map_err(|_| AccountError::InvalidAuthJson)?,
        )?;
        let cfg = self
            .configs
            .read()
            .map_err(|_| AccountError::RegistryUnavailable)?
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or(AccountError::NotEnabled)?;
        let replacement = Account::load(
            &cfg,
            &self.config,
            &current.home,
            current.runtime.clone(),
            current.refresh_gate.clone(),
            false,
        )?;
        let admission = runtime.admission.clone().bind_credentials(&replacement);
        write_admission(&self.state_dir, id, &admission)?;
        drop(runtime);
        {
            let mut state = replacement
                .runtime
                .lock()
                .map_err(|_| AccountError::RegistryUnavailable)?;
            state.admission = admission;
        }
        accounts[i] = Arc::new(replacement);
        Ok(accounts[i].clone())
    }
}

pub struct AccountLease {
    account: Arc<Account>,
    registry: std::sync::Weak<RwLock<Vec<Arc<Account>>>>,
}
impl AccountLease {
    pub fn account(&self) -> &Arc<Account> {
        &self.account
    }
}
impl Drop for AccountLease {
    fn drop(&mut self) {
        let drained = if let Ok(mut s) = self.account.runtime.lock() {
            s.active = s.active.saturating_sub(1);
            s.deleting && s.active == 0
        } else {
            false
        };
        if drained
            && remove_private_credentials(&self.account.home).is_ok()
            && let Some(registry) = self.registry.upgrade()
            && let Ok(mut accounts) = registry.write()
        {
            accounts.retain(|a| a.id() != self.account.id());
        }
    }
}
struct SnapshotAuth {
    token: String,
    account: String,
}
impl AuthProvider for SnapshotAuth {
    fn add_auth_headers(&self, headers: &mut HeaderMap) {
        if let (Ok(mut token), Ok(mut account)) = (
            HeaderValue::from_str(&format!("Bearer {}", self.token)),
            HeaderValue::from_str(&self.account),
        ) {
            token.set_sensitive(true);
            account.set_sensitive(true);
            headers.insert(AUTHORIZATION, token);
            headers.insert("chatgpt-account-id", account);
        }
    }
}
pub fn account_client(proxy: Option<&str>) -> Result<reqwest::Client, AccountError> {
    // login/auth/default_client.rs:421–468. The selected account supplies
    // credentials per request; none are installed as client defaults.
    http_client(proxy, true)
}
/// Device polling and one-time code exchange use the fixed raw auth branch,
/// unlike refresh, which uses the default Codex client in auth/manager.rs.
pub fn oauth_login_client(proxy: Option<&str>) -> Result<reqwest::Client, AccountError> {
    http_client(proxy, false)
}
fn http_client(proxy: Option<&str>, codex_defaults: bool) -> Result<reqwest::Client, AccountError> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none());
    if codex_defaults {
        builder = builder.default_headers(codex_login::default_client::default_headers());
    }
    if let Some(proxy) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy).map_err(|_| AccountError::ClientBuild)?);
    }
    // Preserve the fixed official CODEX_CA_CERTIFICATE / SSL_CERT_FILE
    // precedence and parser without changing this account's explicit proxy.
    codex_http_client::build_reqwest_client_with_custom_ca(builder)
        .map_err(|_| AccountError::ClientBuild)
}
fn oauth_profile(
    id_token: Option<&str>,
    workspace: &str,
) -> Result<(String, String), AccountError> {
    let claims = codex_login::token_data::parse_chatgpt_jwt_claims(
        id_token.ok_or(AccountError::InvalidProfile)?,
    )
    .map_err(|_| AccountError::InvalidProfile)?;
    if claims.chatgpt_account_id.as_deref() != Some(workspace) {
        return Err(AccountError::IdentityChanged);
    }
    let plan = claims
        .get_chatgpt_plan_type_raw()
        .ok_or(AccountError::InvalidProfile)?;
    let email = claims.email.ok_or(AccountError::InvalidProfile)?;
    let email = email.trim();
    if email.is_empty()
        || email.len() > 320
        || !email.contains('@')
        || email.chars().any(char::is_whitespace)
        || email.chars().any(char::is_control)
    {
        return Err(AccountError::InvalidProfile);
    }
    Ok((email.to_owned(), plan))
}

fn read_auth_bytes(path: &Path) -> Result<Vec<u8>, AccountError> {
    let f = File::open(path).map_err(|_| AccountError::AuthRead)?;
    let m = f.metadata().map_err(|_| AccountError::AuthRead)?;
    if !m.is_file() {
        return Err(AccountError::AuthRead);
    }
    if m.len() > MAX_AUTH_BYTES {
        return Err(AccountError::AuthTooLarge);
    }
    let mut raw = Vec::new();
    f.take(MAX_AUTH_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| AccountError::AuthRead)?;
    if raw.len() as u64 > MAX_AUTH_BYTES {
        return Err(AccountError::AuthTooLarge);
    }
    Ok(raw)
}
pub(crate) fn create_private_directory(path: &Path) -> Result<(), AccountError> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err(AccountError::PrivateState);
        }
    } else {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            create_private_directory(parent)?;
        }
        fs::create_dir(path).map_err(|_| AccountError::PrivateState)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| AccountError::PrivateState)?;
    }
    Ok(())
}
pub(crate) fn write_private_auth(home: &Path, raw: &[u8]) -> Result<(), AccountError> {
    create_private_directory(home)?;
    let dest = home.join("auth.json");
    if let Ok(m) = fs::symlink_metadata(&dest)
        && (!m.is_file() || m.file_type().is_symlink())
    {
        return Err(AccountError::PrivateState);
    }
    let temp = home.join(format!("auth.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut f = options
            .open(&temp)
            .map_err(|_| AccountError::PrivateState)?;
        f.write_all(raw).map_err(|_| AccountError::PrivateState)?;
        f.sync_all().map_err(|_| AccountError::PrivateState)?;
        fs::rename(&temp, &dest).map_err(|_| AccountError::PrivateState)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub(crate) fn read_private_auth(home: &Path) -> Result<Option<AuthDotJson>, AccountError> {
    let path = home.join("auth.json");
    if !path.exists() {
        return Ok(None);
    }
    let m = fs::symlink_metadata(path).map_err(|_| AccountError::PrivateState)?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(AccountError::PrivateState);
    }
    codex_login::load_auth_dot_json(
        home,
        AuthCredentialsStoreMode::File,
        AuthKeyringBackendKind::default(),
    )
    .map_err(|_| AccountError::InvalidAuthJson)
}
fn remove_private_credentials(home: &Path) -> Result<(), AccountError> {
    fs::remove_file(home.join("auth.json"))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .map_err(|_| AccountError::PrivateState)
}

fn valid_local_id(id: &str) -> bool {
    let mut components = Path::new(id).components();
    !id.is_empty()
        && !id.contains('\\')
        && matches!(components.next(),Some(std::path::Component::Normal(v)) if v==std::ffi::OsStr::new(id))
        && components.next().is_none()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    id: String,
    created_at_unix_ms: u64,
}
fn creation_time(owner: &Path, id: &str) -> Result<u64, AccountError> {
    let path = owner.join("creation.json");
    if path.exists() {
        let m = fs::symlink_metadata(&path).map_err(|_| AccountError::PrivateState)?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err(AccountError::PrivateState);
        }
        let c: Creation = serde_json::from_slice(&read_auth_bytes(&path)?)
            .map_err(|_| AccountError::PrivateState)?;
        if c.id != id || c.created_at_unix_ms == 0 {
            return Err(AccountError::PrivateState);
        }
        return Ok(c.created_at_unix_ms);
    }
    let created_at_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccountError::PrivateState)?
            .as_millis(),
    )
    .map_err(|_| AccountError::PrivateState)?;
    write_private_json(
        &path,
        &serde_json::to_vec(&Creation {
            id: id.to_owned(),
            created_at_unix_ms,
        })
        .map_err(|_| AccountError::PrivateState)?,
    )?;
    Ok(created_at_unix_ms)
}
fn write_private_json(path: &Path, raw: &[u8]) -> Result<(), AccountError> {
    if let Ok(m) = fs::symlink_metadata(path)
        && (!m.is_file() || m.file_type().is_symlink())
    {
        return Err(AccountError::PrivateState);
    }
    let parent = path.parent().ok_or(AccountError::PrivateState)?;
    create_private_directory(parent)?;
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&temp)
            .map_err(|_| AccountError::PrivateState)?;
        file.write_all(raw)
            .map_err(|_| AccountError::PrivateState)?;
        file.sync_all().map_err(|_| AccountError::PrivateState)?;
        fs::rename(&temp, path).map_err(|_| AccountError::PrivateState)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn read_admission(path: &Path) -> Result<PersistedAdmission, AccountError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistedAdmission::default());
        }
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => {}
        _ => return Err(AccountError::PrivateState),
    }
    serde_json::from_slice(&read_auth_bytes(path)?).map_err(|_| AccountError::PrivateState)
}
fn write_admission(
    directory: &Path,
    id: &str,
    state: &PersistedAdmission,
) -> Result<(), AccountError> {
    let raw = serde_json::to_vec(state).map_err(|_| AccountError::PrivateState)?;
    crate::storage::atomic(
        &directory.join("accounts").join(id).join("admission.json"),
        &raw,
    )
    .map_err(|_| AccountError::PrivateState)
}
fn read_registry(directory: &Path) -> Result<Vec<AccountConfig>, AccountError> {
    let path = directory.join("account_registry.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let m = fs::symlink_metadata(&path).map_err(|_| AccountError::PrivateState)?;
    if !m.is_file() || m.file_type().is_symlink() {
        return Err(AccountError::PrivateState);
    }
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&read_auth_bytes(&path)?).map_err(|_| AccountError::PrivateState)?;
    if entries.len() > 4096 {
        return Err(AccountError::InvalidConfiguration);
    }
    entries
        .into_iter()
        .map(|mut value| {
            let owned = value
                .as_object_mut()
                .ok_or(AccountError::PrivateState)?
                .remove("gateway_owned_source")
                .map(|v| v.as_bool().ok_or(AccountError::PrivateState))
                .transpose()?
                .unwrap_or(false);
            let mut entry: AccountConfig =
                serde_json::from_value(value).map_err(|_| AccountError::PrivateState)?;
            if owned {
                if !valid_local_id(&entry.id) {
                    return Err(AccountError::PrivateState);
                }
                let relative = PathBuf::from("accounts")
                    .join(&entry.id)
                    .join("home/auth.json");
                if entry.auth_path != relative {
                    return Err(AccountError::PrivateState);
                }
                entry.auth_path = directory.join(relative);
            }
            Ok(entry)
        })
        .collect()
}
fn write_registry(directory: &Path, configs: &[AccountConfig]) -> Result<(), AccountError> {
    if configs.len() > 4096 {
        return Err(AccountError::InvalidConfiguration);
    }
    let value: Vec<_> = configs
        .iter()
        .map(|c| {
            let relative = PathBuf::from("accounts").join(&c.id).join("home/auth.json");
            let owned = c.auth_path == directory.join(&relative);
            // Only a source recorded as this gateway's exact private home is
            // portable. External imports are not guessed or rebased.
            serde_json::json!({"id":c.id,
                "auth_path":if owned { &relative } else { &c.auth_path },
                "gateway_owned_source":owned,"proxy":c.proxy,"enabled":c.enabled})
        })
        .collect();
    let raw = serde_json::to_vec(&value).map_err(|_| AccountError::PrivateState)?;
    if raw.len() as u64 > MAX_AUTH_BYTES {
        return Err(AccountError::PrivateState);
    }
    write_private_json(&directory.join("account_registry.json"), &raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("codex-http-accounts-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn auth(path: &std::path::Path, account: &str, token: &str) {
        let body = serde_json::json!({"auth_mode":"chatgpt","tokens":{
            "id_token":"unused-jwt","access_token":token,"refresh_token":"refresh-secret",
            "account_id":account},"last_refresh":"2026-10-09T00:00:00Z"});
        fs::write(path, serde_json::to_vec(&body).unwrap()).unwrap();
    }

    fn config(first: PathBuf, second: PathBuf) -> GatewayConfig {
        serde_json::from_value(serde_json::json!({"listen":"127.0.0.1:18183","client_api_key":"123456",
            "state_dir":first.parent().unwrap().join("state"),"accounts":[
            {"id":"one","auth_path":first,"enabled":true},{"id":"two","auth_path":second,"enabled":true}]})).unwrap()
    }

    #[test]
    fn round_robin_uses_separate_clients_and_ignores_disabled_accounts() {
        let dir = TestDir::new();
        let first = dir.0.join("one.json");
        let second = dir.0.join("two.json");
        auth(&first, "workspace-one", "access-one");
        auth(&second, "workspace-two", "access-two");
        let mut cfg = config(first, second);
        let pool = AccountPool::from_config(&cfg).unwrap();
        let a = pool.next_enabled().unwrap().unwrap();
        let b = pool.next_enabled().unwrap().unwrap();
        assert_eq!(
            (a.id(), b.id(), pool.next_enabled().unwrap().unwrap().id()),
            ("one", "two", "one")
        );
        assert!(!std::ptr::eq(a.client(), b.client()));
        assert_ne!(a.revision(), b.revision());
        let mut headers = HeaderMap::new();
        a.authorize_headers(&mut headers).unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap().as_bytes(),
            b"Bearer access-one"
        );
        assert_eq!(
            headers.get("chatgpt-account-id").unwrap().as_bytes(),
            b"workspace-one"
        );
        assert!(headers.get(AUTHORIZATION).unwrap().is_sensitive());
        assert!(headers.get("chatgpt-account-id").unwrap().is_sensitive());
        cfg.accounts[1].enabled = false;
        let disabled = AccountPool::from_config(&cfg).unwrap();
        assert_eq!(disabled.enabled_count().unwrap(), 1);
        assert!(disabled.by_id("two").unwrap().is_none());
    }

    #[test]
    fn reload_replaces_only_one_revision_and_rejects_identity_swap() {
        let dir = TestDir::new();
        let first = dir.0.join("one.json");
        let second = dir.0.join("two.json");
        auth(&first, "workspace-one", "access-one");
        auth(&second, "workspace-two", "access-two");
        let pool = AccountPool::from_config(&config(first.clone(), second)).unwrap();
        let old = pool.by_id("one").unwrap().unwrap();
        let other = pool.by_id("two").unwrap().unwrap();
        auth(&first, "workspace-one", "new-access-one");
        assert_eq!(pool.reload_auth("one"), Ok(true));
        let new = pool.by_id("one").unwrap().unwrap();
        assert_ne!(old.revision(), new.revision());
        assert!(!Arc::ptr_eq(&old, &new));
        assert!(Arc::ptr_eq(&other, &pool.by_id("two").unwrap().unwrap()));
        assert_eq!(pool.reload_auth("one"), Ok(false));
        auth(&first, "foreign-workspace", "new-access-one");
        assert_eq!(pool.reload_auth("one"), Err(AccountError::IdentityChanged));
        assert!(Arc::ptr_eq(&new, &pool.by_id("one").unwrap().unwrap()));
    }

    #[test]
    fn rejects_duplicate_oauth_identity_and_redacts_errors() {
        let dir = TestDir::new();
        let first = dir.0.join("private-sentinel-one.json");
        let second = dir.0.join("private-sentinel-two.json");
        auth(&first, "same-workspace", "secret-sentinel");
        auth(&second, "same-workspace", "other-secret");
        assert!(matches!(
            AccountPool::from_config(&config(first.clone(), second)),
            Err(AccountError::DuplicateOAuthAccount)
        ));
        fs::write(&first, "{secret-sentinel").unwrap();
        let missing = dir.0.join("missing.json");
        auth(&missing, "unused-workspace", "unused-access");
        let mut cfg = config(first, missing);
        cfg.accounts[1].enabled = false;
        let error = AccountPool::from_config(&cfg).err().unwrap();
        let text = format!("{error:?} {error}");
        assert!(!text.contains("secret-sentinel"));
        assert!(!text.contains("private-sentinel"));
    }

    #[test]
    fn invalid_sdk_header_does_not_leave_partial_authorization() {
        let dir = TestDir::new();
        let first = dir.0.join("one.json");
        auth(&first, "workspace-one", "access-one");
        let unused = dir.0.join("unused.json");
        auth(&unused, "unused-workspace", "unused-access");
        let cfg = config(first, unused);
        let pool = AccountPool::from_config(&cfg).unwrap();
        let mut accounts = pool.accounts.write().unwrap();
        let account = Arc::get_mut(&mut accounts[0]).unwrap();
        // A malformed internal value must not leave the bearer header behind.
        account.workspace_account_id = "bad\naccount".to_owned();
        let mut headers = HeaderMap::new();
        assert_eq!(
            account.authorize_headers(&mut headers),
            Err(AccountError::InvalidTokens)
        );
        assert!(headers.is_empty());
    }

    fn staged_auth(
        cfg: &GatewayConfig,
        id: &str,
        workspace: &str,
        token: &str,
        email: Option<&str>,
        plan: Option<&str>,
    ) -> PathBuf {
        use base64::Engine;
        let claims = serde_json::json!({"email": email, "https://api.openai.com/auth": {
            "chatgpt_account_id": workspace, "chatgpt_plan_type": plan,
            "chatgpt_user_id": "synthetic-user"
        }});
        let jwt = format!(
            "header.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        let body = serde_json::json!({"auth_mode":"chatgpt", "tokens":{
            "id_token":jwt,"access_token":token,"refresh_token":"synthetic-refresh",
            "account_id":workspace},"last_refresh":"2026-10-10T00:00:00Z"});
        let home = cfg.state_dir.join("accounts").join(id).join("home");
        write_private_auth(&home, &serde_json::to_vec(&body).unwrap()).unwrap();
        home
    }

    fn import_config(dir: &TestDir) -> GatewayConfig {
        GatewayConfig {
            state_dir: dir.0.join("state"),
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn oauth_import_creates_and_never_merges_same_email_different_workspaces() {
        let dir = TestDir::new();
        let cfg = import_config(&dir);
        let pool = AccountPool::from_config(&cfg).unwrap();
        let first_home = staged_auth(
            &cfg,
            "stage-one",
            "workspace-one",
            "token-one",
            Some("same@example.test"),
            Some("pro"),
        );
        let original = read_auth_bytes(&first_home.join("auth.json")).unwrap();
        let (first, created) = pool.upsert_from_home("stage-one", None).unwrap();
        assert!(created);
        assert_eq!(
            first.oauth_profile().unwrap(),
            ("same@example.test".into(), "pro".into())
        );
        staged_auth(
            &cfg,
            "stage-two",
            "workspace-two",
            "token-two",
            Some("same@example.test"),
            Some("pro"),
        );
        let (second, created) = pool.upsert_from_home("stage-two", None).unwrap();
        assert!(created);
        assert_ne!(first.id(), second.id());
        assert_eq!(pool.all().unwrap().len(), 2);
        assert_eq!(
            read_auth_bytes(&first_home.join("auth.json")).unwrap(),
            original
        );
        let restarted = AccountPool::from_config(&cfg).unwrap();
        assert_eq!(restarted.all().unwrap().len(), 2);
        assert_eq!(
            restarted
                .managed(first.id())
                .unwrap()
                .unwrap()
                .oauth_profile()
                .unwrap(),
            first.oauth_profile().unwrap()
        );
    }

    #[test]
    fn oauth_reauthorization_preserves_runtime_cooldown_and_frozen_inflight_snapshot() {
        let dir = TestDir::new();
        let cfg = import_config(&dir);
        let pool = AccountPool::from_config(&cfg).unwrap();
        staged_auth(
            &cfg,
            "initial",
            "workspace",
            "old-token",
            Some("old@example.test"),
            Some("pro"),
        );
        let (old, _) = pool.upsert_from_home("initial", None).unwrap();
        let lease = pool.lease(old.id(), true).unwrap().unwrap();
        pool.set_capacity(old.id(), 7).unwrap();
        pool.rest(old.id(), Duration::from_secs(600)).unwrap();
        let reset = unix_ms() + 600_000;
        pool.upstream_rejection(old.id(), old.revision(), true, Some(reset))
            .unwrap();
        assert!(old.admin_enabled().unwrap());
        assert!(!old.availability().unwrap().enabled);
        pool.set_enabled(old.id(), false).unwrap();
        staged_auth(
            &cfg,
            "renewed",
            "workspace",
            "new-token",
            Some("new@example.test"),
            Some("pro"),
        );
        let (new, created) = pool
            .upsert_from_home("renewed", Some("http://127.0.0.1:12345".into()))
            .unwrap();
        assert!(!created);
        assert_eq!(new.id(), old.id());
        assert_eq!(new.created_at_unix_ms(), old.created_at_unix_ms());
        assert_ne!(new.revision(), old.revision());
        assert!(!std::ptr::eq(new.client(), old.client()));
        assert_eq!(old.oauth_profile().unwrap().0, "old@example.test");
        assert_eq!(new.oauth_profile().unwrap().0, "new@example.test");
        assert_eq!(old.access_token, "old-token");
        assert_eq!(lease.account().access_token, "old-token");
        let available = new.availability().unwrap();
        assert!(!new.admin_enabled().unwrap());
        assert!(!available.auth_invalid);
        assert!(available.resting);
        assert_eq!(available.active_requests, 1);
        assert_eq!(available.max_concurrent_requests, 7);
        assert_eq!(available.quota_cooldown_until_unix_ms, Some(reset));
        pool.upstream_rejection(old.id(), old.revision(), true, Some(reset + 600_000))
            .unwrap();
        assert!(!new.availability().unwrap().auth_invalid);
        assert_eq!(
            new.availability().unwrap().quota_cooldown_until_unix_ms,
            Some(reset)
        );
        drop(lease);
        assert_eq!(new.availability().unwrap().active_requests, 0);
        let restarted = AccountPool::from_config(&cfg).unwrap();
        let saved = restarted.managed(old.id()).unwrap().unwrap();
        assert_eq!(saved.access_token, "new-token");
        assert_eq!(saved.proxy(), Some("http://127.0.0.1:12345"));
        assert!(!saved.admin_enabled().unwrap());
        assert!(!saved.availability().unwrap().auth_invalid);
        assert_eq!(
            saved.availability().unwrap().quota_cooldown_until_unix_ms,
            Some(reset)
        );
    }

    #[test]
    fn oauth_same_bearer_reimport_keeps_rejection_and_never_writes_external_source() {
        let dir = TestDir::new();
        let mut cfg = import_config(&dir);
        let source_home = staged_auth(
            &cfg,
            "source",
            "workspace",
            "original-token",
            Some("first@example.test"),
            Some("pro"),
        );
        let source = source_home.join("auth.json");
        let source_raw = read_auth_bytes(&source).unwrap();
        cfg.accounts.push(AccountConfig {
            id: "configured".into(),
            auth_path: source.clone(),
            proxy: None,
            enabled: true,
        });
        let pool = AccountPool::from_config(&cfg).unwrap();
        let old = pool.managed("configured").unwrap().unwrap();
        pool.upstream_rejection(old.id(), old.revision(), true, None)
            .unwrap();
        staged_auth(
            &cfg,
            "reauth",
            "workspace",
            "original-token",
            Some("changed@example.test"),
            Some("pro"),
        );
        let (new, created) = pool
            .upsert_from_home("reauth", Some("http://127.0.0.1:12345".into()))
            .unwrap();
        assert!(!created);
        assert!(new.admin_enabled().unwrap());
        assert!(new.availability().unwrap().auth_invalid);
        assert_eq!(read_auth_bytes(&source).unwrap(), source_raw);
        assert_eq!(pool.reload_auth("configured"), Ok(false));
        assert_eq!(
            pool.managed("configured")
                .unwrap()
                .unwrap()
                .oauth_profile()
                .unwrap()
                .0,
            "changed@example.test"
        );
        let saved = AccountPool::from_config(&cfg)
            .unwrap()
            .managed("configured")
            .unwrap()
            .unwrap();
        assert!(saved.availability().unwrap().auth_invalid);
        assert_eq!(saved.oauth_profile().unwrap().0, "changed@example.test");
    }

    #[test]
    fn oauth_import_rejects_missing_profile_nonpro_identity_mismatch_and_draining() {
        let dir = TestDir::new();
        let cfg = import_config(&dir);
        let pool = AccountPool::from_config(&cfg).unwrap();
        for (id, email, plan, expected) in [
            (
                "missing-email",
                None,
                Some("pro"),
                AccountError::InvalidProfile,
            ),
            (
                "bad-email",
                Some("bad\n@example.test"),
                Some("pro"),
                AccountError::InvalidProfile,
            ),
            (
                "missing-plan",
                Some("a@example.test"),
                None,
                AccountError::InvalidProfile,
            ),
            (
                "other-plan",
                Some("a@example.test"),
                Some("plus"),
                AccountError::ProPlanRequired,
            ),
        ] {
            staged_auth(&cfg, id, "workspace", "token", email, plan);
            assert!(matches!(pool.upsert_from_home(id, None), Err(error) if error == expected));
        }
        let home = staged_auth(
            &cfg,
            "wrong-workspace",
            "workspace",
            "token",
            Some("a@example.test"),
            Some("pro"),
        );
        let mut raw: serde_json::Value =
            serde_json::from_slice(&read_auth_bytes(&home.join("auth.json")).unwrap()).unwrap();
        raw["tokens"]["account_id"] = serde_json::json!("another-workspace");
        write_private_auth(&home, &serde_json::to_vec(&raw).unwrap()).unwrap();
        assert!(matches!(
            pool.upsert_from_home("wrong-workspace", None),
            Err(AccountError::IdentityChanged)
        ));
        assert!(pool.all().unwrap().is_empty());
        staged_auth(
            &cfg,
            "initial",
            "workspace",
            "old",
            Some("a@example.test"),
            Some("pro"),
        );
        let (old, _) = pool.upsert_from_home("initial", None).unwrap();
        let lease = pool.lease(old.id(), true).unwrap().unwrap();
        assert!(!pool.delete_draining(old.id()).unwrap());
        staged_auth(
            &cfg,
            "new",
            "workspace",
            "new",
            Some("a@example.test"),
            Some("pro"),
        );
        assert!(matches!(
            pool.upsert_from_home("new", None),
            Err(AccountError::Deleting)
        ));
        assert_eq!(pool.all().unwrap().len(), 1);
        drop(lease);
        assert!(pool.all().unwrap().is_empty());
    }

    #[test]
    fn oauth_registry_write_failure_rolls_back_existing_private_credentials() {
        let dir = TestDir::new();
        let cfg = import_config(&dir);
        let pool = AccountPool::from_config(&cfg).unwrap();
        staged_auth(
            &cfg,
            "initial",
            "workspace",
            "old",
            Some("old@example.test"),
            Some("pro"),
        );
        let (old, _) = pool.upsert_from_home("initial", None).unwrap();
        let reset = unix_ms() + 600_000;
        pool.upstream_rejection(old.id(), old.revision(), true, Some(reset))
            .unwrap();
        let registry = cfg.state_dir.join("account_registry.json");
        let saved_registry = fs::read(&registry).unwrap();
        fs::remove_file(&registry).unwrap();
        fs::create_dir(&registry).unwrap();
        staged_auth(
            &cfg,
            "new",
            "workspace",
            "new",
            Some("new@example.test"),
            Some("pro"),
        );
        assert!(matches!(
            pool.upsert_from_home("new", None),
            Err(AccountError::PrivateState)
        ));
        assert!(Arc::ptr_eq(&old, &pool.managed(old.id()).unwrap().unwrap()));
        old.verify_private_identity().unwrap();
        assert!(old.availability().unwrap().auth_invalid);
        fs::remove_dir(&registry).unwrap();
        fs::write(&registry, saved_registry).unwrap();
        let saved = AccountPool::from_config(&cfg)
            .unwrap()
            .managed(old.id())
            .unwrap()
            .unwrap();
        assert_eq!(saved.access_token, "old");
        assert!(saved.availability().unwrap().auth_invalid);
        assert_eq!(
            saved.availability().unwrap().quota_cooldown_until_unix_ms,
            Some(reset)
        );
    }

    #[test]
    fn concurrent_oauth_imports_of_one_workspace_publish_one_account() {
        let dir = TestDir::new();
        let cfg = import_config(&dir);
        let pool = Arc::new(AccountPool::from_config(&cfg).unwrap());
        for id in ["stage-a", "stage-b"] {
            staged_auth(
                &cfg,
                id,
                "same-workspace",
                id,
                Some("same@example.test"),
                Some("pro"),
            );
        }
        let start = Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = ["stage-a", "stage-b"]
            .into_iter()
            .map(|id| {
                let pool = pool.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let (account, created) = pool.upsert_from_home(id, None).unwrap();
                    (account.id().to_owned(), created)
                })
            })
            .collect();
        start.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results[0].0, results[1].0);
        assert_eq!(results.iter().filter(|(_, created)| *created).count(), 1);
        let accounts = pool.all().unwrap();
        assert_eq!(accounts.len(), 1);
        accounts[0].verify_private_identity().unwrap();
        let restarted = AccountPool::from_config(&cfg).unwrap();
        let saved = restarted.all().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id(), accounts[0].id());
        assert_eq!(saved[0].revision(), accounts[0].revision());
    }
}
