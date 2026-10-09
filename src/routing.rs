//! Account-owned official workspace discovery. Only Responses routing consumes
//! this origin; Models, Search and Images retain their configured endpoints.
use crate::accounts::{Account, AccountError, AccountPool};
use codex_backend_client::AccountsCheckResponse;
use codex_backend_openapi_models::models as wire;
use codex_protocol::account::PlanType;
use codex_protocol::protocol::{
    CreditsSnapshot, RateLimitReachedType, RateLimitSnapshot, RateLimitWindow,
    SpendControlLimitSnapshot,
};
use http::HeaderMap;
use serde::Deserialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("official upstream rejected the request")]
    Upstream(Box<crate::transport::RawHttpError>),
    #[error("account identity changed during workspace discovery")]
    IdentityChanged,
    #[error("official workspace discovery failed")]
    DiscoveryFailed,
    #[error("official selected workspace is missing")]
    WorkspaceMissing,
    #[error("official workspace routing response is invalid")]
    InvalidRoute,
    #[error("official usage response is invalid")]
    InvalidUsage,
}
#[derive(Clone)]
pub struct WorkspaceRoute {
    pub backend_origin: Option<String>,
    pub account_routing_override: Option<String>,
    pub auth_revision: String,
    observed: Instant,
}
pub struct ResponsesRoute {
    pub base_url: String,
    pub account_routing_override: Option<String>,
    pub auth_revision: String,
}

impl Account {
    pub async fn refresh_workspace_route(
        &self,
        force: bool,
    ) -> Result<WorkspaceRoute, RoutingError> {
        let mut cached = self.routing.lock().await;
        self.verify_private_identity()
            .map_err(|_| RoutingError::IdentityChanged)?;
        if !force
            && let Some(route) = cached.as_ref()
            && route.auth_revision == self.revision()
            && route.observed.elapsed() < Duration::from_secs(60)
        {
            return Ok(route.clone());
        }
        let mut headers = HeaderMap::new();
        self.authorize_headers(&mut headers)
            .map_err(|_| RoutingError::IdentityChanged)?;
        let response = self
            .client()
            .get(format!(
                "{}/wham/accounts/check",
                self.chatgpt_base_url().trim_end_matches('/')
            ))
            .headers(headers)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| RoutingError::DiscoveryFailed)?;
        if !response.status().is_success() {
            return Err(RoutingError::Upstream(Box::new(
                crate::transport::read_http_error(response, 64 * 1024 * 1024).await,
            )));
        }
        let response: AccountsCheckResponse = crate::oauth_contract::json_reply(response)
            .await
            .map_err(|_| RoutingError::DiscoveryFailed)?;
        let selected = response
            .accounts
            .iter()
            .find(|a| a.id == self.workspace_account_id())
            .ok_or(RoutingError::WorkspaceMissing)?;
        let (origin, override_header) = match (
            &selected.workspace_backend_origin,
            &selected.account_routing_override,
        ) {
            (None, None) => (None, None),
            (Some(origin), Some(value)) => {
                let header = match value.as_str() {
                    "NO_CONSTRAINT" => None,
                    "us" | "us_cr" => Some(value.clone()),
                    _ => return Err(RoutingError::InvalidRoute),
                };
                // Fixed app-server/account_processor/workspace_routing.rs:
                // NO_CONSTRAINT is a backend-origin sentinel, independently
                // of the routing-header sentinel. It retains the effective
                // configured backend instead of being parsed as a URL.
                let origin = if origin == "NO_CONSTRAINT" {
                    None
                } else {
                    Some(validate_origin(origin, self.allows_insecure_test())?)
                };
                (origin, header)
            }
            _ => return Err(RoutingError::InvalidRoute),
        };
        self.verify_private_identity()
            .map_err(|_| RoutingError::IdentityChanged)?;
        let route = WorkspaceRoute {
            backend_origin: origin,
            account_routing_override: override_header,
            auth_revision: self.revision().to_owned(),
            observed: Instant::now(),
        };
        *cached = Some(route.clone());
        Ok(route)
    }
    pub async fn responses_route(&self, configured: &str) -> Result<ResponsesRoute, RoutingError> {
        // Same fixed provider gate as supports_codex_backend_routes(); an
        // arbitrary custom /v1 base is not silently converted to ChatGPT.
        if !configured
            .trim_end_matches('/')
            .ends_with("/backend-api/codex")
        {
            return Ok(ResponsesRoute {
                base_url: configured.to_owned(),
                account_routing_override: None,
                auth_revision: self.revision().to_owned(),
            });
        }
        let mut base = Url::parse(configured).map_err(|_| RoutingError::InvalidRoute)?;
        let bootstrap =
            Url::parse(self.chatgpt_base_url()).map_err(|_| RoutingError::InvalidRoute)?;
        // A matching suffix alone is not first-party ownership. A configured
        // operator origin remains configured rather than being overwritten.
        if base.origin() != bootstrap.origin() {
            return Ok(ResponsesRoute {
                base_url: configured.to_owned(),
                account_routing_override: None,
                auth_revision: self.revision().to_owned(),
            });
        }
        let route = self.refresh_workspace_route(false).await?;
        if let Some(origin) = &route.backend_origin {
            let origin = Url::parse(origin).map_err(|_| RoutingError::InvalidRoute)?;
            base.set_scheme(origin.scheme())
                .map_err(|_| RoutingError::InvalidRoute)?;
            base.set_host(origin.host_str())
                .map_err(|_| RoutingError::InvalidRoute)?;
            base.set_port(origin.port())
                .map_err(|_| RoutingError::InvalidRoute)?;
        }
        Ok(ResponsesRoute {
            base_url: base.into(),
            account_routing_override: route.account_routing_override,
            auth_revision: route.auth_revision,
        })
    }
    pub async fn quota_snapshot(&self) -> Result<Vec<RateLimitSnapshot>, RoutingError> {
        Ok(self.quota_data().await?.0)
    }
    async fn quota_data(&self) -> Result<(Vec<RateLimitSnapshot>, Option<bool>), RoutingError> {
        self.verify_private_identity()
            .map_err(|_| RoutingError::IdentityChanged)?;
        let mut headers = HeaderMap::new();
        self.authorize_headers(&mut headers)
            .map_err(|_| RoutingError::IdentityChanged)?;
        let response = self
            .client()
            .get(format!(
                "{}/wham/usage",
                self.chatgpt_base_url().trim_end_matches('/')
            ))
            .headers(headers)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| RoutingError::DiscoveryFailed)?;
        if !response.status().is_success() {
            return Err(RoutingError::Upstream(Box::new(
                crate::transport::read_http_error(response, 64 * 1024 * 1024).await,
            )));
        }
        let payload: Usage = crate::oauth_contract::json_reply(response)
            .await
            .map_err(|_| RoutingError::InvalidUsage)?;
        if payload
            .account_id
            .as_deref()
            .is_some_and(|v| v != self.workspace_account_id())
        {
            return Err(RoutingError::IdentityChanged);
        }
        let allowed = payload
            .rate_limits
            .rate_limit
            .as_ref()
            .and_then(|v| v.as_deref())
            .map(|v| v.allowed);
        let snapshots = usage_snapshots(payload);
        self.verify_private_identity()
            .map_err(|_| RoutingError::IdentityChanged)?;
        Ok((snapshots, allowed))
    }
}

pub(crate) fn validate_origin(value: &str, allow_insecure: bool) -> Result<String, RoutingError> {
    let origin = Url::parse(value).map_err(|_| RoutingError::InvalidRoute)?;
    if value.trim() != value
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !(origin.scheme() == "https"
            || (allow_insecure
                && origin.scheme() == "http"
                && origin.host_str().is_some_and(|h| {
                    h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "[::1]"
                })))
    {
        return Err(RoutingError::InvalidRoute);
    }
    Ok(origin.origin().ascii_serialization())
}

impl AccountPool {
    pub async fn refresh_quota(&self, id: &str) -> Result<Vec<RateLimitSnapshot>, RoutingError> {
        let account = self
            .by_id(id)
            .map_err(|_| RoutingError::IdentityChanged)?
            .ok_or(RoutingError::IdentityChanged)?;
        let (snapshots, allowed) = match account.quota_data().await {
            Ok(value) => value,
            Err(error) => {
                if let RoutingError::Upstream(source) = &error
                    && crate::upstream_policy::observe_raw_http(self, &account, source).is_err()
                {
                    tracing::warn!("upstream account status persistence failed");
                }
                return Err(error);
            }
        };
        if self
            .by_id(id)?
            .is_none_or(|a| a.revision() != account.revision())
        {
            return Err(RoutingError::IdentityChanged);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RoutingError::InvalidUsage)?
            .as_secs();
        let codex = snapshots
            .iter()
            .find(|s| s.limit_id.as_deref() == Some("codex"))
            .or_else(|| snapshots.first());
        if let Some(s) = codex {
            let windows = [s.primary.as_ref(), s.secondary.as_ref()];
            let blocked = allowed == Some(false)
                || s.spend_control_reached == Some(true)
                || windows.iter().flatten().any(|w| w.used_percent >= 100.0)
                || s.rate_limit_reached_type.is_some();
            if blocked {
                let until = windows
                    .iter()
                    .flatten()
                    .filter(|w| w.used_percent >= 100.0)
                    .filter_map(|w| w.resets_at)
                    .filter_map(|v| u64::try_from(v).ok())
                    .filter(|v| *v > now)
                    .max();
                if let Some(until) = until {
                    self.quota_for_revision(
                        id,
                        account.revision(),
                        Some(Duration::from_secs(until - now)),
                    )
                    .map_err(|_| RoutingError::IdentityChanged)?;
                }
            } else {
                self.quota_for_revision(id, account.revision(), None)
                    .map_err(|_| RoutingError::IdentityChanged)?;
            }
        }
        Ok(snapshots)
    }
}
impl From<AccountError> for RoutingError {
    fn from(_: AccountError) -> Self {
        Self::IdentityChanged
    }
}

// Derived from OpenAI Codex backend-client/src/client.rs:613-825 and
// client/rate_limit_resets.rs:32-67, a956835d020762cb2b570053af06f643a11c0ecc.
// Copyright OpenAI, Apache-2.0; vendor/codex/LICENSE and NOTICE apply.
// The original mapper is private. Wire types are the unchanged official crate;
// only its small projection is adapted to an instance-owned account client.
#[derive(Deserialize)]
struct Usage {
    #[serde(flatten)]
    rate_limits: wire::RateLimitStatusPayload,
    additional_rate_limits: Option<Vec<AdditionalUsage>>,
    account_id: Option<String>,
}
#[derive(Deserialize)]
struct AdditionalUsage {
    #[serde(flatten)]
    details: wire::AdditionalRateLimitDetails,
    normal_model_slug: Option<String>,
}
fn usage_snapshots(payload: Usage) -> Vec<RateLimitSnapshot> {
    let plan: PlanType = match payload.rate_limits.plan_type {
        wire::PlanType::Education => PlanType::Edu,
        wire::PlanType::Guest
        | wire::PlanType::FreeWorkspace
        | wire::PlanType::Quorum
        | wire::PlanType::K12
        | wire::PlanType::Unknown => PlanType::Unknown,
        v => serde_json::from_value(serde_json::to_value(v).expect("official plan serializable"))
            .expect("official plan mapping"),
    };
    let reached = payload
        .rate_limits
        .rate_limit_reached_type
        .flatten()
        .and_then(|v| match v.kind {
            wire::RateLimitReachedKind::RateLimitReached => {
                Some(RateLimitReachedType::RateLimitReached)
            }
            wire::RateLimitReachedKind::WorkspaceOwnerCreditsDepleted => {
                Some(RateLimitReachedType::WorkspaceOwnerCreditsDepleted)
            }
            wire::RateLimitReachedKind::WorkspaceMemberCreditsDepleted => {
                Some(RateLimitReachedType::WorkspaceMemberCreditsDepleted)
            }
            wire::RateLimitReachedKind::WorkspaceOwnerUsageLimitReached => {
                Some(RateLimitReachedType::WorkspaceOwnerUsageLimitReached)
            }
            wire::RateLimitReachedKind::WorkspaceMemberUsageLimitReached => {
                Some(RateLimitReachedType::WorkspaceMemberUsageLimitReached)
            }
            wire::RateLimitReachedKind::Unknown => None,
        });
    let mut result = vec![make_snapshot(
        Some("codex".into()),
        None,
        payload.rate_limits.rate_limit.flatten().map(|v| *v),
        payload.rate_limits.credits.flatten().map(|v| *v),
        payload.rate_limits.spend_control.flatten().map(|v| *v),
        plan,
        reached,
    )];
    for extra in payload.additional_rate_limits.into_iter().flatten() {
        let mut snapshot = make_snapshot(
            Some(extra.details.metered_feature),
            Some(extra.details.limit_name),
            extra.details.rate_limit.flatten().map(|v| *v),
            None,
            None,
            plan,
            None,
        );
        snapshot.normal_model_slug = extra.normal_model_slug;
        result.push(snapshot);
    }
    result
}
fn make_snapshot(
    limit_id: Option<String>,
    limit_name: Option<String>,
    limit: Option<wire::RateLimitStatusDetails>,
    credits: Option<wire::CreditStatusDetails>,
    spend: Option<wire::SpendControlStatusDetails>,
    plan: PlanType,
    reached: Option<RateLimitReachedType>,
) -> RateLimitSnapshot {
    let (primary, secondary) = limit
        .map(|v| (window(v.primary_window), window(v.secondary_window)))
        .unwrap_or((None, None));
    let spend_control_reached = spend.as_ref().map(|v| v.reached);
    let individual_limit =
        spend
            .and_then(|v| v.individual_limit.flatten())
            .map(|v| SpendControlLimitSnapshot {
                limit: v.limit,
                used: v.used,
                remaining_percent: v.remaining_percent,
                resets_at: i64::from(v.reset_at),
            });
    RateLimitSnapshot {
        limit_id,
        limit_name,
        normal_model_slug: None,
        primary,
        secondary,
        credits: credits.map(|v| CreditsSnapshot {
            has_credits: v.has_credits,
            unlimited: v.unlimited,
            balance: v.balance.flatten(),
        }),
        individual_limit,
        spend_control_reached,
        plan_type: Some(plan),
        rate_limit_reached_type: reached,
    }
}
fn window(window: Option<Option<Box<wire::RateLimitWindowSnapshot>>>) -> Option<RateLimitWindow> {
    let v = window.flatten()?;
    Some(RateLimitWindow {
        used_percent: f64::from(v.used_percent),
        window_minutes: if v.limit_window_seconds <= 0 {
            None
        } else {
            Some((i64::from(v.limit_window_seconds) + 59) / 60)
        },
        resets_at: Some(i64::from(v.reset_at)),
    })
}
