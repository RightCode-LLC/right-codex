//! Account-owned exporters, resting and persisted idle-cache reaping.
use crate::gateway::AppState;
use futures_util::StreamExt;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
pub fn start(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::join!(
            housekeeping(state.clone()),
            quota_poll(state.clone()),
            collect_facts(state)
        );
    })
}

async fn collect_facts(state: Arc<AppState>) {
    let Some(collector) = &state.collector else {
        return;
    };
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        for account in state.accounts.all().unwrap_or_default() {
            let _ = collector.export_for_account(&account).await;
        }
    }
}
async fn housekeeping(state: Arc<AppState>) {
    // Reattach only configured account revisions to their own durable queue.
    if let Ok(accounts) = state.accounts.all() {
        for account in accounts {
            let _ = state.metrics.flush_account(&account).await;
        }
    }
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    let mut last_rest = tokio::time::Instant::now();
    loop {
        interval.tick().await;
        if let Ok(report) = state.metrics.export_all().await
            && (report.acked_batches > 0
                || report.unknown_delivery_batches > 0
                || report.failed_accounts > 0)
        {
            // HTTP acknowledgement only; never claim individual metric
            // acceptance or include account identifiers or payloads here.
            tracing::info!(
                acknowledged_batches = report.acked_batches,
                unknown_batches = report.unknown_delivery_batches,
                failed_accounts = report.failed_accounts,
                "official metrics HTTP delivery summary"
            );
        }
        let settings = state.scheduling();
        if let Ok(entries) = std::fs::read_dir(&state.scope_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(key) = path.file_stem().and_then(|s| s.to_str()) {
                    let _ = state.sessions.evict_idle_persisted(
                        key,
                        &path,
                        crate::gateway::now_ms(),
                        settings.idle_timeout_secs.saturating_mul(1000),
                    );
                }
            }
        }
        if settings.rest_interval_minutes > 0
            && last_rest.elapsed()
                >= Duration::from_secs(settings.rest_interval_minutes.saturating_mul(60))
        {
            last_rest = tokio::time::Instant::now();
            if let Ok(accounts) = state.accounts.all() {
                let mut eligible = accounts
                    .into_iter()
                    .filter(|a| {
                        a.availability()
                            .is_ok_and(|v| v.enabled && !v.deleting && !v.quota_cooldown)
                    })
                    .map(|a| (Uuid::new_v4(), a))
                    .collect::<Vec<_>>();
                eligible.sort_by_key(|(r, _)| *r);
                let count = (eligible.len() * usize::from(settings.rest_percent)).div_ceil(100);
                for (_, account) in eligible.into_iter().take(count) {
                    let _ = state.accounts.rest(
                        account.id(),
                        Duration::from_secs(settings.rest_duration_minutes.saturating_mul(60)),
                    );
                }
            }
        }
    }
}

async fn quota_poll(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let accounts = state.accounts.all().unwrap_or_default();
        futures_util::stream::iter(accounts)
            .for_each_concurrent(4, |account| {
                let state = state.clone();
                async move {
                    if account
                        .availability()
                        .is_ok_and(|v| v.enabled && !v.deleting)
                    {
                        // Failures leave the previous observed quota unchanged.
                        // The pool verifies the auth revision again before commit.
                        let _ = tokio::time::timeout(
                            Duration::from_secs(30),
                            state.accounts.refresh_quota(account.id()),
                        )
                        .await;
                    }
                }
            })
            .await;
    }
}
