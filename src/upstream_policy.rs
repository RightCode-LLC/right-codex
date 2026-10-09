//! Admission changes driven by actual upstream failures, never response retries.
use crate::accounts::{Account, AccountError, AccountPool};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn observe_http(
    pool: &AccountPool,
    account: &Account,
    status: u16,
    headers: Option<&HeaderMap>,
    body: Option<&Value>,
) -> Result<(), AccountError> {
    let advice = headers.and_then(codex_http_client::RetryAfter::from_headers);
    observe_response(pool, account, status, headers, body, advice)
}

pub fn observe_raw_http(
    pool: &AccountPool,
    account: &Account,
    error: &crate::transport::RawHttpError,
) -> Result<(), AccountError> {
    let body = error
        .complete
        .then(|| serde_json::from_slice::<Value>(&error.body).ok())
        .flatten();
    observe_response(
        pool,
        account,
        error.status.as_u16(),
        Some(&error.headers),
        body.as_ref(),
        error.retry_after,
    )
}

fn observe_response(
    pool: &AccountPool,
    account: &Account,
    status: u16,
    headers: Option<&HeaderMap>,
    body: Option<&Value>,
    advice: Option<codex_http_client::RetryAfter>,
) -> Result<(), AccountError> {
    match status {
        401 => pool.upstream_rejection(account.id(), account.revision(), true, None),
        429 => {
            let now = SystemTime::now();
            if let Some(reset) = reset_time(headers, body, now, advice) {
                pool.upstream_rejection(account.id(), account.revision(), false, Some(reset))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Only actual error envelopes are inspected. A tool's arbitrary JSON output
/// or text mentioning status codes and reset times has no scheduling effect.
pub fn observe_event(
    pool: &AccountPool,
    account: &Account,
    event: &Value,
) -> Result<(), AccountError> {
    let Some(status) = event_status(event) else {
        return Ok(());
    };
    let mut headers = HeaderMap::new();
    for node in error_envelopes(event) {
        if let Some(values) = node.get("headers").and_then(Value::as_object) {
            for (name, value) in values {
                let text = match value {
                    Value::String(v) => v.clone(),
                    Value::Number(v) => v.to_string(),
                    _ => continue,
                };
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&text),
                ) {
                    headers.append(name, value);
                }
            }
        }
    }
    observe_http(pool, account, status, Some(&headers), Some(event))
}

pub fn event_status(event: &Value) -> Option<u16> {
    if !matches!(
        event.get("type").and_then(Value::as_str),
        Some("error" | "response.failed")
    ) {
        return None;
    }
    for node in error_envelopes(event) {
        for field in ["status", "status_code"] {
            if let Some(status) = node
                .get(field)
                .and_then(Value::as_u64)
                .and_then(|v| u16::try_from(v).ok())
                .filter(|v| (400..=599).contains(v))
            {
                return Some(status);
            }
        }
    }
    for node in error_envelopes(event).into_iter().skip(1) {
        if ["code", "type"].iter().any(|field| {
            matches!(
                node.get(*field).and_then(Value::as_str),
                Some(
                    "usage_limit_reached"
                        | "rate_limit_exceeded"
                        | "slow_down"
                        | "insufficient_quota"
                        | "credit_balance_exhausted"
                        | "organization_spend_limit_exceeded"
                        | "project_spend_limit_exceeded"
                )
            )
        }) {
            return Some(429);
        }
    }
    None
}

fn error_envelopes(value: &Value) -> Vec<&Value> {
    let mut nodes = vec![value];
    if let Some(error) = value.get("error").filter(|v| v.is_object()) {
        nodes.push(error);
    }
    if let Some(response) = value.get("response").filter(|v| v.is_object()) {
        nodes.push(response);
        if let Some(error) = response.get("error").filter(|v| v.is_object()) {
            nodes.push(error);
        }
    }
    nodes
}

fn reset_time(
    headers: Option<&HeaderMap>,
    body: Option<&Value>,
    now: SystemTime,
    advice: Option<codex_http_client::RetryAfter>,
) -> Option<u64> {
    let now_ms = millis(now)?;
    let mut resets = Vec::new();
    if let Some(body) = body {
        for node in error_envelopes(body) {
            // Official 0.160.0 API bridge / failed response schema uses Unix
            // seconds. Its WS 429 fixture also supplies resets_in_seconds.
            if let Some(at) = node
                .get("resets_at")
                .and_then(Value::as_u64)
                .and_then(|v| v.checked_mul(1000))
            {
                resets.push(at);
            }
            if let Some(after) = node
                .get("resets_in_seconds")
                .and_then(Value::as_u64)
                .and_then(|v| v.checked_mul(1000))
                .and_then(|v| now_ms.checked_add(v))
            {
                resets.push(after);
            }
        }
    }
    if let Some(headers) = headers {
        // Use the advice captured at header receipt; a delayed error body must
        // not restart Retry-After. The pinned parser also supports HTTP dates.
        if let Some(advice) = advice
            && let Some(at) = now.checked_add(advice.remaining_delay()).and_then(millis)
        {
            resets.push(at);
        }
        // Matches official primary/secondary rate-limit header families. A
        // non-exhausted window must not lengthen another window's cooldown.
        for (name, value) in headers {
            let name = name.as_str();
            let Some(window) = name.strip_suffix("-reset-at") else {
                continue;
            };
            if !window.starts_with("x-")
                || !(window.ends_with("-primary") || window.ends_with("-secondary"))
            {
                continue;
            }
            if headers
                .get(format!("{window}-used-percent"))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|used| used.is_finite() && used < 100.0)
            {
                continue;
            }
            if let Some(at) = value
                .to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .and_then(|v| v.checked_mul(1000))
            {
                resets.push(at);
            }
        }
    }
    resets.into_iter().filter(|at| *at > now_ms).max()
}

fn millis(time: SystemTime) -> Option<u64> {
    u64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn only_verified_future_advice_changes_cooldown() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            reset_time(
                None,
                Some(&json!({"error":{"resets_at":1_800_000_040}})),
                now,
                None
            ),
            Some(1_800_000_040_000)
        );
        assert_eq!(
            reset_time(
                None,
                Some(&json!({"response":{"error":{"resets_in_seconds":12}}})),
                now,
                None
            ),
            Some(1_800_000_012_000)
        );
        for body in [
            json!({"error":{"message":"Try again in 60s"}}),
            json!({"error":{"resets_at":1}}),
            json!({"input":{"error":{"resets_at":2_000_000_000}}}),
            json!({"error":{"resets_at":u64::MAX}}),
        ] {
            assert_eq!(reset_time(None, Some(&body), now, None), None);
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-codex-primary-reset-at", "1800000008".parse().unwrap());
        headers.insert("x-codex-primary-used-percent", "100".parse().unwrap());
        headers.insert("x-codex-secondary-reset-at", "1900000000".parse().unwrap());
        headers.insert("x-codex-secondary-used-percent", "2".parse().unwrap());
        assert_eq!(
            reset_time(Some(&headers), None, now, None),
            Some(1_800_000_008_000)
        );
    }

    #[test]
    fn stream_status_is_limited_to_failure_envelopes() {
        assert_eq!(
            event_status(&json!({"type":"error","status_code":401})),
            Some(401)
        );
        assert_eq!(
            event_status(
                &json!({"type":"response.failed","response":{"error":{"code":"rate_limit_exceeded"}}})
            ),
            Some(429)
        );
        assert_eq!(
            event_status(
                &json!({"type":"response.output_item.done","item":{"error":{"status":401}}})
            ),
            None
        );
        assert_eq!(
            event_status(
                &json!({"type":"response.failed","response":{"error":{"code":"invalid_prompt","message":"401 and 429"}}})
            ),
            None
        );
    }
}
