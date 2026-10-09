//! Client-facing projection of upstream Responses control data.
//!
//! This is a protocol-position projection, not a text scrubber. Only transport
//! headers and the `error` / `response` envelopes (plus their protocol metadata)
//! are visited. Messages, instructions, tool arguments and output content never
//! become identity fields because of the strings they contain.

use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};

use crate::protocol::ProtocolError;

// Pinned 0.160.0 consumers: codex-api/{sse/responses.rs,rate_limits.rs,
// safety_buffering.rs,endpoint/models.rs}. These are business controls, not
// upstream account, request, trace, routing or sticky identifiers.
fn business_header(name: &str, has_header: impl Fn(&str) -> bool) -> bool {
    matches!(
        name,
        "openai-model"
            | "x-openai-model"
            | "x-reasoning-included"
            | "x-models-etag"
            | "etag"
            | "retry-after"
            | "www-authenticate"
            | "allow"
            | "x-codex-safety-buffering-enabled"
            | "x-codex-safety-buffering-faster-model"
            | "x-codex-credits-has-credits"
            | "x-codex-credits-unlimited"
            | "x-codex-credits-balance"
            | "x-codex-promo-message"
            | "x-codex-rate-limit-reached-type"
    ) || name.strip_prefix("x-").is_some_and(|name| {
        // The official parser discovers metered families by their primary
        // used-percent field; their names are business limit ids. Permit only
        // its exact window/name fields, never the entire family prefix.
        [
            "-primary-used-percent",
            "-primary-window-minutes",
            "-primary-reset-at",
            "-secondary-used-percent",
            "-secondary-window-minutes",
            "-secondary-reset-at",
            "-limit-name",
        ]
        .iter()
        .any(|suffix| {
            name.strip_suffix(suffix).is_some_and(|family| {
                family == "codex"
                    || (!family.is_empty()
                        && has_header(&format!("x-{family}-primary-used-percent")))
            })
        })
    })
}

/// Retains only the pinned client's business response controls. The caller
/// obtains these from the actual account/attempt response; this function never
/// synthesizes a header or carries headers between attempts.
pub fn project_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut projected = HeaderMap::new();
    for (name, value) in headers {
        if business_header(name.as_str(), |discovery| headers.contains_key(discovery)) {
            projected.append(name.clone(), value.clone());
        }
    }
    projected
}

fn model_value(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value),
        // ResponsesStreamEvent::response_model uses only the first entry.
        Value::Array(values) => values.first().and_then(model_value),
        _ => None,
    }
}

fn project_json_headers(value: &mut Value) {
    let mut projected = Map::new();
    if let Some(headers) = value.as_object() {
        for (name, value) in headers {
            let Ok(name_parsed) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            if !business_header(name_parsed.as_str(), |discovery| {
                headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(discovery))
            }) {
                continue;
            }
            let projected_value =
                if matches!(name_parsed.as_str(), "openai-model" | "x-openai-model") {
                    model_value(value).map(|value| Value::String(value.to_owned()))
                } else {
                    match value {
                        Value::String(_) | Value::Number(_) | Value::Bool(_) => Some(value.clone()),
                        _ => None,
                    }
                };
            let Some(projected_value) = projected_value else {
                continue;
            };
            let wire_value = projected_value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| projected_value.to_string());
            if HeaderValue::from_str(&wire_value).is_ok() {
                // Preserve header spelling and scalar types for raw event
                // consumers; the whitelist comparison remains insensitive.
                projected.insert(name.clone(), projected_value);
            }
        }
    }
    *value = Value::Object(projected);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolEnvelope {
    Event,
    Response,
    Error,
}

fn ancillary_identity(name: &str) -> bool {
    matches!(
        name,
        "request_id"
            | "client_request_id"
            | "correlation_id"
            | "trace_id"
            | "span_id"
            | "traceparent"
            | "tracestate"
            | "baggage"
            | "cf_ray"
            | "account_id"
            | "chatgpt_account_id"
            | "organization_id"
            | "user_id"
            | "session_id"
            | "thread_id"
            | "turn_id"
            | "installation_id"
            | "window_id"
            | "context_window_id"
            | "conversation_id"
            | "connection_id"
            | "websocket_id"
            | "websocket_request_id"
            | "route_id"
            | "routing_id"
            | "route_token"
            | "routing_token"
            | "sticky_token"
            | "sticky_key"
            | "sticky_turn_state"
            | "codex_turn_state"
            | "prompt_cache_key"
            | "cache_key"
            | "x-request-id"
            | "x-client-request-id"
            | "cf-ray"
            | "chatgpt-account-id"
            | "x-codex-turn-state"
    )
}

fn strip_ancillary(object: &mut Map<String, Value>) {
    object.retain(|name, _| !ancillary_identity(name));
    if let Some(headers) = object.get_mut("headers") {
        project_json_headers(headers);
    }
}

fn strip_native_references(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        for name in [
            "id",
            "item_id",
            "call_id",
            "response_id",
            "previous_response_id",
        ] {
            object.remove(name);
        }
    }
}

fn project_envelope<E>(
    value: &mut Value,
    kind: ProtocolEnvelope,
    native: &mut impl FnMut(&mut Value, ProtocolEnvelope) -> Result<(), E>,
) -> Result<(), E> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    strip_ancillary(object);
    // Only response.id is a native Responses object id. Event/error ids have
    // no continuation consumer in the pinned client and must not escape raw.
    if kind != ProtocolEnvelope::Response {
        object.remove("id");
    }
    if let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut) {
        strip_ancillary(metadata);
        for name in ["item_id", "call_id", "response_id", "previous_response_id"] {
            metadata.remove(name);
        }
    }
    native(value, kind)?;
    // These are the complete envelope edges. No generic recursion into JSON
    // objects, content, error messages, tool output or arbitrary metadata.
    for (name, child_kind) in [
        ("response", ProtocolEnvelope::Response),
        ("error", ProtocolEnvelope::Error),
    ] {
        if let Some(child) = value.get_mut(name) {
            project_envelope(child, child_kind, native)?;
        }
    }
    Ok(())
}

pub(crate) fn project_event(
    event: &mut Value,
    mut native: impl FnMut(&mut Value, ProtocolEnvelope) -> Result<(), ProtocolError>,
) -> Result<(), ProtocolError> {
    project_envelope(event, ProtocolEnvelope::Event, &mut native)
}

/// HTTP failures do not grant continuation provenance. Remove their native
/// references instead of creating Session aliases from an unsuccessful body.
/// Error code, message, status, plan/reset data and safety details are retained.
pub fn sanitize_http_error(value: &mut Value) {
    let result: Result<(), std::convert::Infallible> =
        project_envelope(value, ProtocolEnvelope::Error, &mut |envelope, kind| {
            strip_native_references(envelope);
            if let Some(item) = envelope.get_mut("item") {
                strip_native_references(item);
            }
            if kind == ProtocolEnvelope::Response
                && let Some(output) = envelope.get_mut("output").and_then(Value::as_array_mut)
            {
                for item in output {
                    strip_native_references(item);
                }
            }
            Ok(())
        });
    match result {
        Ok(()) => {}
        Err(never) => match never {},
    }
}
