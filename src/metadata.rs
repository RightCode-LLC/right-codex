//! Codex a956835d Responses metadata. This classifies a wire request; it does
//! not establish local tool execution, approval, or user-interaction facts.
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::protocol::ProtocolError;

pub const CANONICAL_METADATA: &str = "x-codex-turn-metadata";
pub const LITE_METADATA: &str = "ws_request_header_x_openai_internal_codex_responses_lite";
pub const MAX_METADATA_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Turn,
    Prewarm,
    Compaction,
    Memory,
}
impl RequestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Turn => "turn",
            Self::Prewarm => "prewarm",
            Self::Compaction => "compaction",
            Self::Memory => "memory",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRole {
    Conversation,
    Title,
    Subagent,
    Review,
    GuardianReviewer,
    GuardianClassifier,
    Memory,
    Compact,
}

#[derive(Debug, Clone)]
pub struct ClientMetadata {
    pub kind: RequestKind,
    pub role: TaskRole,
    pub lite: bool,
    /// Client identities remain local, for parent lookup and session selection.
    pub client_thread_id: Option<String>,
    pub client_turn_id: Option<String>,
    pub client_parent_thread_id: Option<String>,
    pub client_parent_response_id: Option<String>,
    pub client_window_id: Option<String>,
    semantic: Map<String, Value>,
    subagent: Option<String>,
    guardian: Option<String>,
    guardian_credits_requested: bool,
    native_memgen_request: bool,
}

/// Supplied only after the session owner proves the parent in the same account
/// and authentication revision. Client headers alone must never create it.
#[derive(Debug, Clone)]
pub struct ParentMetadataProof {
    pub account_id: String,
    pub auth_revision: String,
    pub thread_id: String,
    pub turn_id: Option<String>,
    pub root_turn_id: Option<String>,
    pub response_id: Option<String>,
    // Hashes of actual delivered collaboration messages; never general cipher authority.
    pub(crate) agent_message_cipher_sha256: std::collections::BTreeSet<String>,
}
pub struct MetadataScope<'a> {
    pub account_id: &'a str,
    pub auth_revision: &'a str,
    pub installation_id: &'a str,
    pub session_id: &'a str,
    pub thread_id: &'a str,
    pub turn_id: &'a str,
    pub window_id: &'a str,
    pub context_window_id: &'a str,
    pub window_number: u64,
    pub turn_started_at_unix_ms: u64,
    pub parent: Option<&'a ParentMetadataProof>,
}
pub struct MetadataProjection {
    pub kind: RequestKind,
    pub role: TaskRole,
    pub client_metadata: Value,
    /// Only gateway-owned compatible headers, never arbitrary client headers.
    pub headers: HeaderMap,
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn optional_string(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<String>, ProtocolError> {
    value
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .filter(|s| bounded(s))
                .map(str::to_owned)
                .ok_or(ProtocolError::Invalid(field))
        })
        .transpose()
}
fn optional_turn_id(
    value: Option<&Value>,
    kind: RequestKind,
) -> Result<Option<String>, ProtocolError> {
    // The official startup prewarm uses INITIAL_SUBMIT_ID = "". It is a
    // connection setup marker, never a client logical-turn deduplication key.
    if kind == RequestKind::Prewarm && value.and_then(Value::as_str) == Some("") {
        return Ok(Some(String::new()));
    }
    optional_string(value, "turn_id")
}
fn header(headers: &HeaderMap, name: &'static str) -> Result<Option<String>, ProtocolError> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.len() > 1 {
        return Err(ProtocolError::Invalid("metadata.duplicate_header"));
    }
    values
        .first()
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| ProtocolError::Invalid("metadata.header"))
        })
        .transpose()
}
fn parse_canonical(raw: &str) -> Result<Map<String, Value>, ProtocolError> {
    if raw.len() > MAX_METADATA_BYTES {
        return Err(ProtocolError::Capacity("metadata"));
    }
    serde_json::from_str::<Value>(raw)
        .map_err(|_| ProtocolError::Invalid("metadata.canonical"))?
        .as_object()
        .cloned()
        .ok_or(ProtocolError::Invalid("metadata.canonical"))
}
fn agree(a: Option<&str>, b: Option<&str>) -> Result<(), ProtocolError> {
    if a.zip(b).is_some_and(|(a, b)| a != b) {
        return Err(ProtocolError::Invalid("metadata.projection_mismatch"));
    }
    Ok(())
}

fn websocket_handshake(headers: &HeaderMap) -> Result<bool, ProtocolError> {
    Ok(header(headers, "upgrade")?.is_some_and(|value| value.eq_ignore_ascii_case("websocket")))
}

fn canonical_headers_agree(
    canonical: &Map<String, Value>,
    flat: &Map<String, Value>,
    compatible: &Map<String, Value>,
    websocket: bool,
) -> Result<(), ProtocolError> {
    if websocket {
        // core/client.rs:1300-1315 builds these headers when the socket is
        // opened; 1580-1611 reuses the connection for subsequent requests.
        // Turn/window/compaction and tool snapshots in that header are stale
        // by design. Each frame's canonical body remains authoritative.
        for (name, flat_name) in [
            ("installation_id", "x-codex-installation-id"),
            ("session_id", "session_id"),
            ("thread_id", "thread_id"),
        ] {
            if canonical
                .get(name)
                .or_else(|| flat.get(flat_name))
                .zip(compatible.get(name))
                .is_some_and(|(current, handshake)| current != handshake)
            {
                return Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"));
            }
        }
    } else {
        let mut expected = canonical.clone();
        expected.remove("tool_namespaces_info");
        if compatible != &expected {
            return Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"));
        }
    }
    Ok(())
}

/// The standalone Search tool uses its full per-call canonical metadata only
/// in a header (ext/web-search/src/tool.rs:120-149,195-206). SearchRequest has
/// no client_metadata field. This local scope material is never an outbound
/// Search body and must not be used for Responses or image requests.
pub fn search_scope_material(
    body: &Value,
    headers: &HeaderMap,
) -> Result<(Value, HeaderMap), ProtocolError> {
    if body.get("client_metadata").is_some() {
        return Err(ProtocolError::Invalid("search.client_metadata"));
    }
    let Some(raw) = header(headers, CANONICAL_METADATA)? else {
        return Ok((body.clone(), headers.clone()));
    };
    parse_canonical(&raw)?;
    let mut local_headers = headers.clone();
    // Search sends the full canonical value, not the Responses compatibility
    // header projection. Its source is validated as canonical body locally.
    local_headers.remove(CANONICAL_METADATA);
    Ok((
        json!({"client_metadata": {CANONICAL_METADATA: raw}}),
        local_headers,
    ))
}

/// core/responses_metadata.rs:224 canonical body is authoritative; header
/// compatibility output legitimately omits tool_namespaces_info (377-391).
pub fn classify_request(
    body: &Value,
    headers: &HeaderMap,
) -> Result<ClientMetadata, ProtocolError> {
    let flat = body
        .get("client_metadata")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_object()
                .ok_or(ProtocolError::Invalid("client_metadata"))
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();
    if serde_json::to_vec(&flat).map_or(true, |v| v.len() > MAX_METADATA_BYTES) {
        return Err(ProtocolError::Capacity("metadata"));
    }
    if flat.values().any(|v| !v.is_string()) {
        return Err(ProtocolError::Invalid("client_metadata.value"));
    }
    let raw = flat.get(CANONICAL_METADATA).and_then(Value::as_str);
    let compatible = header(headers, CANONICAL_METADATA)?;
    let canonical = raw
        .map(parse_canonical)
        .transpose()?
        .unwrap_or_else(Map::new);
    let kind = match canonical.get("request_kind").and_then(Value::as_str) {
        None | Some("turn") => RequestKind::Turn,
        Some("prewarm") => RequestKind::Prewarm,
        Some("compaction") => RequestKind::Compaction,
        Some("memory") => RequestKind::Memory,
        _ => return Err(ProtocolError::Invalid("metadata.request_kind")),
    };
    if canonical.contains_key("request_kind") && !canonical["request_kind"].is_string() {
        return Err(ProtocolError::Invalid("metadata.request_kind"));
    }
    let websocket = websocket_handshake(headers)?;
    if let (Some(_), Some(compatible)) = (raw, compatible.as_deref()) {
        canonical_headers_agree(&canonical, &flat, &parse_canonical(compatible)?, websocket)?;
    } else if raw.is_none() && compatible.is_some() {
        return Err(ProtocolError::Invalid("metadata.canonical_body_missing"));
    }
    let field = |name: &'static str| {
        if name == "turn_id" {
            optional_turn_id(canonical.get(name), kind)
        } else {
            optional_string(canonical.get(name), name)
        }
    };
    let flat_field = |name: &'static str| {
        if name == "turn_id" {
            optional_turn_id(flat.get(name), kind)
        } else {
            optional_string(flat.get(name), name)
        }
    };
    let client_thread_id = field("thread_id")?.or(flat_field("thread_id")?);
    let client_turn_id = field("turn_id")?
        .or(flat_field("turn_id")?)
        .filter(|value| !value.is_empty());
    for name in ["thread_id", "turn_id", "session_id"] {
        agree(field(name)?.as_deref(), flat_field(name)?.as_deref())?;
    }
    let client_window_id = field("window_id")?.or(flat_field("x-codex-window-id")?);
    agree(
        field("window_id")?.as_deref(),
        flat_field("x-codex-window-id")?.as_deref(),
    )?;
    let window_header = header(headers, "x-codex-window-id")?;
    if !websocket {
        agree(client_window_id.as_deref(), window_header.as_deref())?;
    }
    let client_parent_thread_id =
        field("parent_thread_id")?.or(flat_field("x-codex-parent-thread-id")?);
    agree(
        field("parent_thread_id")?.as_deref(),
        flat_field("x-codex-parent-thread-id")?.as_deref(),
    )?;
    agree(
        client_parent_thread_id.as_deref(),
        header(headers, "x-codex-parent-thread-id")?.as_deref(),
    )?;
    let subagent = flat_field("x-openai-subagent")?.or(header(headers, "x-openai-subagent")?);
    agree(
        flat_field("x-openai-subagent")?.as_deref(),
        header(headers, "x-openai-subagent")?.as_deref(),
    )?;
    let guardian = header(headers, "x-codex-guardian")?;
    if guardian
        .as_deref()
        .is_some_and(|v| !["reviewer", "classifier"].contains(&v))
    {
        return Err(ProtocolError::Invalid("metadata.guardian"));
    }
    let has_trigger = body["input"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v["type"] == "compaction_trigger"));
    if has_trigger && raw.is_some() && kind != RequestKind::Compaction {
        return Err(ProtocolError::Invalid("metadata.compaction_trigger"));
    }
    let kind = if has_trigger {
        RequestKind::Compaction
    } else {
        kind
    };
    let source = field("thread_source")?;
    let role = match (
        guardian.as_deref(),
        subagent.as_deref(),
        source.as_deref(),
        kind,
    ) {
        (Some("reviewer"), _, _, _) => TaskRole::GuardianReviewer,
        (Some("classifier"), _, _, _) => TaskRole::GuardianClassifier,
        (_, Some("review"), _, _) => TaskRole::Review,
        (_, Some("compact"), _, _) => TaskRole::Compact,
        (_, Some("memory_consolidation"), _, _) | (_, _, _, RequestKind::Memory) => {
            TaskRole::Memory
        }
        (_, _, Some("thread_title"), _) => TaskRole::Title,
        (_, Some(_), _, _) => TaskRole::Subagent,
        _ => TaskRole::Conversation,
    };
    let mut semantic = Map::new();
    for name in [
        "request_kind",
        "compaction",
        "subagent_kind",
        "thread_source",
        "turn_trigger",
        "sandbox",
        "sandbox_mode",
        "auto_review_enabled",
        "node_repl_auto_review_required",
        "node_repl_disabled",
        "history_ingest_requested",
        "analytics_enabled",
        "tool_namespaces_info",
    ] {
        if let Some(v) = canonical.get(name).filter(|v| !v.is_null()) {
            semantic.insert(name.to_owned(), v.clone());
        }
    }
    for name in [
        "thread_source",
        "subagent_kind",
        "turn_trigger",
        "sandbox",
        "sandbox_mode",
    ] {
        optional_string(semantic.get(name), "metadata.semantic_string")?;
    }
    for name in [
        "auto_review_enabled",
        "node_repl_auto_review_required",
        "node_repl_disabled",
        "history_ingest_requested",
        "analytics_enabled",
    ] {
        if semantic.get(name).is_some_and(|v| !v.is_boolean()) {
            return Err(ProtocolError::Invalid("metadata.semantic_bool"));
        }
    }
    if let Some(v) = semantic.get("compaction") {
        let o = v
            .as_object()
            .ok_or(ProtocolError::Invalid("metadata.compaction"))?;
        for (key, values) in [
            ("trigger", &["manual", "auto"][..]),
            (
                "reason",
                &[
                    "user_requested",
                    "context_limit",
                    "model_downshift",
                    "comp_hash_changed",
                ][..],
            ),
            (
                "implementation",
                &["responses", "responses_compaction_v2"][..],
            ),
            (
                "phase",
                &["standalone_turn", "pre_turn", "mid_turn", "post_turn"][..],
            ),
            ("strategy", &["memento", "prefix_compaction"][..]),
        ] {
            if !o
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| values.contains(&s))
            {
                return Err(ProtocolError::Invalid("metadata.compaction"));
            }
        }
        if o.len() != 5 || kind != RequestKind::Compaction {
            return Err(ProtocolError::Invalid("metadata.compaction"));
        }
    }
    let lite_flat = flat_field(LITE_METADATA)?;
    let lite_header = header(headers, "x-openai-internal-codex-responses-lite")?;
    agree(lite_flat.as_deref(), lite_header.as_deref())?;
    let lite = match lite_flat.as_deref().or(lite_header.as_deref()) {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(ProtocolError::Invalid("metadata.responses_lite")),
    };
    let guardian_credits_requested = match flat
        .get("guardian_credits_requested")
        .and_then(Value::as_str)
    {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(ProtocolError::Invalid("metadata.guardian_credits")),
    };
    // In fixed core/client.rs the header follows the actual session source,
    // not request_kind=memory. Detached phase-1 uses an interactive root
    // source, while the phase-2 agent uses Internal(MemoryConsolidation).
    // Do not manufacture the header for detached extraction or forward an
    // arbitrary client value. Both Internal and SubAgent(MemoryConsolidation)
    // have the same subagent label, but only Internal receives this header in
    // native Codex; the received exact header is therefore part of the proof.
    let native_memgen_request = match header(headers, "x-openai-memgen-request")?.as_deref() {
        None => false,
        Some("true")
            if kind != RequestKind::Memory
                && source.as_deref() == Some("memory_consolidation")
                && subagent.as_deref() == Some("memory_consolidation")
                && guardian.is_none()
                && role == TaskRole::Memory =>
        {
            true
        }
        _ => return Err(ProtocolError::Invalid("metadata.memgen_header")),
    };
    Ok(ClientMetadata {
        kind,
        role,
        lite,
        client_thread_id,
        client_turn_id,
        client_parent_thread_id,
        client_parent_response_id: flat_field("parent_response_id")?,
        client_window_id,
        semantic,
        subagent,
        guardian,
        guardian_credits_requested,
        native_memgen_request,
    })
}

/// Rejected ingress diagnostics contain only fixed field names and shape
/// facts. No header values, client identifiers, workspace paths or text leave
/// this helper, including when canonical parsing fails.
pub fn diagnostic_shape(body: &Value, headers: &HeaderMap) -> Value {
    let raw = body["client_metadata"][CANONICAL_METADATA].as_str();
    let body_metadata = raw.and_then(|value| parse_canonical(value).ok());
    let header_raw = header(headers, CANONICAL_METADATA).ok().flatten();
    let header_metadata = header_raw
        .as_deref()
        .and_then(|value| parse_canonical(value).ok());
    let known_fields = [
        "installation_id",
        "session_id",
        "thread_id",
        "turn_id",
        "window_id",
        "window_number",
        "context_window_id",
        "request_kind",
        "compaction",
        "parent_thread_id",
        "parent_turn_id",
        "root_turn_id",
        "thread_source",
        "tool_namespaces_info",
        "turn_started_at_unix_ms",
        "workspaces",
        "analytics_enabled",
    ];
    let different_fields: Vec<_> = known_fields
        .into_iter()
        .filter(|name| {
            body_metadata.as_ref().and_then(|value| value.get(*name))
                != header_metadata.as_ref().and_then(|value| value.get(*name))
        })
        .collect();
    let turn = body_metadata
        .as_ref()
        .and_then(|value| value.get("turn_id"));
    let kind = body_metadata
        .as_ref()
        .and_then(|value| value.get("request_kind"))
        .and_then(Value::as_str)
        .filter(|value| ["turn", "prewarm", "compaction", "memory"].contains(value));
    json!({
        "websocket_handshake": websocket_handshake(headers).ok(),
        "canonical_body_present": raw.is_some(),
        "canonical_body_valid": body_metadata.is_some(),
        "canonical_header_present": header_raw.is_some(),
        "canonical_header_valid": header_metadata.is_some(),
        "canonical_body_field_count": body_metadata.as_ref().map(Map::len),
        "canonical_header_field_count": header_metadata.as_ref().map(Map::len),
        "different_fields": different_fields,
        "request_kind": kind,
        "turn_present": turn.is_some(),
        "turn_is_string": turn.is_some_and(Value::is_string),
        "turn_is_empty": turn.and_then(Value::as_str).is_some_and(str::is_empty),
        "turn_is_uuid": turn.and_then(Value::as_str).is_some_and(|value| uuid::Uuid::parse_str(value).is_ok()),
    })
}

pub fn project(
    client: &ClientMetadata,
    scope: &MetadataScope<'_>,
) -> Result<MetadataProjection, ProtocolError> {
    for value in [
        scope.account_id,
        scope.auth_revision,
        scope.installation_id,
        scope.session_id,
        scope.thread_id,
        scope.turn_id,
        scope.window_id,
        scope.context_window_id,
    ] {
        if !bounded(value) {
            return Err(ProtocolError::Invalid("metadata.gateway_scope"));
        }
    }
    let mut canonical = client.semantic.clone();
    canonical.insert("request_kind".into(), json!(client.kind.as_str()));
    canonical.insert("turn_id".into(), json!(scope.turn_id));
    canonical.insert(
        "turn_started_at_unix_ms".into(),
        json!(scope.turn_started_at_unix_ms),
    );
    if client.kind != RequestKind::Memory {
        for (name, value) in [
            ("installation_id", scope.installation_id),
            ("session_id", scope.session_id),
            ("thread_id", scope.thread_id),
            ("window_id", scope.window_id),
            ("context_window_id", scope.context_window_id),
        ] {
            canonical.insert(name.into(), json!(value));
        }
        canonical.insert("window_number".into(), json!(scope.window_number));
    }
    let mut flat = Map::from_iter([
        (
            "x-codex-installation-id".into(),
            json!(scope.installation_id),
        ),
        ("session_id".into(), json!(scope.session_id)),
        ("thread_id".into(), json!(scope.thread_id)),
        ("x-codex-window-id".into(), json!(scope.window_id)),
        ("turn_id".into(), json!(scope.turn_id)),
    ]);
    let mut headers = HeaderMap::new();
    let insert =
        |h: &mut HeaderMap, name: &'static str, value: &str| -> Result<(), ProtocolError> {
            h.insert(
                name,
                HeaderValue::from_str(value)
                    .map_err(|_| ProtocolError::Invalid("metadata.header_projection"))?,
            );
            Ok(())
        };
    insert(&mut headers, "x-codex-window-id", scope.window_id)?;
    if let Some(parent) = scope.parent {
        if parent.account_id != scope.account_id
            || parent.auth_revision != scope.auth_revision
            || !bounded(&parent.thread_id)
        {
            return Err(ProtocolError::Invalid("metadata.foreign_parent"));
        }
        canonical.insert("parent_thread_id".into(), json!(parent.thread_id));
        flat.insert("x-codex-parent-thread-id".into(), json!(parent.thread_id));
        insert(&mut headers, "x-codex-parent-thread-id", &parent.thread_id)?;
        for (key, value) in [
            ("parent_turn_id", &parent.turn_id),
            ("root_turn_id", &parent.root_turn_id),
        ] {
            if let Some(v) = value {
                if !bounded(v) {
                    return Err(ProtocolError::Invalid("metadata.parent"));
                }
                canonical.insert(key.into(), json!(v));
                flat.insert(key.into(), json!(v));
            }
        }
        if client.role == TaskRole::GuardianReviewer
            && let Some(response) = &parent.response_id
        {
            if !bounded(response) {
                return Err(ProtocolError::Invalid("metadata.parent_response"));
            }
            flat.insert("parent_response_id".into(), json!(response));
        }
    }
    if let Some(v) = &client.subagent {
        flat.insert("x-openai-subagent".into(), json!(v));
        insert(&mut headers, "x-openai-subagent", v)?;
    }
    if let Some(v) = &client.guardian {
        insert(&mut headers, "x-codex-guardian", v)?;
    }
    if client.native_memgen_request {
        insert(&mut headers, "x-openai-memgen-request", "true")?;
    }
    if client.lite {
        flat.insert(LITE_METADATA.into(), json!("true"));
        insert(
            &mut headers,
            "x-openai-internal-codex-responses-lite",
            "true",
        )?;
    }
    if client.guardian_credits_requested && client.role != TaskRole::GuardianReviewer {
        flat.insert("guardian_credits_requested".into(), json!("true"));
    }
    flat.insert(
        CANONICAL_METADATA.into(),
        json!(
            serde_json::to_string(&canonical)
                .map_err(|_| ProtocolError::Invalid("metadata.serialization"))?
        ),
    );
    canonical.remove("tool_namespaces_info");
    // Official compatibility headers are ASCII JSON; escaping non-ASCII keeps
    // this projection legal without changing the canonical body value.
    let compatibility = ascii_json(
        &serde_json::to_string(&canonical)
            .map_err(|_| ProtocolError::Invalid("metadata.serialization"))?,
    );
    insert(&mut headers, CANONICAL_METADATA, &compatibility)?;
    Ok(MetadataProjection {
        kind: client.kind,
        role: client.role.clone(),
        client_metadata: Value::Object(flat),
        headers,
    })
}

fn ascii_json(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}
