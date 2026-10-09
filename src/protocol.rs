//! HTTP request projection pinned to Codex 0.160.0, a956835d.
//! Wire shapes: codex-api/src/common.rs and protocol/src/models.rs.
//! This module never turns client metadata or tool output into execution facts.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Identity namespaces are independent even when a client reuses the same
/// label for an item, call and file. Free JSON never enters this map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityKind {
    Item,
    Call,
    File,
    Response,
}
pub type IdentifierMap = BTreeMap<(IdentityKind, String), String>;

/// Fixed protocol/models.rs::ResponseItem::id_prefix. Local declarations are
/// separated by item type so one client string cannot force an API ID prefix.
pub(crate) fn item_id_prefix(kind: &str) -> Option<&'static str> {
    match kind {
        "additional_tools" => Some("at"),
        "message" => Some("msg"),
        "agent_message" => Some("amsg"),
        "reasoning" => Some("rs"),
        "local_shell_call" => Some("lsh"),
        "function_call" => Some("fc"),
        "tool_search_call" => Some("tsc"),
        "function_call_output" => Some("fco"),
        "custom_tool_call" => Some("ctc"),
        "custom_tool_call_output" => Some("ctco"),
        "tool_search_output" => Some("tso"),
        "web_search_call" => Some("ws"),
        "image_generation_call" => Some("ig"),
        "compaction" | "context_compaction" => Some("cmp"),
        _ => None,
    }
}
pub(crate) fn item_identity_key(kind: &str, local: &str) -> String {
    format!("{kind}:{:x}", Sha256::digest(local.as_bytes()))
}

/// All values are supplied by the account-generation-scoped session owner.
/// `verified_opaque` contains exact ciphertext previously received in that same
/// gateway conversation and account generation. An empty set trusts nothing.
pub struct RequestContext<'a> {
    pub gateway_thread_id: &'a str,
    pub gateway_turn_id: &'a str,
    pub cache_key: &'a str,
    pub identifiers: &'a IdentifierMap,
    pub verified_opaque: &'a BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Unsupported(String),
    Invalid(&'static str),
    UnmappedIdentity(&'static str),
    UnverifiedOpaque(&'static str),
    Capacity(&'static str),
}
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(field) => write!(f, "unsupported_field:{field}"),
            Self::Invalid(field) => write!(f, "invalid_field:{field}"),
            Self::UnmappedIdentity(field) => write!(f, "unmapped_identity:{field}"),
            Self::UnverifiedOpaque(field) => write!(f, "unverified_opaque:{field}"),
            Self::Capacity(field) => write!(f, "capacity_exceeded:{field}"),
        }
    }
}
impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone)]
pub struct BuiltRequest {
    pub body: Value,
    pub is_compaction: bool,
}
type Result<T> = std::result::Result<T, ProtocolError>;

const SEMANTIC: &[&str] = &[
    "model",
    "instructions",
    "input",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "reasoning",
    "text",
    "service_tier",
    "include",
    "stream_options",
    "stream",
    "store",
    "access_programs",
    "generate",
];
const CLIENT_ONLY: &[&str] = &[
    "client_metadata",
    "metadata",
    "prompt_cache_key",
    "previous_response_id",
    "conversation",
    "id",
    "response_id",
    "thread_id",
    "session_id",
    "turn_id",
    "user",
    "safety_identifier",
    "trace_id",
    "traceparent",
    "tracestate",
];

fn object<'a>(v: &'a Value, field: &'static str) -> Result<&'a Map<String, Value>> {
    v.as_object().ok_or(ProtocolError::Invalid(field))
}
fn string<'a>(v: &'a Value, field: &'static str) -> Result<&'a str> {
    v.as_str().ok_or(ProtocolError::Invalid(field))
}
fn keys(v: &Map<String, Value>, allowed: &[&str], field: &'static str) -> Result<()> {
    if let Some(key) = v.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(ProtocolError::Unsupported(format!("{field}.{key}")));
    }
    Ok(())
}
fn enum_string(v: &Value, allowed: &[&str], field: &'static str) -> Result<()> {
    if allowed.contains(&string(v, field)?) {
        Ok(())
    } else {
        Err(ProtocolError::Invalid(field))
    }
}
fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn mapped(
    v: &Value,
    kind: IdentityKind,
    field: &'static str,
    ctx: &RequestContext<'_>,
) -> Result<Value> {
    let original = string(v, field)?;
    let replacement = ctx
        .identifiers
        .get(&(kind, original.to_owned()))
        .filter(|s| identity(s) && s.as_str() != original)
        .ok_or(ProtocolError::UnmappedIdentity(field))?;
    Ok(Value::String(replacement.clone()))
}
fn opaque(v: &Value, field: &'static str, ctx: &RequestContext<'_>) -> Result<Value> {
    let value = string(v, field)?;
    if value.is_empty() || !ctx.verified_opaque.contains(value) {
        return Err(ProtocolError::UnverifiedOpaque(field));
    }
    Ok(v.clone())
}

/// A full input is required. A previous-response delta cannot be made into a
/// full request merely by deleting its reference. Session replay is a caller's
/// separate responsibility before invoking this function.
pub fn build_request(input: Value, ctx: &RequestContext<'_>) -> Result<BuiltRequest> {
    build_request_with_agent_messages(input, ctx, &BTreeSet::new())
}

/// Parent evidence is confined to AgentMessage content. It never authorizes
/// reasoning, compaction, function arguments or tool-output ciphertext.
pub(crate) fn build_request_with_agent_messages(
    input: Value,
    ctx: &RequestContext<'_>,
    parent_agent_cipher_sha256: &BTreeSet<String>,
) -> Result<BuiltRequest> {
    if !identity(ctx.gateway_thread_id)
        || !identity(ctx.gateway_turn_id)
        || !identity(ctx.cache_key)
    {
        return Err(ProtocolError::Invalid("gateway_context"));
    }
    let src = object(&input, "request")?;
    for key in src.keys() {
        if !SEMANTIC.contains(&key.as_str()) && !CLIENT_ONLY.contains(&key.as_str()) {
            return Err(ProtocolError::Unsupported(key.clone()));
        }
    }
    for field in ["previous_response_id", "conversation"] {
        if src.get(field).is_some_and(|v| !v.is_null() && v != "") {
            return Err(ProtocolError::Unsupported(field.into()));
        }
    }
    if let Some(stream) = src.get("stream") {
        if stream == false {
            return Err(ProtocolError::Unsupported("stream=false".into()));
        }
        if stream != true {
            return Err(ProtocolError::Invalid("stream"));
        }
    }
    if src.get("store").is_some_and(|v| !v.is_boolean()) {
        return Err(ProtocolError::Invalid("store"));
    }
    let model = string(
        src.get("model").ok_or(ProtocolError::Invalid("model"))?,
        "model",
    )?;
    if !identity(model) {
        return Err(ProtocolError::Invalid("model"));
    }
    let raw_items = src
        .get("input")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::Invalid("input"))?;
    let mut items = Vec::with_capacity(raw_items.len());
    let mut compact_count = 0;
    for (index, item) in raw_items.iter().enumerate() {
        let item = project_item(item, ctx, parent_agent_cipher_sha256)?;
        if item["type"] == "compaction_trigger" {
            compact_count += 1;
            if index + 1 != raw_items.len() || compact_count != 1 {
                return Err(ProtocolError::Invalid("input.compaction_trigger"));
            }
        }
        items.push(item);
    }
    let mut out = Map::new();
    out.insert("model".into(), json!(model));
    out.insert("input".into(), Value::Array(items));
    for (key, value) in src {
        if !SEMANTIC.contains(&key.as_str())
            || ["model", "input", "store", "stream"].contains(&key.as_str())
        {
            continue;
        }
        validate_semantic(key, value)?;
        if !value.is_null() {
            out.insert(key.clone(), value.clone());
        }
    }
    if out.contains_key("stream_options")
        && !out.get("reasoning").is_some_and(|r| {
            r.get("summary")
                .is_some_and(|s| !s.is_null() && s != "none")
        })
    {
        return Err(ProtocolError::Invalid("stream_options.reasoning_summary"));
    }
    out.entry("tool_choice").or_insert(json!("auto"));
    out.entry("parallel_tool_calls").or_insert(json!(true));
    out.entry("reasoning").or_insert(Value::Null);
    out.entry("include")
        .or_insert(json!(["reasoning.encrypted_content"]));
    out.insert("stream".into(), json!(true));
    out.insert("store".into(), json!(false));
    out.insert("prompt_cache_key".into(), json!(ctx.cache_key));
    out.insert(
        "client_metadata".into(),
        json!({"thread_id":ctx.gateway_thread_id,"turn_id":ctx.gateway_turn_id}),
    );
    Ok(BuiltRequest {
        body: Value::Object(out),
        is_compaction: compact_count == 1,
    })
}

fn validate_semantic(key: &str, v: &Value) -> Result<()> {
    match key {
        "instructions" => {
            string(v, "instructions")?;
        }
        "parallel_tool_calls" => {
            if !v.is_boolean() {
                return Err(ProtocolError::Invalid("parallel_tool_calls"));
            }
        }
        "generate" => {
            if !v.is_boolean() {
                return Err(ProtocolError::Invalid("generate"));
            }
        }
        "access_programs" => {
            if !v.is_null() {
                let o = object(v, "access_programs")?;
                keys(o, &["cyber"], "access_programs")?;
                if o.get("cyber").is_some_and(|v| v != "standard") {
                    return Err(ProtocolError::Unsupported("access_programs.cyber".into()));
                }
            }
        }
        "tool_choice" => enum_string(v, &["auto", "none", "required"], "tool_choice")?,
        "service_tier" => {
            if !v.is_null() && !identity(string(v, "service_tier")?) {
                return Err(ProtocolError::Invalid("service_tier"));
            }
        }
        "tools" => {
            if !v.is_null() {
                validate_tools(v)?;
            }
        }
        "reasoning" => {
            if !v.is_null() {
                let o = object(v, "reasoning")?;
                keys(o, &["effort", "summary", "context"], "reasoning")?;
                if let Some(effort) = o.get("effort").filter(|v| !v.is_null())
                    && !(effort.as_u64().is_some() || effort.as_str().is_some_and(identity))
                {
                    return Err(ProtocolError::Invalid("reasoning.effort"));
                }
                if let Some(summary) = o.get("summary").filter(|v| !v.is_null()) {
                    enum_string(
                        summary,
                        &["auto", "concise", "detailed", "none"],
                        "reasoning.summary",
                    )?;
                }
                if let Some(context) = o.get("context").filter(|v| !v.is_null()) {
                    enum_string(
                        context,
                        &["auto", "current_turn", "all_turns"],
                        "reasoning.context",
                    )?;
                }
            }
        }
        "text" => {
            if !v.is_null() {
                let o = object(v, "text")?;
                keys(o, &["verbosity", "format"], "text")?;
                if let Some(verbosity) = o.get("verbosity").filter(|v| !v.is_null()) {
                    enum_string(verbosity, &["low", "medium", "high"], "text.verbosity")?;
                }
                if let Some(format) = o.get("format").filter(|v| !v.is_null()) {
                    let f = object(format, "text.format")?;
                    keys(f, &["type", "strict", "schema", "name"], "text.format")?;
                    enum_string(
                        f.get("type").unwrap_or(&Value::Null),
                        &["json_schema"],
                        "text.format.type",
                    )?;
                    if !f.get("strict").is_some_and(Value::is_boolean)
                        || !f
                            .get("schema")
                            .is_some_and(|s| s.is_object() || s.is_boolean())
                        || !f.get("name").is_some_and(Value::is_string)
                    {
                        return Err(ProtocolError::Invalid("text.format"));
                    }
                }
            }
        }
        "include" => {
            if !v
                .as_array()
                .is_some_and(|a| a.iter().all(|s| s == "reasoning.encrypted_content"))
            {
                return Err(ProtocolError::Unsupported("include".into()));
            }
        }
        "stream_options" => {
            if !v.is_null() {
                let o = object(v, "stream_options")?;
                keys(o, &["reasoning_summary_delivery"], "stream_options")?;
                enum_string(
                    o.get("reasoning_summary_delivery").unwrap_or(&Value::Null),
                    &["sequential_cutoff"],
                    "stream_options.reasoning_summary_delivery",
                )?;
            }
        }
        _ => return Err(ProtocolError::Unsupported(key.into())),
    }
    Ok(())
}

fn validate_tools(v: &Value) -> Result<()> {
    for tool in v.as_array().ok_or(ProtocolError::Invalid("tools"))? {
        let tool = object(tool, "tools.item")?;
        let kind = tool
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::Invalid("tools.type"))?;
        if ![
            "function",
            "custom",
            "namespace",
            "web_search",
            "web_search_preview",
            "tool_search",
        ]
        .contains(&kind)
        {
            return Err(ProtocolError::Unsupported(format!("tools.type:{kind}")));
        }
        keys(
            tool,
            match kind {
                "function" => &[
                    "type",
                    "name",
                    "description",
                    "strict",
                    "defer_loading",
                    "parameters",
                ],
                "custom" => &["type", "name", "description", "defer_loading", "format"],
                "namespace" => &["type", "name", "description", "tools"],
                "tool_search" => &["type", "execution", "description", "parameters"],
                "web_search" | "web_search_preview" => &[
                    "type",
                    "external_web_access",
                    "indexed_web_access",
                    "filters",
                    "user_location",
                    "search_context_size",
                    "search_content_types",
                ],
                _ => unreachable!(),
            },
            "tools.item",
        )?;
        for name in ["name", "description", "execution"] {
            if let Some(v) = tool.get(name) {
                string(v, "tools.string")?;
            }
        }
        for name in [
            "strict",
            "defer_loading",
            "external_web_access",
            "indexed_web_access",
        ] {
            if tool
                .get(name)
                .filter(|v| !v.is_null())
                .is_some_and(|v| !v.is_boolean())
            {
                return Err(ProtocolError::Invalid("tools.boolean"));
            }
        }
        if ["function", "custom", "namespace"].contains(&kind)
            && !tool
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(identity)
        {
            return Err(ProtocolError::Invalid("tools.name"));
        }
        if let Some(format) = tool.get("format").filter(|v| !v.is_null()) {
            let format = object(format, "tools.format")?;
            keys(format, &["type", "syntax", "definition"], "tools.format")?;
            for name in ["type", "syntax", "definition"] {
                string(format.get(name).unwrap_or(&Value::Null), "tools.format")?;
            }
        }
        if let Some(filters) = tool.get("filters").filter(|v| !v.is_null()) {
            let filters = object(filters, "tools.filters")?;
            keys(filters, &["allowed_domains"], "tools.filters")?;
            if filters
                .get("allowed_domains")
                .filter(|v| !v.is_null())
                .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(Value::is_string)))
            {
                return Err(ProtocolError::Invalid("tools.filters"));
            }
        }
        if let Some(location) = tool.get("user_location").filter(|v| !v.is_null()) {
            let location = object(location, "tools.user_location")?;
            keys(
                location,
                &["type", "country", "region", "city", "timezone"],
                "tools.user_location",
            )?;
            for value in location.values().filter(|v| !v.is_null()) {
                string(value, "tools.user_location")?;
            }
        }
        if tool
            .get("search_content_types")
            .filter(|v| !v.is_null())
            .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(Value::is_string)))
        {
            return Err(ProtocolError::Invalid("tools.search_content_types"));
        }
        // Parameters, schemas and custom grammar are semantic free JSON. Do
        // not recursively remove fields named id or encrypted_content there.
        if kind == "namespace" {
            validate_tools(
                tool.get("tools")
                    .ok_or(ProtocolError::Invalid("tools.namespace"))?,
            )?;
            if tool["tools"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|t| !matches!(t["type"].as_str(), Some("function" | "custom")))
            }) {
                return Err(ProtocolError::Invalid("tools.namespace_kind"));
            }
        }
    }
    Ok(())
}

fn project_item(
    v: &Value,
    ctx: &RequestContext<'_>,
    parent_agent_cipher_sha256: &BTreeSet<String>,
) -> Result<Value> {
    let o = object(v, "input.item")?;
    let kind = match o.get("type") {
        Some(value) => string(value, "input.type")?,
        None => "message",
    };
    let semantic: &[&str] = match kind {
        "message" => &["role", "content", "phase"],
        "agent_message" => &["author", "recipient", "content"],
        "local_shell_call" => &["status", "action"],
        "additional_tools" => &["role", "tools"],
        "reasoning" => &["summary", "content"],
        "function_call" => &["name", "namespace", "arguments"],
        "custom_tool_call" => &["name", "namespace", "input", "status"],
        "function_call_output" | "custom_tool_call_output" => &["name", "namespace", "output"],
        "tool_search_call" => &["status", "execution", "arguments"],
        "tool_search_output" => &["status", "execution", "tools"],
        "web_search_call" => &["status", "action"],
        "image_generation_call" => &["status", "revised_prompt", "result"],
        "compaction" | "context_compaction" => &[],
        "compaction_trigger" => &[],
        "configuration_update" => &["reasoning"],
        _ => return Err(ProtocolError::Unsupported(format!("input.type:{kind}"))),
    };
    let mut out = Map::new();
    out.insert("type".into(), json!(kind));
    for (key, value) in o {
        if semantic.contains(&key.as_str()) {
            out.insert(key.clone(), value.clone());
        } else if ![
            "type",
            "id",
            "call_id",
            "encrypted_content",
            "encrypted_function_args",
            "internal_chat_message_metadata_passthrough",
            "status",
        ]
        .contains(&key.as_str())
        {
            return Err(ProtocolError::Unsupported(format!("input.{kind}.{key}")));
        }
    }
    if let Some(raw) = o
        .get("internal_chat_message_metadata_passthrough")
        .filter(|value| !value.is_null())
    {
        // The native client's explicit content classifications are business
        // context, not evidence of gateway tool execution. Preserve only this
        // field: old turn/time/cell IDs and host-owned call facts stay local.
        let metadata: codex_protocol::models::InternalChatMessageMetadataPassthrough =
            serde_json::from_value(raw.clone())
                .map_err(|_| ProtocolError::Invalid("input.content_metadata"))?;
        if let Some(kinds) = metadata.content_item_kinds {
            let contents = o.get("content").and_then(Value::as_array);
            if kind != "message"
                || contents.is_none_or(|parts| parts.len() != kinds.len())
                || kinds.iter().any(|kind| {
                    kind.0.is_empty() || kind.0.len() > 256 || kind.0.chars().any(char::is_control)
                })
            {
                return Err(ProtocolError::Invalid("input.content_item_kinds"));
            }
            out.insert(
                "internal_chat_message_metadata_passthrough".into(),
                json!({
                    "content_item_kinds": kinds
                }),
            );
        } else if raw
            .get("content_item_kinds")
            .is_some_and(|value| !value.is_null())
        {
            return Err(ProtocolError::Invalid("input.content_item_kinds"));
        }
    }
    let has_call = [
        "function_call",
        "custom_tool_call",
        "function_call_output",
        "custom_tool_call_output",
        "tool_search_call",
        "tool_search_output",
        "local_shell_call",
    ]
    .contains(&kind);
    if o.contains_key("call_id") && !has_call {
        return Err(ProtocolError::Unsupported(format!("input.{kind}.call_id")));
    }
    if kind == "compaction_trigger" && o.len() != 1 {
        return Err(ProtocolError::Invalid("input.compaction_trigger"));
    }
    if let Some(id) = o.get("id").filter(|v| !v.is_null()) {
        string(id, "input.id")?;
        // Unmapped local message IDs carry no upstream reference authority.
        let typed = (
            IdentityKind::Item,
            item_identity_key(kind, id.as_str().unwrap_or_default()),
        );
        if let Some(mapped) = ctx.identifiers.get(&typed) {
            if !identity(mapped) {
                return Err(ProtocolError::Invalid("input.id"));
            }
            out.insert("id".into(), json!(mapped));
        } else if ctx.identifiers.contains_key(&(
            IdentityKind::Item,
            id.as_str().unwrap_or_default().to_owned(),
        )) {
            out.insert(
                "id".into(),
                mapped(id, IdentityKind::Item, "input.id", ctx)?,
            );
        }
    }
    if let Some(call) = o.get("call_id").filter(|v| !v.is_null()) {
        out.insert(
            "call_id".into(),
            mapped(call, IdentityKind::Call, "input.call_id", ctx)?,
        );
    }
    // Direct output is a native start/steer item (turn_input.rs:289-298).
    // It carries no call-reference authority and is never matched to a call.
    if [
        "function_call",
        "custom_tool_call",
        "custom_tool_call_output",
    ]
    .contains(&kind)
        && !out.contains_key("call_id")
    {
        return Err(ProtocolError::Invalid("input.call_id"));
    }
    if kind == "message" {
        enum_string(
            out.get("role").unwrap_or(&Value::Null),
            &["user", "developer", "system", "assistant"],
            "input.role",
        )?;
        if let Some(phase) = out.get("phase").filter(|v| !v.is_null()) {
            enum_string(phase, &["commentary", "final_answer"], "input.phase")?;
        }
        out.insert(
            "content".into(),
            content(o.get("content").unwrap_or(&Value::Null), ctx, true)?,
        );
    }
    if kind == "additional_tools" {
        validate_tools(o.get("tools").unwrap_or(&Value::Null))?;
    }
    if kind == "agent_message" {
        for field in ["author", "recipient"] {
            if !out.get(field).and_then(Value::as_str).is_some_and(identity) {
                return Err(ProtocolError::Invalid("input.agent_message"));
            }
        }
        let parts = o
            .get("content")
            .and_then(Value::as_array)
            .ok_or(ProtocolError::Invalid("input.agent_message.content"))?;
        let mut projected = Vec::with_capacity(parts.len());
        for part in parts {
            let p = object(part, "input.agent_message.content")?;
            match p.get("type").and_then(Value::as_str) {
                Some("input_text") => {
                    keys(p, &["type", "text"], "input.agent_message.content")?;
                    string(
                        p.get("text").unwrap_or(&Value::Null),
                        "input.agent_message.text",
                    )?;
                    projected.push(part.clone());
                }
                Some("encrypted_content") => {
                    keys(
                        p,
                        &["type", "encrypted_content"],
                        "input.agent_message.content",
                    )?;
                    let cipher = p.get("encrypted_content").unwrap_or(&Value::Null);
                    let text = string(cipher, "input.agent_message.encrypted_content")?;
                    if !parent_agent_cipher_sha256
                        .contains(&format!("{:x}", Sha256::digest(text.as_bytes())))
                    {
                        opaque(cipher, "input.agent_message.encrypted_content", ctx)?;
                    }
                    projected.push(part.clone());
                }
                _ => return Err(ProtocolError::Invalid("input.agent_message.content")),
            }
        }
        out.insert("content".into(), Value::Array(projected));
    }
    if kind == "local_shell_call" {
        enum_string(
            out.get("status").unwrap_or(&Value::Null),
            &["completed", "in_progress", "incomplete"],
            "input.local_shell.status",
        )?;
        let action = out
            .get("action")
            .ok_or(ProtocolError::Invalid("input.local_shell.action"))?;
        let _: codex_protocol::models::LocalShellAction = serde_json::from_value(action.clone())
            .map_err(|_| ProtocolError::Invalid("input.local_shell.action"))?;
        keys(
            object(action, "input.local_shell.action")?,
            &[
                "type",
                "command",
                "timeout_ms",
                "working_directory",
                "env",
                "user",
            ],
            "input.local_shell.action",
        )?;
    }
    if kind == "reasoning" {
        if !o.get("summary").is_some_and(Value::is_array) {
            return Err(ProtocolError::Invalid("input.reasoning.summary"));
        }
        for field in ["summary", "content"] {
            if let Some(values) = o.get(field).filter(|v| !v.is_null()) {
                let a = values
                    .as_array()
                    .ok_or(ProtocolError::Invalid("input.reasoning"))?;
                for part in a {
                    let part = object(part, "input.reasoning.part")?;
                    keys(part, &["type", "text"], "input.reasoning.part")?;
                    enum_string(
                        part.get("type").unwrap_or(&Value::Null),
                        if field == "summary" {
                            &["summary_text"]
                        } else {
                            &["reasoning_text", "text"]
                        },
                        "input.reasoning.part.type",
                    )?;
                    string(
                        part.get("text").unwrap_or(&Value::Null),
                        "input.reasoning.part.text",
                    )?;
                }
            }
        }
    }
    for (item_type, fields) in [
        ("function_call", &["name", "arguments"][..]),
        ("custom_tool_call", &["name", "input"][..]),
        ("tool_search_call", &["execution"][..]),
        ("tool_search_output", &["execution", "status", "tools"][..]),
        ("image_generation_call", &["status", "result"][..]),
    ] {
        if kind == item_type && fields.iter().any(|f| !out.contains_key(*f)) {
            return Err(ProtocolError::Invalid("input.required_field"));
        }
    }
    if kind == "configuration_update" {
        let value = out
            .get("reasoning")
            .ok_or(ProtocolError::Invalid("input.configuration_update"))?;
        let reasoning = object(value, "input.configuration_update.reasoning")?;
        keys(
            reasoning,
            &["effort"],
            "input.configuration_update.reasoning",
        )?;
        if !reasoning
            .get("effort")
            .is_some_and(|v| v.as_str().is_some_and(identity))
        {
            return Err(ProtocolError::Invalid(
                "input.configuration_update.reasoning.effort",
            ));
        }
    }
    if ["function_call_output", "custom_tool_call_output"].contains(&kind) {
        let output = o
            .get("output")
            .ok_or(ProtocolError::Invalid("input.output"))?;
        out.insert(
            "output".into(),
            if output.is_string() {
                output.clone()
            } else {
                content(output, ctx, false)?
            },
        );
    }
    if let Some(cipher) = o.get("encrypted_content").filter(|v| !v.is_null()) {
        if !["reasoning", "compaction", "context_compaction"].contains(&kind) {
            return Err(ProtocolError::Unsupported(format!(
                "input.{kind}.encrypted_content"
            )));
        }
        match opaque(cipher, "input.encrypted_content", ctx) {
            Ok(value) => {
                out.insert("encrypted_content".into(), value);
            }
            Err(ProtocolError::UnverifiedOpaque(_)) if kind == "reasoning" => {}
            Err(error) => return Err(error),
        }
    }
    if kind == "compaction" && !out.contains_key("encrypted_content") {
        return Err(ProtocolError::UnverifiedOpaque("input.compaction"));
    }
    if let Some(values) = o.get("encrypted_function_args").filter(|v| !v.is_null()) {
        if kind != "function_call" {
            return Err(ProtocolError::Unsupported(format!(
                "input.{kind}.encrypted_function_args"
            )));
        }
        let values = values
            .as_array()
            .ok_or(ProtocolError::Invalid("input.encrypted_function_args"))?;
        if values
            .iter()
            .all(|v| v.as_str().is_some_and(|s| ctx.verified_opaque.contains(s)))
        {
            out.insert(
                "encrypted_function_args".into(),
                Value::Array(values.clone()),
            );
        } else if out
            .get("arguments")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(ProtocolError::UnverifiedOpaque(
                "input.encrypted_function_args",
            ));
        }
    }
    for field in [
        "name",
        "namespace",
        "arguments",
        "input",
        "execution",
        "status",
        "revised_prompt",
        "result",
    ] {
        if let Some(value) = out.get(field).filter(|v| !v.is_null())
            && (field != "arguments" || kind != "tool_search_call")
        {
            string(value, "input.semantic_string")?;
        }
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(v: Value) -> Result<BuiltRequest> {
        build_request(
            v,
            &RequestContext {
                gateway_thread_id: "gw-thread",
                gateway_turn_id: "gw-turn",
                cache_key: "gw-cache",
                identifiers: &IdentifierMap::new(),
                verified_opaque: &BTreeSet::new(),
            },
        )
    }
    fn base() -> Value {
        json!({"model":"gpt-test","input":[{"role":"user","content":"hi"}]})
    }

    #[test]
    fn semantic_fields_survive_but_client_identity_does_not() {
        let mut v = base();
        v["client_metadata"] = json!({"thread_id":"CLIENT","executed_tool_calls":[1]});
        v["metadata"] = json!({"user":"CLIENT"});
        v["prompt_cache_key"] = json!("CLIENT");
        v["traceparent"] = json!("CLIENT");
        v["id"] = json!("CLIENT");
        v["store"] = json!(true);
        v["instructions"] = json!("keep this");
        v["reasoning"] = json!({"effort":2048,"summary":"concise","context":"all_turns"});
        v["text"] = json!({"verbosity":"high","format":{"type":"json_schema","strict":true,"name":"reply","schema":{"properties":{"id":{"const":"literal-client-id"}},"encrypted_content":true}}});
        v["stream_options"] = json!({"reasoning_summary_delivery":"sequential_cutoff"});
        let projected = build(v.clone()).unwrap().body;
        assert_eq!(projected["instructions"], v["instructions"]);
        assert_eq!(projected["reasoning"], v["reasoning"]);
        assert_eq!(projected["text"], v["text"]);
        assert_eq!(
            projected["client_metadata"],
            json!({"thread_id":"gw-thread","turn_id":"gw-turn"})
        );
        assert_eq!(projected["prompt_cache_key"], "gw-cache");
        assert_eq!(projected["stream"], true);
        assert_eq!(projected["store"], false);
        for key in ["metadata", "traceparent", "id"] {
            assert!(projected.get(key).is_none());
        }
    }

    #[test]
    fn unknown_fields_nonstream_and_incremental_history_are_explicit_rejections() {
        let mut v = base();
        v["temperature"] = json!(0.5);
        assert_eq!(
            build(v).unwrap_err(),
            ProtocolError::Unsupported("temperature".into())
        );
        let mut v = base();
        v["stream"] = json!(false);
        assert_eq!(
            build(v).unwrap_err(),
            ProtocolError::Unsupported("stream=false".into())
        );
        for field in ["previous_response_id", "conversation"] {
            let mut v = base();
            v[field] = json!("foreign");
            assert_eq!(
                build(v).unwrap_err(),
                ProtocolError::Unsupported(field.into())
            );
        }
        let mut v = base();
        v["previous_response_id"] = Value::Null;
        assert!(build(v).unwrap().body.get("previous_response_id").is_none());
    }

    #[test]
    fn only_root_mapped_call_and_resource_ids_are_sent() {
        let v = json!({"model":"test","input":[{"type":"function_call","id":"client-item","call_id":"client-call","name":"run","arguments":"{\"id\":\"literal\"}"},
            {"type":"function_call_output","call_id":"client-call","id":"client-output","output":"ok","internal_chat_message_metadata_passthrough":{"executed_tool_calls":[1]}},
            {"role":"user","content":[{"type":"input_image","file_id":"client-file","detail":"original"}]}]});
        assert_eq!(
            build(v.clone()).unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
        let ids = IdentifierMap::from([
            ((IdentityKind::Item, "client-item".into()), "gw-item".into()),
            ((IdentityKind::Call, "client-call".into()), "gw-call".into()),
            ((IdentityKind::File, "client-file".into()), "gw-file".into()),
        ]);
        let body = build_request(
            v,
            &RequestContext {
                gateway_thread_id: "gw-thread",
                gateway_turn_id: "gw-turn",
                cache_key: "gw-cache",
                identifiers: &ids,
                verified_opaque: &BTreeSet::new(),
            },
        )
        .unwrap()
        .body;
        assert_eq!(body["input"][0]["id"], "gw-item");
        assert_eq!(body["input"][1]["call_id"], "gw-call");
        assert_eq!(body["input"][0]["arguments"], "{\"id\":\"literal\"}");
        assert!(body["input"][1].get("id").is_none());
        assert!(
            body["input"][1]
                .get("internal_chat_message_metadata_passthrough")
                .is_none()
        );
        assert_eq!(body["input"][2]["content"][0]["file_id"], "gw-file");
    }

    #[test]
    fn explicit_native_content_classes_survive_without_client_ids_or_tool_claims() {
        let mut input = json!({"model":"test","input":[{"role":"user","content":[
            {"type":"input_text","text":"native instructions"},
            {"type":"input_text","text":"native request"}],
            "internal_chat_message_metadata_passthrough":{
                "content_item_kinds":["environments.environment_context","user.text"],
                "turn_id":"client-turn","create_time":123.5,"cell_id":"client-cell",
                "executed_tool_calls":[{"name":"not-observed"}],"tool_calls_complete":true}}]});
        let output = build(input.clone()).unwrap().body;
        assert_eq!(
            output["input"][0]["internal_chat_message_metadata_passthrough"],
            json!({
            "content_item_kinds":["environments.environment_context","user.text"]})
        );
        input["input"][0]["internal_chat_message_metadata_passthrough"]["content_item_kinds"] =
            json!(["user.text"]);
        assert!(matches!(
            build(input),
            Err(ProtocolError::Invalid("input.content_item_kinds"))
        ));
    }

    #[test]
    fn ciphertext_never_acquires_authority_from_client_input() {
        let reasoning = json!({"model":"test","input":[{"type":"reasoning","id":"client-rs","summary":[{"type":"summary_text","text":"readable"}],"encrypted_content":"foreign"}]});
        let body = build(reasoning).unwrap().body;
        assert!(body["input"][0].get("encrypted_content").is_none());
        assert_eq!(body["input"][0]["summary"][0]["text"], "readable");
        let v =
            json!({"model":"test","input":[{"type":"compaction","encrypted_content":"foreign"}]});
        assert_eq!(
            build(v.clone()).unwrap_err(),
            ProtocolError::UnverifiedOpaque("input.encrypted_content")
        );
        let trusted = BTreeSet::from(["foreign".into()]);
        let body = build_request(
            v,
            &RequestContext {
                gateway_thread_id: "gw-thread",
                gateway_turn_id: "gw-turn",
                cache_key: "gw-cache",
                identifiers: &IdentifierMap::new(),
                verified_opaque: &trusted,
            },
        )
        .unwrap()
        .body;
        assert_eq!(body["input"][0]["encrypted_content"], "foreign");
    }

    #[test]
    fn identifier_namespaces_do_not_cross_authorize_calls_or_files() {
        let ids = IdentifierMap::from([
            ((IdentityKind::Item, "same".into()), "gw-item".into()),
            ((IdentityKind::Call, "same".into()), "gw-call".into()),
            ((IdentityKind::File, "same".into()), "gw-file".into()),
        ]);
        let context = RequestContext {
            gateway_thread_id: "gw-thread",
            gateway_turn_id: "gw-turn",
            cache_key: "gw-cache",
            identifiers: &ids,
            verified_opaque: &BTreeSet::new(),
        };
        let input = json!({"model":"test","input":[{"type":"function_call","id":"same","call_id":"same","name":"run","arguments":"{}"},{"role":"user","content":[{"type":"input_image","file_id":"same"}]}]});
        let body = build_request(input.clone(), &context).unwrap().body;
        assert_eq!(body["input"][0]["id"], "gw-item");
        assert_eq!(body["input"][0]["call_id"], "gw-call");
        assert_eq!(body["input"][1]["content"][0]["file_id"], "gw-file");
        let item_only =
            IdentifierMap::from([((IdentityKind::Item, "same".into()), "gw-item".into())]);
        assert_eq!(
            build_request(
                input,
                &RequestContext {
                    identifiers: &item_only,
                    ..context
                }
            )
            .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
        let image = json!({"model":"test","input":[{"role":"user","content":[{"type":"input_image","file_id":"same"}]}]});
        assert_eq!(
            build_request(
                image,
                &RequestContext {
                    identifiers: &item_only,
                    ..context
                }
            )
            .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.file_id")
        );
    }

    #[test]
    fn standalone_direct_output_carries_no_call_reference() {
        for call in [None, Some(Value::Null)] {
            let mut item = json!({"type":"function_call_output","name":"agent_mailbox","output":"external message"});
            if let Some(call) = call {
                item["call_id"] = call;
            }
            let request = build(json!({"model":"test","input":[item]})).unwrap();
            assert!(request.body["input"][0].get("call_id").is_none());
            assert_eq!(request.body["input"][0]["output"], "external message");
        }
    }

    #[test]
    fn compaction_control_must_be_a_single_final_input() {
        let mut v = base();
        v["input"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"compaction_trigger"}));
        assert!(build(v.clone()).unwrap().is_compaction);
        v["input"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role":"user","content":"later"}));
        assert_eq!(
            build(v).unwrap_err(),
            ProtocolError::Invalid("input.compaction_trigger")
        );
    }

    #[test]
    fn malformed_content_and_stream_options_do_not_pass_through() {
        let mut v = base();
        v["stream_options"] = json!({"include_usage":true});
        assert!(matches!(build(v), Err(ProtocolError::Unsupported(_))));
        let mut v = base();
        v["stream_options"] = json!({"reasoning_summary_delivery":"sequential_cutoff"});
        assert_eq!(
            build(v).unwrap_err(),
            ProtocolError::Invalid("stream_options.reasoning_summary")
        );
        let v = json!({"model":"test","input":[{"role":"user","content":[{"type":"input_file","file_id":"foreign"}]}]});
        assert_eq!(
            build(v).unwrap_err(),
            ProtocolError::Unsupported("input.content.type:input_file".into())
        );
    }

    #[test]
    fn v2_needs_one_compaction_and_actual_completed_not_eof() {
        let done = json!({"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"result"}});
        let completed = json!({"type":"response.completed","response":{"id":"resp-own"}});
        let mut observe = V2Completion::default();
        assert!(observe.finish().is_err());
        observe.observe(&done).unwrap();
        assert!(observe.finish().is_err());
        observe.observe(&completed).unwrap();
        observe.finish().unwrap();
        let mut duplicate = V2Completion::default();
        duplicate.observe(&done).unwrap();
        assert!(duplicate.observe(&done).is_err());
        assert!(V2Completion::default().observe(&completed).is_err());
    }
}

fn content(v: &Value, ctx: &RequestContext<'_>, message: bool) -> Result<Value> {
    if message && v.is_string() {
        return Ok(json!([{"type":"input_text","text":v}]));
    }
    let mut result = Vec::new();
    for item in v
        .as_array()
        .ok_or(ProtocolError::Invalid("input.content"))?
    {
        let o = object(item, "input.content.item")?;
        let kind = string(o.get("type").unwrap_or(&Value::Null), "input.content.type")?;
        let mut out = Map::new();
        out.insert("type".into(), json!(kind));
        match kind {
            "input_text" | "output_text" => {
                string(o.get("text").unwrap_or(&Value::Null), "input.content.text")?;
                out.insert("text".into(), o["text"].clone());
            }
            "input_image" => {
                if o.contains_key("image_url") == o.contains_key("file_id") {
                    return Err(ProtocolError::Invalid("input.image_reference"));
                }
                if let Some(url) = o.get("image_url") {
                    string(url, "input.image_url")?;
                    out.insert("image_url".into(), url.clone());
                }
                if let Some(file) = o.get("file_id") {
                    out.insert(
                        "file_id".into(),
                        mapped(file, IdentityKind::File, "input.file_id", ctx)?,
                    );
                }
                if let Some(detail) = o.get("detail").filter(|v| !v.is_null()) {
                    enum_string(
                        detail,
                        &["auto", "low", "high", "original"],
                        "input.image.detail",
                    )?;
                    out.insert("detail".into(), detail.clone());
                }
            }
            "input_audio" => {
                string(
                    o.get("audio_url").unwrap_or(&Value::Null),
                    "input.audio_url",
                )?;
                out.insert("audio_url".into(), o["audio_url"].clone());
            }
            "encrypted_content" if !message => {
                out.insert(
                    "encrypted_content".into(),
                    opaque(
                        o.get("encrypted_content").unwrap_or(&Value::Null),
                        "input.output.encrypted_content",
                        ctx,
                    )?,
                );
            }
            _ => {
                return Err(ProtocolError::Unsupported(format!(
                    "input.content.type:{kind}"
                )));
            }
        }
        keys(
            o,
            &[
                "type",
                "text",
                "image_url",
                "file_id",
                "detail",
                "audio_url",
                "encrypted_content",
                "annotations",
            ],
            "input.content",
        )?;
        result.push(Value::Object(out));
    }
    Ok(Value::Array(result))
}

/// Compact V2's collect_compaction_output contract: exactly one completed
/// compaction item and a response.completed. EOF alone proves no completion.
#[derive(Default, Debug)]
pub struct V2Completion {
    compactions: usize,
    completed: bool,
}
impl V2Completion {
    pub fn observe(&mut self, event: &Value) -> Result<()> {
        let o = object(event, "response.event")?;
        let kind = string(o.get("type").unwrap_or(&Value::Null), "response.event.type")?;
        if self.completed {
            return Err(ProtocolError::Invalid("response.after_completed"));
        }
        if kind == "response.output_item.done" && event["item"]["type"] == "compaction" {
            if !event["item"]["encrypted_content"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            {
                return Err(ProtocolError::Invalid("response.compaction_item"));
            }
            self.compactions += 1;
            if self.compactions > 1 {
                return Err(ProtocolError::Invalid("response.compaction_count"));
            }
        }
        if kind == "response.completed" {
            if !event["response"]["id"].as_str().is_some_and(identity) || self.compactions != 1 {
                return Err(ProtocolError::Invalid("response.compaction_completion"));
            }
            self.completed = true;
        }
        Ok(())
    }
    pub fn finish(&self) -> Result<()> {
        if self.completed && self.compactions == 1 {
            Ok(())
        } else {
            Err(ProtocolError::Invalid("response.compaction_incomplete"))
        }
    }
}
