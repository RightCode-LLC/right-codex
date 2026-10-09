use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::metadata::{self, ClientMetadata, MetadataScope, ParentMetadataProof};
use crate::protocol::{
    self, BuiltRequest, IdentifierMap, IdentityKind, ProtocolError, RequestContext,
};
use crate::response_projection::{self, ProtocolEnvelope};

pub const MAX_SESSIONS: usize = 128;
pub const MAX_SESSION_CAPACITY: usize = 4096;
pub const MAX_IDENTITY_ROWS: usize = 4096;
pub const MAX_IDENTITY_BYTES: usize = 1024 * 1024;
pub const MAX_OPAQUE_ITEMS: usize = 128;
pub const MAX_OPAQUE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SINGLE_OPAQUE_BYTES: usize = 256 * 1024;
pub const MAX_ATTEMPTS: usize = 256;
// Includes repeated attempt/checkpoint history, not just one input. Native
// image tool results cross the former 8 MiB aggregate in two ordinary turns.
pub const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FILE_ROWS: usize = 256;
pub const MAX_REALTIME_CALL_ROWS: usize = 256;
pub const MAX_CONNECTION_SIDEBANDS: usize = 256;
pub const MAX_PERSISTENCE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CallKind {
    Function,
    Custom,
    ToolSearch,
    LocalShell,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CallSignature {
    kind: CallKind,
    name: Option<String>,
    namespace: Option<String>,
}

fn bounded_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn history_item(mut item: Value) -> Value {
    // Official Responses parsing deserializes ResponseItem and drops this
    // unknown backend field (sse/responses.rs:355). It is not the harness
    // internal_chat_message_metadata_passthrough wire field. Keep the raw
    // event for delivery; normalize only the durable continuation item.
    if let Some(object) = item.as_object_mut() {
        object.remove("metadata");
        if object.get("type").and_then(Value::as_str) == Some("message")
            && let Some(parts) = object.get_mut("content").and_then(Value::as_array_mut)
        {
            for part in parts {
                // The pinned ContentItem decoder retains only the fields of
                // its four variants. Raw SSE still reaches the client intact;
                // continuation history follows the decoded native item.
                if matches!(
                    part.get("type").and_then(Value::as_str),
                    Some("input_text" | "output_text" | "input_image" | "input_audio")
                ) && let Ok(decoded) =
                    serde_json::from_value::<codex_protocol::models::ContentItem>(part.clone())
                    && let Ok(normalized) = serde_json::to_value(decoded)
                {
                    *part = normalized;
                }
            }
        }
    }
    item
}

impl CallSignature {
    fn from_item(item: &Value) -> Result<Option<Self>, ProtocolError> {
        let kind = match item["type"].as_str() {
            Some("function_call") => CallKind::Function,
            Some("custom_tool_call") => CallKind::Custom,
            Some("tool_search_call") => CallKind::ToolSearch,
            Some("local_shell_call") => CallKind::LocalShell,
            _ => return Ok(None),
        };
        let mut name = None;
        let mut namespace = None;
        for (field, target) in [("name", &mut name), ("namespace", &mut namespace)] {
            if let Some(value) = item.get(field).filter(|value| !value.is_null()) {
                let value = value
                    .as_str()
                    .filter(|value| bounded_identity(value))
                    .ok_or(ProtocolError::Invalid("input.call_signature"))?;
                *target = Some(value.to_owned());
            }
        }
        if !matches!(kind, CallKind::ToolSearch | CallKind::LocalShell) && name.is_none() {
            return Err(ProtocolError::Invalid("input.call_signature"));
        }
        Ok(Some(Self {
            kind,
            name,
            namespace,
        }))
    }

    fn validate_output(&self, item: &Value) -> Result<(), ProtocolError> {
        let expected = match item["type"].as_str() {
            Some("function_call_output") => CallKind::Function,
            Some("custom_tool_call_output") => CallKind::Custom,
            Some("tool_search_output") => CallKind::ToolSearch,
            _ => return Err(ProtocolError::Invalid("input.call_output")),
        };
        if expected != self.kind
            && !(self.kind == CallKind::LocalShell && expected == CallKind::Function)
        {
            return Err(ProtocolError::Invalid("input.call_output_kind"));
        }
        for (field, expected) in [("name", &self.name), ("namespace", &self.namespace)] {
            if let Some(actual) = item.get(field).filter(|value| !value.is_null())
                && actual.as_str() != expected.as_deref()
            {
                return Err(ProtocolError::Invalid("input.call_output_signature"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct IdentityState {
    identifiers: IdentifierMap,
    upstream_to_client: IdentifierMap,
    /// Only real upstream call items populate this set. Input declarations do
    /// not become evidence for outputs in a later request.
    observed_calls: BTreeMap<String, CallSignature>,
}

impl IdentityState {
    fn check_budget(&self) -> Result<(), ProtocolError> {
        let rows =
            self.identifiers.len() + self.upstream_to_client.len() + self.observed_calls.len();
        let bytes: usize = self
            .identifiers
            .iter()
            .chain(&self.upstream_to_client)
            .map(|((_, key), value)| key.len() + value.len())
            .sum::<usize>()
            + self
                .observed_calls
                .iter()
                .map(|(key, value)| {
                    key.len()
                        + value.name.as_ref().map_or(0, String::len)
                        + value.namespace.as_ref().map_or(0, String::len)
                })
                .sum::<usize>();
        if rows > MAX_IDENTITY_ROWS || bytes > MAX_IDENTITY_BYTES {
            return Err(ProtocolError::Capacity("session.identities"));
        }
        Ok(())
    }

    fn map_local(&mut self, kind: IdentityKind, value: &str) -> Result<(), ProtocolError> {
        if !bounded_identity(value) {
            return Err(ProtocolError::Invalid("input.identity"));
        }
        self.identifiers
            .entry((kind, value.to_owned()))
            .or_insert_with(|| format!("{}_{}", identity_prefix(kind), Uuid::new_v4()));
        self.check_budget()
    }
    fn map_local_item(&mut self, kind: &str, value: &str) -> Result<(), ProtocolError> {
        if !bounded_identity(value) {
            return Err(ProtocolError::Invalid("input.id"));
        }
        let prefix = protocol::item_id_prefix(kind)
            .ok_or(ProtocolError::Invalid("input.item_without_id"))?;
        if let Some(actual) = self.identifiers.get(&(IdentityKind::Item, value.into()))
            && self
                .upstream_to_client
                .get(&(IdentityKind::Item, actual.clone()))
                .map(String::as_str)
                == Some(value)
        {
            return Ok(());
        }
        self.identifiers
            .entry((IdentityKind::Item, protocol::item_identity_key(kind, value)))
            .or_insert_with(|| format!("{prefix}_{}", Uuid::new_v4()));
        self.check_budget()
    }

    fn client_alias(
        &mut self,
        kind: IdentityKind,
        original: &str,
    ) -> Result<String, ProtocolError> {
        if !bounded_identity(original) {
            return Err(ProtocolError::Invalid("upstream.identity"));
        }
        let key = (kind, original.to_owned());
        if let Some(alias) = self.upstream_to_client.get(&key) {
            return Ok(alias.clone());
        }
        let alias = format!("{}_{}", identity_prefix(kind), Uuid::new_v4());
        self.upstream_to_client.insert(key, alias.clone());
        self.identifiers
            .insert((kind, alias.clone()), original.to_owned());
        self.check_budget()?;
        Ok(alias)
    }

    fn rewrite_field(
        &mut self,
        object: &mut Value,
        field: &str,
        kind: IdentityKind,
    ) -> Result<(), ProtocolError> {
        if let Some(original) = object.get(field).filter(|value| !value.is_null()) {
            let original = original
                .as_str()
                .ok_or(ProtocolError::Invalid("upstream.identity"))?;
            let alias = self.client_alias(kind, original)?;
            object[field] = Value::String(alias);
        }
        Ok(())
    }

    fn rewrite_item(&mut self, item: &mut Value) -> Result<(), ProtocolError> {
        let signature = CallSignature::from_item(item)?;
        self.rewrite_field(item, "id", IdentityKind::Item)?;
        self.rewrite_field(item, "call_id", IdentityKind::Call)?;
        if let (Some(signature), Some(alias)) = (signature, item["call_id"].as_str()) {
            if self
                .observed_calls
                .get(alias)
                .is_some_and(|prior| prior != &signature)
            {
                return Err(ProtocolError::Invalid("upstream.call_signature_changed"));
            }
            self.observed_calls.insert(alias.to_owned(), signature);
            self.check_budget()?;
        }
        Ok(())
    }
}

fn identity_prefix(kind: IdentityKind) -> &'static str {
    match kind {
        IdentityKind::Item => "item",
        IdentityKind::Call => "call",
        IdentityKind::File => "file",
        IdentityKind::Response => "resp",
    }
}

/// All upstream identities belong to one conversation and account/auth revision.
/// Client labels are used only in local lookup keys. Limits reject new entries;
/// an already-used identity is never silently evicted or rebound.
pub struct Session {
    pub account_id: String,
    pub auth_revision: String,
    pub thread_id: String,
    pub session_id: String,
    pub cache_key: String,
    pub verified_opaque: BTreeSet<String>,
    identities: IdentityState,
    pub installation_id: String,
    pub window_id: String,
    pub context_window_id: String,
    pub window_number: u64,
    generation: u64,
    attempts: BTreeMap<String, AttemptRecord>,
    plaintext_history: Vec<Value>,
    response_histories: BTreeMap<String, Vec<Value>>,
    compaction_histories: BTreeMap<String, Vec<Value>>,
    files: BTreeMap<String, FileProvenance>,
    delivered_tools: BTreeMap<String, DeliveredTool>,
    sticky_turn_state: Option<String>,
    switched: bool,
    active_attempt: Option<String>,
    last_activity_unix_ms: u64,
    turn_aliases: BTreeMap<String, String>,
    suppressed_tools: BTreeMap<String, (String, String)>,
    realtime_calls: BTreeMap<String, ScopedRealtimeCall>,
    connection_sidebands: Vec<ConnectionSideband>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Prepared,
    Sending,
    Unknown,
    Completed,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt_id: String,
    pub turn_id: String,
    pub upstream_turn_id: String,
    pub account_id: String,
    pub auth_revision: String,
    pub request_sha256: String,
    pub state: AttemptState,
    pub response_id: Option<String>,
    pub terminal_sha256: Option<String>,
    input: Vec<Value>,
    is_compaction: bool,
    delivered_events: Vec<Value>,
    observed_output: Vec<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileProvenance {
    pub account_id: String,
    pub auth_revision: String,
    pub client_id: String,
    pub upstream_id: String,
    pub content_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedRealtimeCall {
    account_id: String,
    auth_revision: String,
    upstream_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSideband {
    pub connection_id: String,
    pub frame_index: u64,
    pub account_id: String,
    pub auth_revision: String,
    pub kind: String,
    pub raw_sha256: String,
    pub bytes: usize,
    pub observed_at_unix_ms: u64,
    pub client_socket_written: bool,
}
/// Holds uncommitted aliases. A stale prepare cannot overwrite events or a
/// later account revision; commit checks the session mutation generation.
#[derive(Debug)]
pub struct PreparedRequest {
    generation: u64,
    identities: IdentityState,
    request: BuiltRequest,
    headers: HeaderMap,
    metadata: ClientMetadata,
    attempt: AttemptRecord,
    turn_aliases: BTreeMap<String, String>,
}
#[derive(Debug)]
pub struct ScopedRequest {
    pub request: BuiltRequest,
    pub outbound_headers: HeaderMap,
    pub metadata: ClientMetadata,
    pub attempt_id: String,
    pub upstream_turn_id: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDelivery {
    Deliver,
    AlreadyDelivered,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveredTool {
    attempt_id: String,
    fingerprint: String,
    item_sha256: String,
}

impl Session {
    pub fn new(account_id: String, auth_revision: String) -> Self {
        Self {
            account_id,
            auth_revision,
            thread_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            cache_key: Uuid::new_v4().to_string(),
            verified_opaque: BTreeSet::new(),
            identities: IdentityState::default(),
            installation_id: Uuid::new_v4().to_string(),
            window_id: Uuid::new_v4().to_string(),
            context_window_id: Uuid::new_v4().to_string(),
            window_number: 1,
            generation: 0,
            attempts: BTreeMap::new(),
            plaintext_history: Vec::new(),
            response_histories: BTreeMap::new(),
            compaction_histories: BTreeMap::new(),
            files: BTreeMap::new(),
            delivered_tools: BTreeMap::new(),
            sticky_turn_state: None,
            switched: false,
            active_attempt: None,
            last_activity_unix_ms: unix_ms(),
            turn_aliases: BTreeMap::new(),
            suppressed_tools: BTreeMap::new(),
            realtime_calls: BTreeMap::new(),
            connection_sidebands: Vec::new(),
        }
    }

    pub fn identifiers(&self) -> &IdentifierMap {
        &self.identities.identifiers
    }

    pub fn attempt(&self, id: &str) -> Option<&AttemptRecord> {
        self.attempts.get(id)
    }
    /// The local hashed native turn must already have an actual request in
    /// this conversation. This is scope lookup, not current-account resource
    /// authority or evidence of image/tool execution.
    pub(crate) fn has_registered_image_turn(&self, logical_turn: &str) -> bool {
        self.attempts.values().any(|attempt| {
            attempt.turn_id == logical_turn
                && !attempt.is_compaction
                && matches!(
                    attempt.state,
                    AttemptState::Sending | AttemptState::Completed
                )
        })
    }
    /// Local turn ownership survives a switch, but the upstream turn is always
    /// minted under the current account/revision after its alias map is cleared.
    pub fn bind_auxiliary_turn(&mut self, logical_turn: &str) -> Result<String, ProtocolError> {
        if !self.has_registered_image_turn(logical_turn) {
            return Err(ProtocolError::UnmappedIdentity("images.turn"));
        }
        if let Some(turn) = self.turn_aliases.get(logical_turn) {
            return Ok(turn.clone());
        }
        if self.turn_aliases.len() >= MAX_ATTEMPTS {
            return Err(ProtocolError::Capacity("session.turns"));
        }
        let turn = Uuid::new_v4().to_string();
        self.turn_aliases.insert(logical_turn.into(), turn.clone());
        self.generation += 1;
        self.last_activity_unix_ms = unix_ms();
        Ok(turn)
    }
    pub fn upstream_turn_for(&self, logical_turn: &str) -> Option<&str> {
        let upstream = self.turn_aliases.get(logical_turn)?;
        self.attempts
            .values()
            .any(|attempt| {
                attempt.turn_id == logical_turn
                    && &attempt.upstream_turn_id == upstream
                    && attempt.account_id == self.account_id
                    && attempt.auth_revision == self.auth_revision
                    && !attempt.is_compaction
                    && matches!(
                        attempt.state,
                        AttemptState::Sending | AttemptState::Completed
                    )
            })
            .then_some(upstream.as_str())
    }
    pub fn history(&self) -> &[Value] {
        &self.plaintext_history
    }
    /// Projects an actual connection handshake without inventing a model
    /// request or attempt. `input` supplies local classifier metadata only.
    /// A later request for this logical turn reuses the committed turn alias.
    pub fn prepare_handshake_metadata(
        &mut self,
        input: &Value,
        headers: &HeaderMap,
        logical_turn: &str,
        parent: Option<&ParentMetadataProof>,
    ) -> Result<HeaderMap, ProtocolError> {
        let metadata = metadata::classify_request(input, headers)?;
        if !bounded_identity(logical_turn) {
            return Err(ProtocolError::Invalid("session.logical_turn"));
        }
        let mut turn_aliases = self.turn_aliases.clone();
        let upstream_turn_id = turn_aliases
            .entry(logical_turn.into())
            .or_insert_with(|| Uuid::new_v4().to_string())
            .clone();
        if turn_aliases.len() > MAX_ATTEMPTS {
            return Err(ProtocolError::Capacity("session.turns"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::Invalid("clock"))?
            .as_millis()
            .try_into()
            .map_err(|_| ProtocolError::Invalid("clock"))?;
        let projection = metadata::project(
            &metadata,
            &MetadataScope {
                account_id: &self.account_id,
                auth_revision: &self.auth_revision,
                installation_id: &self.installation_id,
                session_id: &self.session_id,
                thread_id: &self.thread_id,
                turn_id: &upstream_turn_id,
                window_id: &self.window_id,
                context_window_id: &self.context_window_id,
                window_number: self.window_number,
                turn_started_at_unix_ms: now,
                parent,
            },
        )?;
        let mut outbound = projection.headers;
        if let Some(sticky) = &self.sticky_turn_state {
            outbound.insert(
                "x-codex-turn-state",
                http::HeaderValue::from_str(sticky)
                    .map_err(|_| ProtocolError::Invalid("session.sticky"))?,
            );
        }
        self.turn_aliases = turn_aliases;
        self.generation += 1;
        self.last_activity_unix_ms = unix_ms();
        Ok(outbound)
    }
    pub fn prepare_request(
        &self,
        input: Value,
        headers: &HeaderMap,
        turn: &str,
    ) -> Result<PreparedRequest, ProtocolError> {
        self.prepare_request_with_parent(input, headers, turn, None)
    }
    pub fn prepare_request_with_parent(
        &self,
        mut input: Value,
        headers: &HeaderMap,
        turn: &str,
        parent: Option<&ParentMetadataProof>,
    ) -> Result<PreparedRequest, ProtocolError> {
        if self.attempts.len() >= MAX_ATTEMPTS {
            return Err(ProtocolError::Capacity("session.attempts"));
        }
        let metadata = metadata::classify_request(&input, headers)?;
        self.expand_history(&mut input)?;
        let client_input = input["input"]
            .as_array()
            .cloned()
            .ok_or(ProtocolError::Invalid("input"))?;
        if !bounded_identity(turn) {
            return Err(ProtocolError::Invalid("session.logical_turn"));
        }
        let mut turn_aliases = self.turn_aliases.clone();
        let upstream_turn_id = turn_aliases
            .entry(turn.into())
            .or_insert_with(|| Uuid::new_v4().to_string())
            .clone();
        if turn_aliases.len() > MAX_ATTEMPTS {
            return Err(ProtocolError::Capacity("session.turns"));
        }
        let parent_agent_cipher_sha256 = parent
            .filter(|parent| {
                parent.account_id == self.account_id
                    && parent.auth_revision == self.auth_revision
                    && metadata.client_parent_thread_id.is_some()
                    && metadata.role == metadata::TaskRole::Subagent
            })
            .map(|parent| &parent.agent_message_cipher_sha256);
        let (identities, mut request) = self.stage_request_with_parent_messages(
            input,
            &upstream_turn_id,
            parent_agent_cipher_sha256,
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ProtocolError::Invalid("clock"))?
            .as_millis();
        let projection = metadata::project(
            &metadata,
            &MetadataScope {
                account_id: &self.account_id,
                auth_revision: &self.auth_revision,
                installation_id: &self.installation_id,
                session_id: &self.session_id,
                thread_id: &self.thread_id,
                turn_id: &upstream_turn_id,
                window_id: &self.window_id,
                context_window_id: &self.context_window_id,
                window_number: self.window_number,
                turn_started_at_unix_ms: now
                    .try_into()
                    .map_err(|_| ProtocolError::Invalid("clock"))?,
                parent,
            },
        )?;
        request.body["client_metadata"] = projection.client_metadata;
        let mut outbound = projection.headers;
        if let Some(sticky) = &self.sticky_turn_state {
            outbound.insert(
                "x-codex-turn-state",
                http::HeaderValue::from_str(sticky)
                    .map_err(|_| ProtocolError::Invalid("session.sticky"))?,
            );
        }
        let attempt_id = Uuid::new_v4().to_string();
        let attempt = AttemptRecord {
            attempt_id,
            turn_id: turn.into(),
            upstream_turn_id,
            account_id: self.account_id.clone(),
            auth_revision: self.auth_revision.clone(),
            request_sha256: value_sha(&request.body)?,
            state: AttemptState::Prepared,
            response_id: None,
            terminal_sha256: None,
            input: client_input,
            is_compaction: request.is_compaction,
            delivered_events: Vec::new(),
            observed_output: Vec::new(),
        };
        self.check_history_budget(Some(&attempt))?;
        Ok(PreparedRequest {
            generation: self.generation,
            identities,
            request,
            headers: outbound,
            metadata,
            attempt,
            turn_aliases,
        })
    }
    pub fn commit_request(
        &mut self,
        prepared: PreparedRequest,
    ) -> Result<ScopedRequest, ProtocolError> {
        if prepared.generation != self.generation
            || prepared.attempt.account_id != self.account_id
            || prepared.attempt.auth_revision != self.auth_revision
        {
            return Err(ProtocolError::Invalid("session.stale_prepare"));
        }
        if self.attempts.len() >= MAX_ATTEMPTS
            || self.attempts.contains_key(&prepared.attempt.attempt_id)
        {
            return Err(ProtocolError::Capacity("session.attempts"));
        }
        self.check_history_budget(Some(&prepared.attempt))?;
        let attempt_id = prepared.attempt.attempt_id.clone();
        self.identities = prepared.identities;
        self.turn_aliases = prepared.turn_aliases;
        let upstream_turn_id = prepared.attempt.upstream_turn_id.clone();
        self.attempts.insert(attempt_id.clone(), prepared.attempt);
        self.generation += 1;
        self.switched = false;
        self.active_attempt = Some(attempt_id.clone());
        self.last_activity_unix_ms = unix_ms();
        Ok(ScopedRequest {
            request: prepared.request,
            outbound_headers: prepared.headers,
            metadata: prepared.metadata,
            attempt_id,
            upstream_turn_id,
        })
    }
    /// Must be persisted before a network send. Unknown is spent, never reset
    /// to Prepared by a GET, retry, process restart or account switch.
    pub fn mark_sending(&mut self, id: &str) -> Result<(), ProtocolError> {
        let a = self.current_attempt_mut(id)?;
        if a.state != AttemptState::Prepared {
            return Err(ProtocolError::Invalid("attempt.already_sent"));
        }
        a.state = AttemptState::Sending;
        self.generation += 1;
        Ok(())
    }
    pub fn mark_unknown(&mut self, id: &str) -> Result<(), ProtocolError> {
        let a = self.current_attempt_mut(id)?;
        if !matches!(
            a.state,
            AttemptState::Prepared | AttemptState::Sending | AttemptState::Unknown
        ) {
            return Err(ProtocolError::Invalid("attempt.terminal"));
        }
        a.state = AttemptState::Unknown;
        self.generation += 1;
        Ok(())
    }
    pub fn cancel_attempt(&mut self, id: &str) -> Result<(), ProtocolError> {
        let a = self.current_attempt_mut(id)?;
        if matches!(a.state, AttemptState::Completed | AttemptState::Failed) {
            return Err(ProtocolError::Invalid("attempt.terminal"));
        }
        a.state = AttemptState::Cancelled;
        self.generation += 1;
        Ok(())
    }
    fn current_attempt_mut(&mut self, id: &str) -> Result<&mut AttemptRecord, ProtocolError> {
        let a = self
            .attempts
            .get_mut(id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        if a.account_id != self.account_id || a.auth_revision != self.auth_revision {
            return Err(ProtocolError::Invalid("attempt.foreign_scope"));
        }
        Ok(a)
    }
    /// The event is the already-mapped actual upstream terminal, not a client
    /// supplied body. Completion does not establish downstream consumption.
    /// A source error proves failure but conveys no successful continuation,
    /// response history or cipher authority, even when it has no response id.
    pub fn fail_attempt(&mut self, id: &str, event: &Value) -> Result<(), ProtocolError> {
        if !matches!(event["type"].as_str(), Some("error" | "response.failed")) {
            return Err(ProtocolError::Invalid("attempt.error_event"));
        }
        self.fail_observed(id, value_sha(event)?)
    }
    /// An actual complete non-success HTTP response terminates the attempt;
    /// it grants no history or cipher provenance and is not a model event.
    pub fn fail_http_attempt(
        &mut self,
        id: &str,
        status: u16,
        body_sha: &str,
    ) -> Result<(), ProtocolError> {
        if !(300..=599).contains(&status) || !valid_sha(body_sha) {
            return Err(ProtocolError::Invalid("attempt.http_rejection"));
        }
        self.fail_observed(
            id,
            value_sha(&serde_json::json!(["http", status, body_sha]))?,
        )
    }
    fn fail_observed(&mut self, id: &str, terminal: String) -> Result<(), ProtocolError> {
        let a = self
            .attempts
            .get_mut(id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        if a.account_id != self.account_id || a.auth_revision != self.auth_revision {
            return Err(ProtocolError::Invalid("attempt.foreign_scope"));
        }
        if a.terminal_sha256.as_ref() == Some(&terminal) {
            return Ok(());
        }
        if !matches!(a.state, AttemptState::Sending | AttemptState::Unknown) {
            return Err(ProtocolError::Invalid("attempt.terminal"));
        }
        a.state = AttemptState::Failed;
        a.terminal_sha256 = Some(terminal);
        a.input.clear();
        self.generation += 1;
        self.last_activity_unix_ms = unix_ms();
        Ok(())
    }
    pub fn finish_attempt(&mut self, id: &str, event: &Value) -> Result<(), ProtocolError> {
        let a = self
            .attempts
            .get(id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?
            .clone();
        if a.account_id != self.account_id || a.auth_revision != self.auth_revision {
            return Err(ProtocolError::Invalid("attempt.foreign_scope"));
        }
        let terminal = value_sha(event)?;
        if a.terminal_sha256.as_ref() == Some(&terminal) {
            return Ok(());
        }
        if !matches!(a.state, AttemptState::Sending | AttemptState::Unknown) {
            return Err(ProtocolError::Invalid("attempt.terminal"));
        }
        let completed = match event["type"].as_str() {
            Some("response.completed") => true,
            Some("response.failed" | "response.incomplete") => false,
            _ => return Err(ProtocolError::Invalid("attempt.terminal_event")),
        };
        let response_id = event["response"]["id"]
            .as_str()
            .filter(|s| bounded_identity(s))
            .ok_or(ProtocolError::Invalid("attempt.response_id"))?
            .to_owned();
        if !self
            .identities
            .identifiers
            .contains_key(&(IdentityKind::Response, response_id.clone()))
        {
            return Err(ProtocolError::UnmappedIdentity("attempt.response_id"));
        }
        let mut history = a
            .input
            .iter()
            .filter(|v| v["type"] != "compaction_trigger")
            .cloned()
            .collect::<Vec<_>>();
        if completed {
            let output = event["response"]["output"]
                .as_array()
                .filter(|items| !items.is_empty())
                .unwrap_or(&a.observed_output)
                .iter()
                .cloned()
                .map(history_item)
                .collect::<Vec<_>>();
            // Native Codex accumulates OutputItemDone independently of the
            // completion envelope (client.rs::map_response_events). OAuth WS
            // completions may have output: []; retain the actual done items
            // for full-input continuation without altering that wire event.
            history.extend(output.iter().cloned());
            let mut response_histories = self.response_histories.clone();
            response_histories.insert(response_id.clone(), history.clone());
            let mut compaction_histories = self.compaction_histories.clone();
            if a.is_compaction {
                let compactions = output
                    .iter()
                    .filter(|v| v["type"] == "compaction")
                    .collect::<Vec<_>>();
                if compactions.len() != 1 {
                    return Err(ProtocolError::Invalid("v2.compaction_count"));
                }
                let cipher = compactions[0]["encrypted_content"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .ok_or(ProtocolError::Invalid("v2.compaction"))?;
                compaction_histories.insert(
                    cipher.into(),
                    a.input
                        .iter()
                        .filter(|v| v["type"] != "compaction_trigger")
                        .cloned()
                        .collect(),
                );
            }
            check_value_budget(
                &serde_json::json!([history, response_histories, compaction_histories]),
                MAX_HISTORY_BYTES,
                "session.history",
            )?;
            let mut material = event.clone();
            material["response"]["output"] = Value::Array(output.clone());
            self.commit_completed(&material)?;
            self.plaintext_history = history;
            self.response_histories = response_histories;
            self.compaction_histories = compaction_histories;
            if a.is_compaction {
                self.window_id = Uuid::new_v4().to_string();
                self.context_window_id = Uuid::new_v4().to_string();
                self.window_number = self.window_number.saturating_add(1);
            }
        }
        let a = self
            .attempts
            .get_mut(id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        a.state = if completed {
            AttemptState::Completed
        } else {
            AttemptState::Failed
        };
        a.response_id = Some(response_id);
        a.terminal_sha256 = Some(terminal);
        a.input.clear();
        self.generation += 1;
        self.last_activity_unix_ms = unix_ms();
        Ok(())
    }
    fn expand_history(&self, input: &mut Value) -> Result<(), ProtocolError> {
        let previous = input
            .get("previous_response_id")
            .filter(|v| !v.is_null() && *v != "")
            .map(|v| {
                v.as_str()
                    .ok_or(ProtocolError::Invalid("previous_response_id"))
            })
            .transpose()?;
        let delta = input["input"]
            .as_array()
            .ok_or(ProtocolError::Invalid("input"))?;
        let mut history = if let Some(previous) = previous {
            self.response_histories
                .get(previous)
                .map(|items| items.iter().cloned().map(history_item).collect())
                .ok_or(ProtocolError::UnmappedIdentity("previous_response_id"))?
        } else {
            Vec::new()
        };
        if self.switched
            && previous.is_none()
            && delta.first().is_some_and(|v| {
                matches!(
                    v["type"].as_str(),
                    Some("function_call_output" | "custom_tool_call_output" | "tool_search_output")
                )
            })
        {
            history = self
                .plaintext_history
                .iter()
                .cloned()
                .map(history_item)
                .collect();
        }
        for item in delta {
            if matches!(
                item["type"].as_str(),
                Some("compaction" | "context_compaction")
            ) && let Some(cipher) = item["encrypted_content"].as_str()
                && !self.verified_opaque.contains(cipher)
            {
                history.extend(
                    self.compaction_histories
                        .get(cipher)
                        .cloned()
                        .ok_or(ProtocolError::UnverifiedOpaque("input.compaction"))?,
                );
            } else {
                history.push(item.clone());
            }
        }
        check_value_budget(
            &Value::Array(history.clone()),
            MAX_HISTORY_BYTES,
            "session.history",
        )?;
        input["input"] = Value::Array(history);
        input
            .as_object_mut()
            .ok_or(ProtocolError::Invalid("request"))?
            .remove("previous_response_id");
        Ok(())
    }
    fn check_history_budget(&self, attempt: Option<&AttemptRecord>) -> Result<(), ProtocolError> {
        let current = self
            .attempts
            .values()
            .map(|a| (&a.input, &a.delivered_events, &a.observed_output))
            .collect::<Vec<_>>();
        check_value_budget(
            &serde_json::json!([
                self.plaintext_history,
                self.response_histories,
                self.compaction_histories,
                current,
                attempt.map(|a| &a.input)
            ]),
            MAX_HISTORY_BYTES,
            "session.history",
        )
    }
    pub fn switch_account(
        &mut self,
        account_id: String,
        auth_revision: String,
    ) -> Result<(), ProtocolError> {
        if !bounded_identity(&account_id) || !bounded_identity(&auth_revision) {
            return Err(ProtocolError::Invalid("session.account"));
        }
        if self.account_id == account_id && self.auth_revision == auth_revision {
            return Ok(());
        }
        for a in self.attempts.values_mut() {
            if matches!(a.state, AttemptState::Prepared | AttemptState::Sending) {
                a.state = AttemptState::Unknown;
            }
        }
        // Keep local tool signatures and readable history. No upstream ID,
        // cipher, resource, sticky state or cache token crosses the revision.
        self.identities.identifiers.clear();
        self.identities.upstream_to_client.clear();
        self.verified_opaque.clear();
        self.files.clear();
        self.realtime_calls.clear();
        self.sticky_turn_state = None;
        self.account_id = account_id;
        self.auth_revision = auth_revision;
        self.thread_id = Uuid::new_v4().to_string();
        self.session_id = Uuid::new_v4().to_string();
        self.installation_id = Uuid::new_v4().to_string();
        self.window_id = Uuid::new_v4().to_string();
        self.context_window_id = Uuid::new_v4().to_string();
        self.cache_key = Uuid::new_v4().to_string();
        self.turn_aliases.clear();
        self.window_number = 1;
        self.generation += 1;
        self.switched = true;
        Ok(())
    }
    /// The caller supplies an alias only after observing the actual OAuth call
    /// response. This registry carries resource identity, not send permission.
    pub fn register_realtime_call(
        &mut self,
        alias: String,
        upstream: String,
    ) -> Result<(), ProtocolError> {
        if !bounded_identity(&alias) || !bounded_identity(&upstream) || alias == upstream {
            return Err(ProtocolError::Invalid("realtime.call_identity"));
        }
        if let Some(prior) = self.realtime_calls.get(&alias) {
            return if prior.account_id == self.account_id
                && prior.auth_revision == self.auth_revision
                && prior.upstream_id == upstream
            {
                Ok(())
            } else {
                Err(ProtocolError::Invalid("realtime.call_identity_changed"))
            };
        }
        if self.realtime_calls.len() >= MAX_REALTIME_CALL_ROWS {
            return Err(ProtocolError::Capacity("realtime.calls"));
        }
        if self
            .realtime_calls
            .values()
            .any(|v| v.upstream_id == upstream)
        {
            return Err(ProtocolError::Invalid("realtime.call_alias_duplicate"));
        }
        self.realtime_calls.insert(
            alias,
            ScopedRealtimeCall {
                account_id: self.account_id.clone(),
                auth_revision: self.auth_revision.clone(),
                upstream_id: upstream,
            },
        );
        self.generation += 1;
        self.last_activity_unix_ms = unix_ms();
        Ok(())
    }
    pub fn realtime_call(&self, alias: &str) -> Option<&str> {
        self.realtime_calls
            .get(alias)
            .filter(|v| v.account_id == self.account_id && v.auth_revision == self.auth_revision)
            .map(|v| v.upstream_id.as_str())
    }
    pub fn observe_connection_sideband(
        &mut self,
        mut fact: ConnectionSideband,
    ) -> Result<(), ProtocolError> {
        if fact.account_id != self.account_id
            || fact.auth_revision != self.auth_revision
            || !bounded_identity(&fact.connection_id)
            || fact.frame_index == 0
            || !matches!(
                fact.kind.as_str(),
                "codex.response.metadata" | "codex.rate_limits" | "error"
            )
            || !valid_sha(&fact.raw_sha256)
            || fact.bytes == 0
            || fact.bytes > 256 * 1024
        {
            return Err(ProtocolError::Invalid("connection.sideband"));
        }
        if self.connection_sidebands.len() >= MAX_CONNECTION_SIDEBANDS {
            return Err(ProtocolError::Capacity("connection.sidebands"));
        }
        if self.connection_sidebands.iter().any(|old| {
            old.connection_id == fact.connection_id && old.frame_index >= fact.frame_index
        }) {
            return Err(ProtocolError::Invalid("connection.sideband_order"));
        }
        fact.client_socket_written = false;
        self.connection_sidebands.push(fact);
        self.generation += 1;
        Ok(())
    }
    pub fn connection_sideband_written(
        &mut self,
        connection: &str,
        index: u64,
        raw_sha: &str,
    ) -> Result<(), ProtocolError> {
        let fact = self
            .connection_sidebands
            .iter_mut()
            .find(|v| v.connection_id == connection && v.frame_index == index)
            .ok_or(ProtocolError::Invalid("connection.sideband_missing"))?;
        if fact.account_id != self.account_id
            || fact.auth_revision != self.auth_revision
            || fact.raw_sha256 != raw_sha
        {
            return Err(ProtocolError::Invalid("connection.sideband_write"));
        }
        fact.client_socket_written = true;
        self.generation += 1;
        Ok(())
    }
    pub fn connection_sidebands(&self) -> &[ConnectionSideband] {
        &self.connection_sidebands
    }
    pub fn register_file(&mut self, file: FileProvenance) -> Result<(), ProtocolError> {
        if file.account_id != self.account_id || file.auth_revision != self.auth_revision {
            return Err(ProtocolError::Invalid("file.foreign_scope"));
        }
        if !bounded_identity(&file.client_id)
            || !bounded_identity(&file.upstream_id)
            || !valid_sha(&file.content_sha256)
            || file.client_id == file.upstream_id
        {
            return Err(ProtocolError::Invalid("file.provenance"));
        }
        if let Some(existing) = self.files.get(&file.client_id) {
            return if existing == &file {
                Ok(())
            } else {
                Err(ProtocolError::Invalid("file.rebound"))
            };
        }
        if self.files.len() >= MAX_FILE_ROWS {
            return Err(ProtocolError::Capacity("session.files"));
        }
        let mut staged = self.identities.clone();
        staged.identifiers.insert(
            (IdentityKind::File, file.client_id.clone()),
            file.upstream_id.clone(),
        );
        staged.check_budget()?;
        self.identities = staged;
        self.files.insert(file.client_id.clone(), file);
        self.generation += 1;
        Ok(())
    }
    pub fn file(&self, id: &str) -> Option<&FileProvenance> {
        self.files.get(id)
    }
    pub fn set_sticky_from_upstream(
        &mut self,
        account: &str,
        revision: &str,
        value: String,
    ) -> Result<(), ProtocolError> {
        if account != self.account_id
            || revision != self.auth_revision
            || value.is_empty()
            || value.len() > 4096
            || http::HeaderValue::from_str(&value).is_err()
        {
            return Err(ProtocolError::Invalid("session.sticky"));
        }
        self.sticky_turn_state = Some(value);
        self.generation += 1;
        Ok(())
    }
    /// Records an actual downstream tool-item write, not client execution or
    /// model consumption. The key includes the logical turn so intentional
    /// identical calls in a later user turn are not globally suppressed.
    pub fn tool_delivery(
        &self,
        attempt: &str,
        item: &Value,
    ) -> Result<ToolDelivery, ProtocolError> {
        let (key, fingerprint) = self.tool_delivery_key(attempt, item)?;
        Ok(
            if self.delivered_tools.contains_key(&key)
                || self.suppressed_tools.contains_key(&key)
                || self.prior_delivery(attempt, &fingerprint).is_some()
            {
                ToolDelivery::AlreadyDelivered
            } else {
                ToolDelivery::Deliver
            },
        )
    }
    pub fn record_tool_delivery(
        &mut self,
        attempt: &str,
        item: &Value,
    ) -> Result<ToolDelivery, ProtocolError> {
        let (key, fingerprint) = self.tool_delivery_key(attempt, item)?;
        if self.delivered_tools.contains_key(&key) || self.suppressed_tools.contains_key(&key) {
            return Ok(ToolDelivery::AlreadyDelivered);
        }
        if self.delivered_tools.len() + self.suppressed_tools.len() >= MAX_IDENTITY_ROWS {
            return Err(ProtocolError::Capacity("session.deliveries"));
        }
        if let Some(prior) = self.prior_delivery(attempt, &fingerprint) {
            self.suppressed_tools.insert(key, (attempt.into(), prior));
            self.generation += 1;
            return Ok(ToolDelivery::AlreadyDelivered);
        }
        self.delivered_tools.insert(
            key,
            DeliveredTool {
                attempt_id: attempt.into(),
                fingerprint,
                item_sha256: value_sha(item)?,
            },
        );
        self.generation += 1;
        Ok(ToolDelivery::Deliver)
    }
    fn prior_delivery(&self, attempt: &str, fingerprint: &str) -> Option<String> {
        self.delivered_tools
            .iter()
            .find(|(key, record)| {
                record.attempt_id != attempt
                    && record.fingerprint == fingerprint
                    && !self
                        .suppressed_tools
                        .values()
                        .any(|(a, used)| a == attempt && used == *key)
            })
            .map(|(key, _)| key.clone())
    }
    fn tool_delivery_key(
        &self,
        attempt: &str,
        item: &Value,
    ) -> Result<(String, String), ProtocolError> {
        let a = self
            .attempts
            .get(attempt)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        if a.account_id != self.account_id
            || a.auth_revision != self.auth_revision
            || !matches!(a.state, AttemptState::Sending | AttemptState::Unknown)
        {
            return Err(ProtocolError::Invalid("delivery.scope"));
        }
        let signature =
            CallSignature::from_item(item)?.ok_or(ProtocolError::Invalid("delivery.tool"))?;
        let slot = if let Some(call) = item["call_id"].as_str() {
            if self.identities.observed_calls.get(call) != Some(&signature) {
                return Err(ProtocolError::UnmappedIdentity("delivery.call_id"));
            }
            call.to_owned()
        } else if matches!(signature.kind, CallKind::ToolSearch | CallKind::LocalShell) {
            // Official nullable-call items have no call reference. Their real
            // upstream item is a delivery slot only, not tool execution proof.
            let id = item["id"]
                .as_str()
                .ok_or(ProtocolError::Invalid("delivery.item_id"))?;
            let upstream = self
                .identities
                .identifiers
                .get(&(IdentityKind::Item, id.into()))
                .ok_or(ProtocolError::UnmappedIdentity("delivery.item_id"))?;
            if self
                .identities
                .upstream_to_client
                .get(&(IdentityKind::Item, upstream.clone()))
                .map(String::as_str)
                != Some(id)
            {
                return Err(ProtocolError::UnmappedIdentity("delivery.item_id"));
            }
            format!("item:{id}")
        } else {
            return Err(ProtocolError::Invalid("delivery.call_id"));
        };
        let content = match signature.kind {
            CallKind::Function => &item["arguments"],
            CallKind::Custom => &item["input"],
            CallKind::ToolSearch => &item["arguments"],
            CallKind::LocalShell => &item["action"],
        };
        let mut material = serde_json::json!([
            a.turn_id,
            item["type"],
            signature.name,
            signature.namespace,
            content
        ]);
        if signature.kind == CallKind::ToolSearch {
            material
                .as_array_mut()
                .ok_or(ProtocolError::Invalid("delivery.fingerprint"))?
                .push(item["execution"].clone());
        }
        let fingerprint = value_sha(&material)?;
        Ok((value_sha(&serde_json::json!([attempt, slot]))?, fingerprint))
    }

    pub fn record_delivery(&mut self, event: &Value) -> Result<ToolDelivery, ProtocolError> {
        let id = self
            .active_attempt
            .clone()
            .ok_or(ProtocolError::Invalid("delivery.attempt"))?;
        let a = self
            .attempts
            .get(&id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        if a.account_id != self.account_id
            || a.auth_revision != self.auth_revision
            || !matches!(a.state, AttemptState::Sending | AttemptState::Unknown)
        {
            return Err(ProtocolError::Invalid("delivery.scope"));
        }
        let tool = (event["type"] == "response.output_item.done")
            .then(|| event.get("item"))
            .flatten()
            .filter(|v| CallSignature::from_item(v).ok().flatten().is_some());
        let decision = if let Some(item) = tool {
            self.tool_delivery(&id, item)?
        } else {
            ToolDelivery::Deliver
        };
        if decision == ToolDelivery::AlreadyDelivered {
            if let Some(item) = tool {
                self.record_tool_delivery(&id, item)?;
            }
            return Ok(decision);
        }
        let mut events = a.delivered_events.clone();
        events.push(event.clone());
        check_value_budget(
            &serde_json::json!([a.input, events]),
            MAX_HISTORY_BYTES,
            "session.delivery",
        )?;
        if let Some(item) = tool {
            self.record_tool_delivery(&id, item)?;
        }
        self.attempts
            .get_mut(&id)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?
            .delivered_events = events;
        self.last_activity_unix_ms = unix_ms();
        self.generation += 1;
        Ok(decision)
    }
    /// Reconstructs only input and actual forwarded output. The root chooses a
    /// new attempt and account; this function never sends or executes a tool.
    pub fn continuation_request(
        &self,
        attempt: &str,
        mut original: Value,
    ) -> Result<Value, ProtocolError> {
        let a = self
            .attempts
            .get(attempt)
            .ok_or(ProtocolError::Invalid("attempt.missing"))?;
        let mut items = a.input.clone();
        let mut done = BTreeSet::new();
        let mut text = BTreeMap::<(u64, u64), String>::new();
        for event in &a.delivered_events {
            if event["type"] == "response.output_item.done" {
                let item = event
                    .get("item")
                    .ok_or(ProtocolError::Invalid("delivery.item"))?;
                if let Some(id) = item["id"].as_str()
                    && !done.insert(id.to_owned())
                {
                    continue;
                }
                if let Some(index) = event["output_index"].as_u64() {
                    text.retain(|(i, _), _| *i != index);
                }
                items.push(history_item(item.clone()));
            } else if event["type"] == "response.output_text.delta" {
                let index = event["output_index"].as_u64().unwrap_or(0);
                let content = event["content_index"].as_u64().unwrap_or(0);
                if let Some(delta) = event["delta"].as_str() {
                    text.entry((index, content)).or_default().push_str(delta);
                }
            }
        }
        for (_, value) in text {
            if !value.is_empty() {
                items.push(serde_json::json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":value}]}));
            }
        }
        check_value_budget(
            &Value::Array(items.clone()),
            MAX_HISTORY_BYTES,
            "session.history",
        )?;
        let object = original
            .as_object_mut()
            .ok_or(ProtocolError::Invalid("request"))?;
        object.insert("input".into(), Value::Array(items));
        for key in [
            "previous_response_id",
            "prompt_cache_key",
            "client_metadata",
        ] {
            object.remove(key);
        }
        Ok(original)
    }
    pub fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_activity_unix_ms) >= idle_ms
            && !self.attempts.values().any(|a| {
                matches!(
                    a.state,
                    AttemptState::Prepared | AttemptState::Sending | AttemptState::Unknown
                )
            })
    }

    /// Stage all input aliases, validate the entire protocol request, and only
    /// then commit. Rejected requests do not consume identity capacity.
    pub fn build_request(
        &mut self,
        input: Value,
        gateway_turn_id: &str,
    ) -> Result<BuiltRequest, ProtocolError> {
        let (staged, built) = self.stage_request(input, gateway_turn_id)?;
        self.identities = staged;
        self.generation += 1;
        Ok(built)
    }

    fn stage_request(
        &self,
        input: Value,
        gateway_turn_id: &str,
    ) -> Result<(IdentityState, BuiltRequest), ProtocolError> {
        self.stage_request_with_parent_messages(input, gateway_turn_id, None)
    }
    fn stage_request_with_parent_messages(
        &self,
        input: Value,
        gateway_turn_id: &str,
        parent_agent_cipher_sha256: Option<&BTreeSet<String>>,
    ) -> Result<(IdentityState, BuiltRequest), ProtocolError> {
        let mut staged = self.identities.clone();
        let items = input["input"]
            .as_array()
            .ok_or(ProtocolError::Invalid("input"))?;
        let mut declared = BTreeMap::<String, CallSignature>::new();
        for item in items {
            if let Some(signature) = CallSignature::from_item(item)? {
                if let Some(call) = item.get("call_id").filter(|value| !value.is_null()) {
                    let call = call
                        .as_str()
                        .ok_or(ProtocolError::Invalid("input.call_id"))?;
                    if declared
                        .get(call)
                        .or_else(|| staged.observed_calls.get(call))
                        .is_some_and(|prior| prior != &signature)
                    {
                        return Err(ProtocolError::Invalid("input.call_signature_changed"));
                    }
                    staged.map_local(IdentityKind::Call, call)?;
                    declared.insert(call.to_owned(), signature);
                }
            } else if matches!(
                item["type"].as_str(),
                Some("function_call_output" | "custom_tool_call_output" | "tool_search_output")
            ) && let Some(call) = item.get("call_id").filter(|value| !value.is_null())
            {
                let call = call
                    .as_str()
                    .ok_or(ProtocolError::Invalid("input.call_id"))?;
                let signature = declared
                    .get(call)
                    .ok_or(ProtocolError::UnmappedIdentity("input.call_id"))?;
                signature.validate_output(item)?;
                // An output is a reference, never a new call declaration.
                if !staged
                    .identifiers
                    .contains_key(&(IdentityKind::Call, call.to_owned()))
                {
                    return Err(ProtocolError::UnmappedIdentity("input.call_id"));
                }
            }
            if let Some(id) = item.get("id").filter(|value| !value.is_null()) {
                let id = id.as_str().ok_or(ProtocolError::Invalid("input.id"))?;
                staged.map_local_item(item["type"].as_str().unwrap_or("message"), id)?;
            }
        }
        staged.check_budget()?;
        let built = protocol::build_request_with_agent_messages(
            input,
            &RequestContext {
                gateway_thread_id: &self.thread_id,
                gateway_turn_id,
                cache_key: &self.cache_key,
                identifiers: &staged.identifiers,
                verified_opaque: &self.verified_opaque,
            },
            parent_agent_cipher_sha256.unwrap_or(&BTreeSet::new()),
        )?;
        Ok((staged, built))
    }

    /// Only protocol identity positions are rewritten. Tool arguments, schema,
    /// text and arbitrary output values are never recursively edited. The event
    /// and identity state are both unchanged if any check or budget fails.
    pub fn rewrite_event(&mut self, event: &mut Value) -> Result<(), ProtocolError> {
        let mut staged = self.identities.clone();
        let mut rewritten = event.clone();
        response_projection::project_event(&mut rewritten, |envelope, kind| {
            staged.rewrite_field(envelope, "item_id", IdentityKind::Item)?;
            staged.rewrite_field(envelope, "call_id", IdentityKind::Call)?;
            staged.rewrite_field(envelope, "response_id", IdentityKind::Response)?;
            staged.rewrite_field(envelope, "previous_response_id", IdentityKind::Response)?;
            if kind == ProtocolEnvelope::Event
                && let Some(item) = envelope.get_mut("item")
            {
                staged.rewrite_item(item)?;
            }
            if kind == ProtocolEnvelope::Response {
                staged.rewrite_field(envelope, "id", IdentityKind::Response)?;
                if let Some(output) = envelope.get_mut("output").and_then(Value::as_array_mut) {
                    for item in output {
                        staged.rewrite_item(item)?;
                    }
                }
            }
            Ok(())
        })?;
        staged.check_budget()?;
        let observed = if rewritten["type"] == "response.output_item.done" {
            self.active_attempt
                .as_ref()
                .and_then(|id| self.attempts.get(id))
                .filter(|a| {
                    a.account_id == self.account_id
                        && a.auth_revision == self.auth_revision
                        && matches!(a.state, AttemptState::Sending | AttemptState::Unknown)
                })
                .map(|a| {
                    let mut items = a.observed_output.clone();
                    if let Some(item) = rewritten.get("item") {
                        let id = item.get("id");
                        if let Some(index) = items
                            .iter()
                            .position(|v| id.is_some_and(|id| v.get("id") == Some(id)))
                        {
                            items[index] = history_item(item.clone());
                        } else {
                            items.push(history_item(item.clone()));
                        }
                    }
                    (a.attempt_id.clone(), items)
                })
        } else {
            None
        };
        if let Some((_, items)) = &observed {
            check_value_budget(
                &Value::Array(items.clone()),
                MAX_HISTORY_BYTES,
                "session.output",
            )?;
        }
        let created = if rewritten["type"] == "response.created" {
            self.active_attempt
                .as_ref()
                .and_then(|id| self.attempts.get(id))
                .filter(|a| {
                    a.account_id == self.account_id
                        && a.auth_revision == self.auth_revision
                        && a.state == AttemptState::Sending
                })
                .map(|a| {
                    let response = rewritten["response"]["id"]
                        .as_str()
                        .ok_or(ProtocolError::Invalid("upstream.response_created"))?;
                    if a.response_id
                        .as_deref()
                        .is_some_and(|prior| prior != response)
                    {
                        return Err(ProtocolError::Invalid("upstream.response_created_changed"));
                    }
                    Ok((a.attempt_id.clone(), response.to_owned()))
                })
                .transpose()?
        } else {
            None
        };
        self.identities = staged;
        *event = rewritten;
        if let Some((id, items)) = observed {
            self.attempts
                .get_mut(&id)
                .ok_or(ProtocolError::Invalid("attempt.missing"))?
                .observed_output = items;
        }
        if let Some((id, response)) = created {
            self.attempts
                .get_mut(&id)
                .ok_or(ProtocolError::Invalid("attempt.missing"))?
                .response_id = Some(response);
        }
        self.generation += 1;
        Ok(())
    }

    /// Only exact ciphertext in this session's actual completed output grants
    /// provenance. Partial, interrupted and foreign input grant nothing.
    pub fn commit_completed(&mut self, event: &Value) -> Result<(), ProtocolError> {
        if event["type"] != "response.completed" {
            return Ok(());
        }
        let mut staged = self.verified_opaque.clone();
        let mut bytes = staged.iter().map(String::len).sum::<usize>();
        if let Some(output) = event["response"]["output"].as_array() {
            for item in output {
                let mut ciphers = Vec::new();
                if matches!(
                    item["type"].as_str(),
                    Some("reasoning" | "compaction" | "context_compaction")
                ) && let Some(cipher) = item.get("encrypted_content").filter(|v| !v.is_null())
                {
                    ciphers.push(cipher);
                }
                if item["type"] == "function_call"
                    && let Some(args) = item.get("encrypted_function_args").filter(|v| !v.is_null())
                {
                    ciphers.extend(
                        args.as_array()
                            .ok_or(ProtocolError::Invalid("upstream.encrypted_function_args"))?,
                    );
                }
                if item["type"] == "agent_message"
                    && let Some(parts) = item["content"].as_array()
                {
                    ciphers.extend(
                        parts
                            .iter()
                            .filter(|v| v["type"] == "encrypted_content")
                            .filter_map(|v| v.get("encrypted_content")),
                    );
                }
                for cipher in ciphers {
                    let cipher = cipher
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .ok_or(ProtocolError::Invalid("upstream.encrypted_content"))?;
                    if cipher.len() > MAX_SINGLE_OPAQUE_BYTES {
                        return Err(ProtocolError::Capacity("session.opaque"));
                    }
                    if !staged.contains(cipher) {
                        bytes += cipher.len();
                        if bytes > MAX_OPAQUE_BYTES || staged.len() == MAX_OPAQUE_ITEMS {
                            return Err(ProtocolError::Capacity("session.opaque"));
                        }
                        staged.insert(cipher.to_owned());
                    }
                }
            }
        }
        self.verified_opaque = staged;
        Ok(())
    }

    pub fn parent_proof(
        &self,
        turn_id: Option<String>,
        response_id: Option<String>,
    ) -> Result<ParentMetadataProof, ProtocolError> {
        if !self.attempts.values().any(|a| {
            a.account_id == self.account_id
                && a.auth_revision == self.auth_revision
                && matches!(a.state, AttemptState::Sending | AttemptState::Completed)
        }) {
            return Err(ProtocolError::UnmappedIdentity("metadata.parent_thread"));
        }
        if let Some(id) = &response_id {
            let origin = self
                .attempts
                .values()
                .find(|a| {
                    a.response_id.as_ref() == Some(id)
                        && a.account_id == self.account_id
                        && a.auth_revision == self.auth_revision
                        && (a.state == AttemptState::Completed
                            && self.response_histories.contains_key(id)
                            || a.state == AttemptState::Sending
                                && self.active_attempt.as_ref() == Some(&a.attempt_id))
                })
                .ok_or(ProtocolError::UnmappedIdentity("metadata.parent_response"))?;
            if turn_id.as_ref().is_some_and(|turn| turn != &origin.turn_id) {
                return Err(ProtocolError::UnmappedIdentity("metadata.parent_turn"));
            }
        }
        let response_id = response_id
            .map(|id| {
                self.identities
                    .identifiers
                    .get(&(IdentityKind::Response, id))
                    .cloned()
                    .ok_or(ProtocolError::UnmappedIdentity("metadata.parent_response"))
            })
            .transpose()?;
        if turn_id.as_ref().is_some_and(|id| {
            !self.attempts.values().any(|a| {
                &a.turn_id == id
                    && a.account_id == self.account_id
                    && a.auth_revision == self.auth_revision
            })
        }) {
            return Err(ProtocolError::UnmappedIdentity("metadata.parent_turn"));
        }
        let turn_id = turn_id
            .map(|id| {
                self.turn_aliases
                    .get(&id)
                    .cloned()
                    .ok_or(ProtocolError::UnmappedIdentity("metadata.parent_turn"))
            })
            .transpose()?;
        let mut agent_message_cipher_sha256 = BTreeSet::new();
        for attempt in self.attempts.values().filter(|attempt| {
            attempt.account_id == self.account_id
                && attempt.auth_revision == self.auth_revision
                && matches!(
                    attempt.state,
                    AttemptState::Sending | AttemptState::Completed
                )
                && (attempt.state != AttemptState::Sending
                    || self.active_attempt.as_ref() == Some(&attempt.attempt_id))
                && response_id.as_ref().is_none_or(|upstream| {
                    attempt.response_id.as_ref().and_then(|alias| {
                        self.identities
                            .identifiers
                            .get(&(IdentityKind::Response, alias.clone()))
                    }) == Some(upstream)
                })
        }) {
            for item in &attempt.observed_output {
                if item["type"] != "function_call"
                    || item["namespace"] != "collaboration"
                    || !matches!(
                        item["name"].as_str(),
                        Some("spawn_agent" | "send_message" | "followup_task")
                    )
                    || !attempt.delivered_events.iter().any(|event| {
                        event["type"] == "response.output_item.done"
                            && history_item(event["item"].clone()) == *item
                    })
                {
                    continue;
                }
                let Some(arguments) = item["arguments"].as_str() else {
                    continue;
                };
                let Ok(arguments) = serde_json::from_str::<Value>(arguments) else {
                    continue;
                };
                let Some(message) = arguments["message"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                if message.len() > MAX_SINGLE_OPAQUE_BYTES {
                    return Err(ProtocolError::Capacity("parent.agent_message"));
                }
                agent_message_cipher_sha256
                    .insert(format!("{:x}", Sha256::digest(message.as_bytes())));
                if agent_message_cipher_sha256.len() > MAX_OPAQUE_ITEMS {
                    return Err(ProtocolError::Capacity("parent.agent_messages"));
                }
            }
        }
        Ok(ParentMetadataProof {
            account_id: self.account_id.clone(),
            auth_revision: self.auth_revision.clone(),
            thread_id: self.thread_id.clone(),
            root_turn_id: turn_id.clone(),
            turn_id,
            response_id,
            agent_message_cipher_sha256,
        })
    }

    pub fn snapshot(&self) -> Result<Value, ProtocolError> {
        let s = SessionSnapshot {
            version: 1,
            account_id: self.account_id.clone(),
            auth_revision: self.auth_revision.clone(),
            thread_id: self.thread_id.clone(),
            session_id: self.session_id.clone(),
            cache_key: self.cache_key.clone(),
            installation_id: self.installation_id.clone(),
            window_id: self.window_id.clone(),
            context_window_id: self.context_window_id.clone(),
            window_number: self.window_number,
            generation: self.generation,
            identifiers: self
                .identities
                .identifiers
                .iter()
                .map(|((k, a), b)| (*k, a.clone(), b.clone()))
                .collect(),
            upstream_to_client: self
                .identities
                .upstream_to_client
                .iter()
                .map(|((k, a), b)| (*k, a.clone(), b.clone()))
                .collect(),
            observed_calls: self.identities.observed_calls.clone(),
            verified_opaque: self.verified_opaque.clone(),
            attempts: self.attempts.clone(),
            plaintext_history: self.plaintext_history.clone(),
            response_histories: self.response_histories.clone(),
            compaction_histories: self.compaction_histories.clone(),
            files: self.files.clone(),
            delivered_tools: self.delivered_tools.clone(),
            sticky_turn_state: self.sticky_turn_state.clone(),
            switched: self.switched,
            active_attempt: self.active_attempt.clone(),
            last_activity_unix_ms: self.last_activity_unix_ms,
            turn_aliases: self.turn_aliases.clone(),
            suppressed_tools: self.suppressed_tools.clone(),
            realtime_calls: self.realtime_calls.clone(),
            connection_sidebands: self.connection_sidebands.clone(),
        };
        serde_json::to_value(s).map_err(|_| ProtocolError::Invalid("session.snapshot"))
    }
    /// The caller must load only a protected private state file. This restores
    /// identity data, not OAuth credentials or network-send permission.
    pub fn restore(value: Value) -> Result<Self, ProtocolError> {
        check_value_budget(&value, MAX_PERSISTENCE_BYTES, "session.snapshot")?;
        let s: SessionSnapshot = serde_json::from_value(value)
            .map_err(|_| ProtocolError::Invalid("session.snapshot"))?;
        if s.version != 1
            || s.window_number == 0
            || s.attempts.len() > MAX_ATTEMPTS
            || s.files.len() > MAX_FILE_ROWS
            || s.delivered_tools.len() + s.suppressed_tools.len() > MAX_IDENTITY_ROWS
            || s.turn_aliases.len() > MAX_ATTEMPTS
            || s.realtime_calls.len() > MAX_REALTIME_CALL_ROWS
            || s.connection_sidebands.len() > MAX_CONNECTION_SIDEBANDS
        {
            return Err(ProtocolError::Invalid("session.snapshot"));
        }
        for v in [
            &s.account_id,
            &s.auth_revision,
            &s.thread_id,
            &s.session_id,
            &s.cache_key,
            &s.installation_id,
            &s.window_id,
            &s.context_window_id,
        ] {
            if !bounded_identity(v) {
                return Err(ProtocolError::Invalid("session.snapshot_identity"));
            }
        }
        let map =
            |rows: Vec<(IdentityKind, String, String)>| -> Result<IdentifierMap, ProtocolError> {
                let mut out = IdentifierMap::new();
                for (kind, key, value) in rows {
                    if !bounded_identity(&key)
                        || !bounded_identity(&value)
                        || key == value
                        || out.insert((kind, key), value).is_some()
                    {
                        return Err(ProtocolError::Invalid("session.snapshot_map"));
                    }
                }
                Ok(out)
            };
        let identities = IdentityState {
            identifiers: map(s.identifiers)?,
            upstream_to_client: map(s.upstream_to_client)?,
            observed_calls: s.observed_calls,
        };
        identities.check_budget()?;
        for ((kind, upstream), client) in &identities.upstream_to_client {
            if identities.identifiers.get(&(*kind, client.clone())) != Some(upstream) {
                return Err(ProtocolError::Invalid("session.snapshot_inverse"));
            }
        }
        let opaque_bytes = s.verified_opaque.iter().map(String::len).sum::<usize>();
        if s.verified_opaque.len() > MAX_OPAQUE_ITEMS
            || opaque_bytes > MAX_OPAQUE_BYTES
            || s.verified_opaque
                .iter()
                .any(|c| c.is_empty() || c.len() > MAX_SINGLE_OPAQUE_BYTES)
        {
            return Err(ProtocolError::Capacity("session.opaque"));
        }
        for (id, file) in &s.files {
            if id != &file.client_id
                || file.account_id != s.account_id
                || file.auth_revision != s.auth_revision
                || !valid_sha(&file.content_sha256)
                || identities
                    .identifiers
                    .get(&(IdentityKind::File, id.clone()))
                    != Some(&file.upstream_id)
            {
                return Err(ProtocolError::Invalid("session.snapshot_file"));
            }
        }
        let mut realtime_upstream = BTreeSet::new();
        let mut sideband_indexes = BTreeMap::new();
        for fact in &s.connection_sidebands {
            if !bounded_identity(&fact.account_id)
                || !bounded_identity(&fact.auth_revision)
                || !bounded_identity(&fact.connection_id)
                || fact.frame_index == 0
                || !matches!(
                    fact.kind.as_str(),
                    "codex.response.metadata" | "codex.rate_limits" | "error"
                )
                || !valid_sha(&fact.raw_sha256)
                || fact.bytes == 0
                || fact.bytes > 256 * 1024
                || sideband_indexes
                    .insert(fact.connection_id.clone(), fact.frame_index)
                    .is_some_and(|old| old >= fact.frame_index)
            {
                return Err(ProtocolError::Invalid("session.snapshot_connection"));
            }
        }
        for (alias, call) in &s.realtime_calls {
            if !bounded_identity(alias)
                || !bounded_identity(&call.upstream_id)
                || alias == &call.upstream_id
                || call.account_id != s.account_id
                || call.auth_revision != s.auth_revision
                || !realtime_upstream.insert(call.upstream_id.clone())
            {
                return Err(ProtocolError::Invalid("session.snapshot_realtime_call"));
            }
        }
        let mut attempts = s.attempts;
        for (id, a) in &mut attempts {
            if id != &a.attempt_id
                || !bounded_identity(id)
                || !bounded_identity(&a.turn_id)
                || !bounded_identity(&a.upstream_turn_id)
                || !bounded_identity(&a.account_id)
                || !bounded_identity(&a.auth_revision)
                || !valid_sha(&a.request_sha256)
                || a.terminal_sha256.as_ref().is_some_and(|s| !valid_sha(s))
            {
                return Err(ProtocolError::Invalid("session.snapshot_attempt"));
            }
            if matches!(a.state, AttemptState::Prepared | AttemptState::Sending) {
                a.state = AttemptState::Unknown;
            }
        }
        if s.delivered_tools.iter().any(|(k, v)| {
            !valid_sha(k)
                || !valid_sha(&v.fingerprint)
                || !valid_sha(&v.item_sha256)
                || !attempts.contains_key(&v.attempt_id)
        }) || s.suppressed_tools.iter().any(|(key, (attempt, origin))| {
            !valid_sha(key)
                || !attempts.contains_key(attempt)
                || !s.delivered_tools.contains_key(origin)
        }) || s
            .turn_aliases
            .iter()
            .any(|(key, value)| !bounded_identity(key) || !bounded_identity(value) || key == value)
            || s.sticky_turn_state.as_ref().is_some_and(|s| {
                s.is_empty() || s.len() > 4096 || http::HeaderValue::from_str(s).is_err()
            })
        {
            return Err(ProtocolError::Invalid("session.snapshot_delivery"));
        }
        if s.active_attempt
            .as_ref()
            .is_some_and(|id| !attempts.contains_key(id))
        {
            return Err(ProtocolError::Invalid("session.snapshot_active"));
        }
        let out = Self {
            account_id: s.account_id,
            auth_revision: s.auth_revision,
            thread_id: s.thread_id,
            session_id: s.session_id,
            cache_key: s.cache_key,
            installation_id: s.installation_id,
            window_id: s.window_id,
            context_window_id: s.context_window_id,
            window_number: s.window_number,
            generation: s
                .generation
                .checked_add(1)
                .ok_or(ProtocolError::Capacity("session.generation"))?,
            identities,
            verified_opaque: s.verified_opaque,
            attempts,
            plaintext_history: s.plaintext_history,
            response_histories: s.response_histories,
            compaction_histories: s.compaction_histories,
            files: s.files,
            delivered_tools: s.delivered_tools,
            sticky_turn_state: s.sticky_turn_state,
            switched: s.switched,
            active_attempt: s.active_attempt,
            last_activity_unix_ms: s.last_activity_unix_ms,
            turn_aliases: s.turn_aliases,
            suppressed_tools: s.suppressed_tools,
            realtime_calls: s.realtime_calls,
            connection_sidebands: s.connection_sidebands,
        };
        out.check_history_budget(None)?;
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSnapshot {
    version: u8,
    account_id: String,
    auth_revision: String,
    thread_id: String,
    session_id: String,
    cache_key: String,
    installation_id: String,
    window_id: String,
    context_window_id: String,
    window_number: u64,
    generation: u64,
    identifiers: Vec<(IdentityKind, String, String)>,
    upstream_to_client: Vec<(IdentityKind, String, String)>,
    observed_calls: BTreeMap<String, CallSignature>,
    verified_opaque: BTreeSet<String>,
    attempts: BTreeMap<String, AttemptRecord>,
    plaintext_history: Vec<Value>,
    response_histories: BTreeMap<String, Vec<Value>>,
    compaction_histories: BTreeMap<String, Vec<Value>>,
    files: BTreeMap<String, FileProvenance>,
    delivered_tools: BTreeMap<String, DeliveredTool>,
    sticky_turn_state: Option<String>,
    switched: bool,
    active_attempt: Option<String>,
    last_activity_unix_ms: u64,
    turn_aliases: BTreeMap<String, String>,
    suppressed_tools: BTreeMap<String, (String, String)>,
    #[serde(default)]
    realtime_calls: BTreeMap<String, ScopedRealtimeCall>,
    #[serde(default)]
    connection_sidebands: Vec<ConnectionSideband>,
}
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}
fn value_sha(v: &Value) -> Result<String, ProtocolError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).map_err(|_| ProtocolError::Invalid("serialization"))?)
    ))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn check_value_budget(v: &Value, limit: usize, field: &'static str) -> Result<(), ProtocolError> {
    if serde_json::to_vec(v)
        .map_err(|_| ProtocolError::Invalid("serialization"))?
        .len()
        > limit
    {
        Err(ProtocolError::Capacity(field))
    } else {
        Ok(())
    }
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, Arc<AsyncMutex<Session>>>>,
    capacity: usize,
}
impl Default for SessionStore {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            capacity: MAX_SESSIONS,
        }
    }
}

impl SessionStore {
    /// Resolve an already registered hashed native turn from the existing
    /// cache/protected snapshots. No client ID or second identity index is
    /// persisted. Ambiguous owners fail rather than selecting the first row.
    pub(crate) fn image_scope_for_turn(
        &self,
        logical_turn: &str,
        scope_directory: &Path,
    ) -> Result<Option<crate::images_scope::RegisteredImageScope>, ProtocolError> {
        let mut keys = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::Invalid("session.store_lock"))?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for entry in std::fs::read_dir(scope_directory)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?
        {
            let entry = entry.map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let key = path
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|key| valid_sha(key))
                .ok_or(ProtocolError::Invalid("session.persistence_key"))?;
            keys.insert(key.into());
            if keys.len() > self.capacity {
                return Err(ProtocolError::Capacity("session.store"));
            }
        }
        let mut found = None;
        for key in keys {
            let current = self.get(&key);
            let owner = if let Some(arc) = &current
                && let Ok(session) = arc.try_lock()
            {
                session
                    .has_registered_image_turn(logical_turn)
                    .then(|| (session.account_id.clone(), session.auth_revision.clone()))
            } else {
                let bytes = private_read(&scope_directory.join(format!("{key}.json")))?;
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
                let object = value
                    .as_object()
                    .filter(|v| v.len() == 2 && v.get("key").and_then(Value::as_str) == Some(&key))
                    .ok_or(ProtocolError::Invalid("session.persistence_key"))?;
                let raw = object
                    .get("session")
                    .ok_or(ProtocolError::Invalid("session.persistence"))?;
                let mut session = Session::restore(raw.clone())?;
                // Only a busy live Arc preserves its persisted Sending marker.
                // A restarted unresolved send remains Unknown and is rejected.
                if current.is_some() {
                    let original: SessionSnapshot = serde_json::from_value(raw.clone())
                        .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
                    if let Some(id) = original.active_attempt
                        && let Some(old) = original.attempts.get(&id)
                        && old.state == AttemptState::Sending
                        && old.account_id == session.account_id
                        && old.auth_revision == session.auth_revision
                        && let Some(attempt) = session.attempts.get_mut(&id)
                    {
                        attempt.state = AttemptState::Sending;
                    }
                }
                session
                    .has_registered_image_turn(logical_turn)
                    .then(|| (session.account_id.clone(), session.auth_revision.clone()))
            };
            if let Some((account_id, auth_revision)) = owner {
                if found.is_some() {
                    return Err(ProtocolError::Invalid("image.turn_scope_ambiguous"));
                }
                let session = current
                    .or(self.get_or_load_scope(&key, scope_directory)?)
                    .ok_or(ProtocolError::Invalid("image.turn_scope_missing"))?;
                found = Some(crate::images_scope::RegisteredImageScope {
                    key,
                    session,
                    account_id,
                    auth_revision,
                    logical_turn: logical_turn.into(),
                });
            }
        }
        Ok(found)
    }
    pub fn with_capacity(capacity: usize) -> Result<Self, ProtocolError> {
        if capacity == 0 || capacity > MAX_SESSION_CAPACITY {
            return Err(ProtocolError::Capacity("session.store_capacity"));
        }
        Ok(Self {
            sessions: Mutex::new(HashMap::new()),
            capacity,
        })
    }
    pub fn insert_restored(&self, key: String, session: Session) -> Result<(), ProtocolError> {
        if !valid_sha(&key) {
            return Err(ProtocolError::Invalid("session.persistence_key"));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::Invalid("session.store_lock"))?;
        if sessions.contains_key(&key) {
            return Err(ProtocolError::Invalid("session.already_loaded"));
        }
        if sessions.len() >= self.capacity {
            return Err(ProtocolError::Capacity("session.store"));
        }
        sessions.insert(key, Arc::new(AsyncMutex::new(session)));
        Ok(())
    }
    /// Load a protected per-scope snapshot once. Concurrent readers converge
    /// on the existing Arc and never overwrite a live session with old disk state.
    pub fn get_or_load_scope(
        &self,
        key: &str,
        scope_directory: &Path,
    ) -> Result<Option<Arc<AsyncMutex<Session>>>, ProtocolError> {
        if !valid_sha(key) {
            return Err(ProtocolError::Invalid("session.persistence_key"));
        }
        if let Some(session) = self.get(key) {
            return Ok(Some(session));
        }
        let path = scope_directory.join(format!("{key}.json"));
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ProtocolError::Invalid("session.persistence_io")),
            Ok(_) => {}
        }
        let bytes = private_read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
        let object = value
            .as_object()
            .filter(|v| v.len() == 2 && v.get("key").and_then(Value::as_str) == Some(key))
            .ok_or(ProtocolError::Invalid("session.persistence_key"))?;
        let restored = Session::restore(
            object
                .get("session")
                .ok_or(ProtocolError::Invalid("session.persistence"))?
                .clone(),
        )?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::Invalid("session.store_lock"))?;
        if let Some(existing) = sessions.get(key) {
            return Ok(Some(existing.clone()));
        }
        if sessions.len() >= self.capacity {
            return Err(ProtocolError::Capacity("session.store"));
        }
        let restored = Arc::new(AsyncMutex::new(restored));
        sessions.insert(key.into(), restored.clone());
        Ok(Some(restored))
    }
    /// Returns only the local persisted owner. Callers still compare the actual
    /// account revision before using it to choose a parent-bound upstream.
    pub fn scope_owner(
        &self,
        key: &str,
        scope_directory: &Path,
    ) -> Result<Option<(String, String)>, ProtocolError> {
        let Some(arc) = self.get_or_load_scope(key, scope_directory)? else {
            return Ok(None);
        };
        if let Ok(session) = arc.try_lock() {
            return Ok(Some((
                session.account_id.clone(),
                session.auth_revision.clone(),
            )));
        }
        let bytes = private_read(&scope_directory.join(format!("{key}.json")))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
        let object = value
            .as_object()
            .filter(|v| v.len() == 2 && v.get("key").and_then(Value::as_str) == Some(key))
            .ok_or(ProtocolError::Invalid("session.persistence_key"))?;
        let snapshot = Session::restore(
            object
                .get("session")
                .ok_or(ProtocolError::Invalid("session.persistence"))?
                .clone(),
        )?;
        Ok(Some((snapshot.account_id, snapshot.auth_revision)))
    }
    pub fn parent_proof(
        &self,
        namespace: &str,
        parent_local_thread: &str,
        account: &str,
        revision: &str,
    ) -> Option<ParentMetadataProof> {
        self.parent_proof_for_response(namespace, parent_local_thread, account, revision, None)
    }
    pub fn parent_proof_for_response(
        &self,
        namespace: &str,
        parent_local_thread: &str,
        account: &str,
        revision: &str,
        response_alias: Option<String>,
    ) -> Option<ParentMetadataProof> {
        let parent = self.get(&Self::local_key(namespace, parent_local_thread))?;
        let session = parent.try_lock().ok()?;
        if session.account_id != account || session.auth_revision != revision {
            return None;
        }
        session.parent_proof(None, response_alias).ok()
    }
    /// Busy parents are read only from the gateway's protected persisted scope.
    /// The retained Sending fact grants metadata lineage, never replay authority.
    pub fn parent_proof_from_file(
        &self,
        namespace: &str,
        parent_local_thread: &str,
        account: &str,
        revision: &str,
        response_alias: Option<String>,
        scope_directory: &Path,
    ) -> Option<ParentMetadataProof> {
        let key = Self::local_key(namespace, parent_local_thread);
        let _registered = self.get_or_load_scope(&key, scope_directory).ok()??;
        let bytes = private_read(&scope_directory.join(format!("{key}.json"))).ok()?;
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        let object = value
            .as_object()
            .filter(|o| o.len() == 2 && o.get("key") == Some(&Value::String(key)))?;
        let raw = object.get("session")?;
        let mut session = Session::restore(raw.clone()).ok()?;
        if session.account_id != account || session.auth_revision != revision {
            return None;
        }
        // Restore has already checked the entire private snapshot and changed
        // unresolved sends to Unknown. Only this local read retains original
        // Sending for exact metadata lookup; this Session is never returned.
        let original: SessionSnapshot = serde_json::from_value(raw.clone()).ok()?;
        if let Some(id) = original.active_attempt {
            let old = original.attempts.get(&id)?;
            if old.state == AttemptState::Sending
                && old.account_id == account
                && old.auth_revision == revision
            {
                let attempt = session.attempts.get_mut(&id)?;
                attempt.state = AttemptState::Sending;
            }
        }
        session.parent_proof(None, response_alias).ok()
    }
    /// Explicit cache eviction requires the protected per-scope file to match
    /// the current snapshot. The persistent file remains; active/unknown sends
    /// are never evicted or automatically resent on a later reload.
    pub fn evict_idle_persisted(
        &self,
        key: &str,
        path: &Path,
        now_ms: u64,
        idle_ms: u64,
    ) -> Result<bool, ProtocolError> {
        let Some(arc) = self.get(key) else {
            return Ok(false);
        };
        let Ok(session) = arc.try_lock() else {
            return Ok(false);
        };
        if !session.is_idle(now_ms, idle_ms) {
            return Ok(false);
        }
        let original: Value = serde_json::from_slice(&private_read(path)?)
            .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
        if original["key"] != key
            || original["session"] != session.snapshot()?
            || original.as_object().is_none_or(|o| o.len() != 2)
        {
            return Err(ProtocolError::Invalid("session.persisted_snapshot_changed"));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::Invalid("session.store_lock"))?;
        if !sessions
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, &arc))
        {
            return Err(ProtocolError::Invalid("session.store_changed"));
        }
        sessions.remove(key);
        Ok(true)
    }
    pub fn local_key(client_namespace: &str, client_thread: &str) -> String {
        let mut digest = Sha256::new();
        for part in [client_namespace, client_thread] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
        format!("{:x}", digest.finalize())
    }

    pub fn get(&self, key: &str) -> Option<Arc<AsyncMutex<Session>>> {
        self.sessions.lock().ok()?.get(key).cloned()
    }

    pub fn get_or_insert(
        &self,
        key: String,
        account_id: String,
        auth_revision: String,
    ) -> Option<Arc<AsyncMutex<Session>>> {
        let mut sessions = self.sessions.lock().ok()?;
        if let Some(existing) = sessions.get(&key) {
            return Some(existing.clone());
        }
        if sessions.len() >= self.capacity {
            return None;
        }
        let session = Arc::new(AsyncMutex::new(Session::new(account_id, auth_revision)));
        sessions.insert(key, session.clone());
        Some(session)
    }

    pub async fn save(&self, path: &Path) -> Result<(), ProtocolError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| ProtocolError::Invalid("session.store_lock"))?
            .iter()
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect::<Vec<_>>();
        let mut rows = BTreeMap::new();
        for (key, session) in sessions {
            rows.insert(key, session.lock().await.snapshot()?);
        }
        let material = serde_json::to_vec(&serde_json::json!({"version":1,"sessions":rows}))
            .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
        if material.len() > MAX_PERSISTENCE_BYTES {
            return Err(ProtocolError::Capacity("session.persistence"));
        }
        private_write(path, &material)
    }
    pub fn load(path: &Path) -> Result<Self, ProtocolError> {
        let material = private_read(path)?;
        let value: Value = serde_json::from_slice(&material)
            .map_err(|_| ProtocolError::Invalid("session.persistence"))?;
        let o = value
            .as_object()
            .filter(|o| o.len() == 2 && o.get("version") == Some(&serde_json::json!(1)))
            .ok_or(ProtocolError::Invalid("session.persistence"))?;
        let rows = o
            .get("sessions")
            .and_then(Value::as_object)
            .ok_or(ProtocolError::Invalid("session.persistence"))?;
        if rows.len() > MAX_SESSIONS {
            return Err(ProtocolError::Capacity("session.store"));
        }
        let mut sessions = HashMap::new();
        for (key, value) in rows {
            if !valid_sha(key) {
                return Err(ProtocolError::Invalid("session.persistence_key"));
            }
            sessions.insert(
                key.clone(),
                Arc::new(AsyncMutex::new(Session::restore(value.clone())?)),
            );
        }
        Ok(Self {
            sessions: Mutex::new(sessions),
            capacity: MAX_SESSIONS,
        })
    }
}

#[cfg(unix)]
fn private_parent(path: &Path) -> Result<std::fs::Metadata, ProtocolError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(ProtocolError::Invalid("session.persistence_path"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    }
    let meta = std::fs::symlink_metadata(parent)
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    if !meta.is_dir() || meta.file_type().is_symlink() || meta.mode() & 0o777 != 0o700 {
        return Err(ProtocolError::Invalid("session.persistence_custody"));
    }
    Ok(meta)
}
#[cfg(unix)]
fn private_write(path: &Path, material: &[u8]) -> Result<(), ProtocolError> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = private_parent(path)?;
    if path.exists() {
        let old = std::fs::symlink_metadata(path)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        if !old.is_file()
            || old.file_type().is_symlink()
            || old.mode() & 0o777 != 0o600
            || old.nlink() != 1
            || old.uid() != parent.uid()
        {
            return Err(ProtocolError::Invalid("session.persistence_custody"));
        }
    }
    let tmp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        file.write_all(material)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        file.sync_all()
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        std::fs::rename(&tmp, path)
            .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        std::fs::File::open(
            path.parent()
                .ok_or(ProtocolError::Invalid("session.persistence_path"))?,
        )
        .and_then(|f| f.sync_all())
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
#[cfg(unix)]
fn private_read(path: &Path) -> Result<Vec<u8>, ProtocolError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let parent = private_parent(path)?;
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.uid() != parent.uid()
        || before.len() > MAX_PERSISTENCE_BYTES as u64
    {
        return Err(ProtocolError::Invalid("session.persistence_custody"));
    }
    let mut file =
        std::fs::File::open(path).map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    let opened = file
        .metadata()
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(ProtocolError::Invalid("session.persistence_changed"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PERSISTENCE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    let after = file
        .metadata()
        .map_err(|_| ProtocolError::Invalid("session.persistence_io"))?;
    if bytes.len() > MAX_PERSISTENCE_BYTES
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err(ProtocolError::Invalid("session.persistence_changed"));
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn private_write(_: &Path, _: &[u8]) -> Result<(), ProtocolError> {
    Err(ProtocolError::Unsupported(
        "session.persistence.platform".into(),
    ))
}
#[cfg(not(unix))]
fn private_read(_: &Path) -> Result<Vec<u8>, ProtocolError> {
    Err(ProtocolError::Unsupported(
        "session.persistence.platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(items: Value) -> Value {
        json!({"model":"test","input":items})
    }

    fn key(kind: IdentityKind, label: &str) -> (IdentityKind, String) {
        (kind, label.to_owned())
    }

    fn call(label: &str) -> Value {
        json!({"type":"function_call","id":label,"call_id":label,"name":"run","arguments":"{}"})
    }

    #[test]
    fn completed_output_text_uses_official_decoded_history_without_backend_logprobs() {
        let mut session = Session::new("pool-a".into(), "revision-a".into());
        let prepared = session
            .prepare_request(
                request(json!([{"role":"user","content":"first"}])),
                &HeaderMap::new(),
                "logical-first",
            )
            .unwrap();
        let scoped = session.commit_request(prepared).unwrap();
        session.mark_sending(&scoped.attempt_id).unwrap();
        let mut event = json!({"type":"response.completed","response":{
            "id":"resp-upstream","output":[{"type":"message","id":"msg-upstream",
                "role":"assistant","metadata":{"backend":"warehouse-only"},
                "content":[{"type":"output_text","text":"answer","logprobs":[],
                    "annotations":[{"type":"citation","id":"raw-only"}]}]}]}});
        session.rewrite_event(&mut event).unwrap();
        let delivered = event.clone();
        session.finish_attempt(&scoped.attempt_id, &event).unwrap();
        assert_eq!(
            delivered["response"]["output"][0]["content"][0]["logprobs"],
            json!([])
        );
        let history = session.history();
        assert_eq!(
            history[1]["content"][0],
            json!({"type":"output_text","text":"answer"})
        );
        assert!(history[1].get("metadata").is_none());

        let mut next = request(json!([{"role":"user","content":"next"}]));
        next["previous_response_id"] = delivered["response"]["id"].clone();
        let continuation = session
            .prepare_request(next, &HeaderMap::new(), "logical-next")
            .unwrap();
        assert_eq!(
            continuation.request.body["input"][1]["content"][0],
            json!({"type":"output_text","text":"answer"})
        );
    }

    #[test]
    fn observed_call_roundtrip_preserves_only_own_upstream_reference() {
        let mut session = Session::new("a".into(), "rev-a".into());
        let mut event = json!({"type":"response.output_item.done","item":{"type":"function_call","id":"fc_upstream","call_id":"call_upstream","name":"run","arguments":"{\"id\":\"user-content\"}"}});
        session.rewrite_event(&mut event).unwrap();
        assert_eq!(event["item"]["arguments"], "{\"id\":\"user-content\"}");
        let alias = event["item"]["call_id"].as_str().unwrap();
        let output = json!({"type":"function_call_output","call_id":alias,"output":"ok"});
        assert_eq!(
            session
                .build_request(request(json!([output.clone()])), "orphan")
                .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
        let built = session
            .build_request(request(json!([event["item"].clone(), output])), "turn")
            .unwrap();
        assert_eq!(built.body["input"][0]["call_id"], "call_upstream");
        assert_eq!(built.body["input"][1]["call_id"], "call_upstream");
        assert_ne!(event["item"]["id"], "fc_upstream");
    }

    #[test]
    fn orphan_reversed_and_wrong_kind_outputs_are_rejected_without_aliases() {
        let mut session = Session::new("a".into(), "rev".into());
        let output = json!({"type":"function_call_output","call_id":"orphan","output":"ok"});
        assert_eq!(
            session
                .build_request(request(json!([output.clone()])), "turn")
                .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
        assert_eq!(
            session
                .build_request(request(json!([output, call("orphan")])), "turn")
                .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
        assert!(session.identifiers().is_empty());
        let wrong = json!({"type":"custom_tool_call_output","call_id":"same","output":"ok"});
        assert_eq!(
            session
                .build_request(request(json!([call("same"), wrong])), "turn")
                .unwrap_err(),
            ProtocolError::Invalid("input.call_output_kind")
        );
        assert!(session.identifiers().is_empty());
    }

    #[test]
    fn full_input_call_declaration_does_not_authorize_later_orphan_output() {
        let mut session = Session::new("a".into(), "rev".into());
        let built = session.build_request(request(json!([call("same"), {"type":"function_call_output","call_id":"same","output":"ok"}])), "turn").unwrap();
        assert_eq!(
            built.body["input"][0]["call_id"],
            built.body["input"][1]["call_id"]
        );
        assert_ne!(
            built.body["input"][0]["id"],
            built.body["input"][0]["call_id"]
        );
        assert_eq!(
            session
                .build_request(
                    request(
                        json!([{"type":"function_call_output","call_id":"same","output":"later"}])
                    ),
                    "turn2"
                )
                .unwrap_err(),
            ProtocolError::UnmappedIdentity("input.call_id")
        );
    }

    #[test]
    fn invalid_request_rolls_back_all_staged_identity_entries() {
        let mut session = Session::new("a".into(), "rev".into());
        let mut input = request(json!([call("fresh")]));
        input["temperature"] = json!(1);
        assert!(matches!(
            session.build_request(input, "turn"),
            Err(ProtocolError::Unsupported(_))
        ));
        assert!(session.identifiers().is_empty());
        assert!(session.identities.observed_calls.is_empty());
        assert!(session.identities.upstream_to_client.is_empty());
    }

    #[test]
    fn identical_upstream_item_call_response_labels_get_distinct_namespaces() {
        let mut session = Session::new("a".into(), "rev".into());
        let mut event = json!({"type":"response.completed","response":{"id":"same","output":[{"type":"function_call","id":"same","call_id":"same","name":"run","arguments":"{}"}]}});
        session.rewrite_event(&mut event).unwrap();
        let response = event["response"]["id"].as_str().unwrap();
        let item = event["response"]["output"][0]["id"].as_str().unwrap();
        let call = event["response"]["output"][0]["call_id"].as_str().unwrap();
        assert_ne!(response, item);
        assert_ne!(item, call);
        assert_eq!(
            session.identifiers()[&key(IdentityKind::Response, response)],
            "same"
        );
        assert_eq!(
            session.identifiers()[&key(IdentityKind::Item, item)],
            "same"
        );
        assert_eq!(
            session.identifiers()[&key(IdentityKind::Call, call)],
            "same"
        );
        assert!(
            !session
                .identifiers()
                .contains_key(&key(IdentityKind::File, call))
        );
    }

    #[test]
    fn account_and_revision_changes_create_disjoint_identities() {
        let mut a = Session::new("a".into(), "rev-a".into());
        let mut event = json!({"type":"response.output_item.done","item":{"type":"function_call","id":"fc","call_id":"call","name":"run","arguments":"{}"}});
        a.rewrite_event(&mut event).unwrap();
        let alias = event["item"]["call_id"].clone();
        for (account, revision) in [("b", "rev-b"), ("a", "rev-new")] {
            let mut b = Session::new(account.into(), revision.into());
            assert_ne!(a.thread_id, b.thread_id);
            assert_ne!(a.session_id, b.session_id);
            assert_ne!(a.cache_key, b.cache_key);
            assert!(b.identifiers().is_empty());
            assert!(b.verified_opaque.is_empty());
            assert_eq!(
                b.build_request(
                    request(
                        json!([{"type":"function_call_output","call_id":alias,"output":"old"}])
                    ),
                    "turn"
                )
                .unwrap_err(),
                ProtocolError::UnmappedIdentity("input.call_id")
            );
        }
        assert_ne!(
            SessionStore::local_key("ab", "c"),
            SessionStore::local_key("a", "bc")
        );
    }

    #[test]
    fn session_capacity_rejects_new_keys_without_evicting_existing_sessions() {
        let store = SessionStore::default();
        let first = store
            .get_or_insert("first".into(), "a".into(), "rev".into())
            .unwrap();
        for index in 1..MAX_SESSIONS {
            assert!(
                store
                    .get_or_insert(index.to_string(), "a".into(), "rev".into())
                    .is_some()
            );
        }
        assert!(
            store
                .get_or_insert("overflow".into(), "a".into(), "rev".into())
                .is_none()
        );
        assert!(Arc::ptr_eq(
            &first,
            &store
                .get_or_insert("first".into(), "other".into(), "other-rev".into())
                .unwrap()
        ));
    }

    #[test]
    fn identity_capacity_is_atomic_for_request_and_response_aliases() {
        let mut session = Session::new("a".into(), "rev".into());
        for index in 0..MAX_IDENTITY_ROWS {
            session.identities.identifiers.insert(
                key(IdentityKind::Item, &index.to_string()),
                format!("item_{index}"),
            );
        }
        let before = session.identifiers().clone();
        assert_eq!(
            session
                .build_request(
                    request(json!([{"id":"fresh","role":"user","content":"hi"}])),
                    "turn"
                )
                .unwrap_err(),
            ProtocolError::Capacity("session.identities")
        );
        assert_eq!(session.identifiers(), &before);
        let mut event = json!({"type":"response.created","response":{"id":"fresh"}});
        let original = event.clone();
        assert_eq!(
            session.rewrite_event(&mut event).unwrap_err(),
            ProtocolError::Capacity("session.identities")
        );
        assert_eq!(event, original);
        assert!(session.identities.upstream_to_client.is_empty());
        assert_eq!(session.identifiers(), &before);
    }

    #[test]
    fn opacity_requires_completed_and_capacity_failure_is_atomic() {
        let mut session = Session::new("a".into(), "rev".into());
        for kind in ["response.output_item.done", "response.incomplete"] {
            session.commit_completed(&json!({"type":kind,"response":{"output":[{"type":"compaction","encrypted_content":"unconfirmed"}]}})).unwrap();
        }
        assert!(session.verified_opaque.is_empty());
        session.commit_completed(&json!({"type":"response.completed","response":{"output":[{"type":"compaction","encrypted_content":"actual-result"}]}})).unwrap();
        assert!(session.verified_opaque.contains("actual-result"));
        let too_large = "x".repeat(MAX_SINGLE_OPAQUE_BYTES + 1);
        assert_eq!(session.commit_completed(&json!({"type":"response.completed","response":{"output":[{"type":"reasoning","encrypted_content":"new-valid"},{"type":"compaction","encrypted_content":too_large}]}})).unwrap_err(), ProtocolError::Capacity("session.opaque"));
        assert_eq!(
            session.verified_opaque,
            BTreeSet::from(["actual-result".to_owned()])
        );
        for index in 1..MAX_OPAQUE_ITEMS {
            session.verified_opaque.insert(index.to_string());
        }
        let before = session.verified_opaque.clone();
        assert_eq!(session.commit_completed(&json!({"type":"response.completed","response":{"output":[{"type":"compaction","encrypted_content":"overflow"}]}})).unwrap_err(), ProtocolError::Capacity("session.opaque"));
        assert_eq!(session.verified_opaque, before);
    }
}
