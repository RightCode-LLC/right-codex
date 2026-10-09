//! Account-scoped auxiliary endpoints in the pinned Codex SDK.
//! Only the request fields with a pinned 0.160.0 wire meaning are accepted.
use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use codex_http_client::{
    HttpTransport, Request, RequestBody, Response as HttpResponse, StreamResponse, TransportError,
};

use codex_api::{
    ImageBackground, ImageEditRequest, ImageGenerationRequest, ImageQuality, ImagesClient,
    ModelsClient, RealtimeCallClient, RealtimeCallResponse, RealtimeEventParser,
    RealtimeOutputModality, RealtimeSessionConfig, RealtimeSessionMode, Reasoning,
    ReasoningContext, SearchClient, SearchCommands, SearchInput, SearchRequest, SearchSettings,
};
use codex_client::RequestTelemetry;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::models::{ImageReference, ResponseItem};
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::{ConversationTextParams, ConversationTextRole, RealtimeVoice};
use futures::StreamExt;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::accounts::Account;
use crate::gateway::{self, AppState, Conversation};
use crate::observability::{AccountTelemetry, ObservedNetworkEvent};
use crate::protocol::{self, RequestContext};
use crate::resources::{ResourceStore, is_generated_alias};
use crate::search_resources::SearchResourceStore;
use crate::session::Session;
use crate::telemetry::{AttemptJournal, FactLedger, OutboundIdentity, TerminalKind};
use crate::transport::RawHttpError;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/alpha/search", post(search))
        .route("/v1/images/generations", post(image_generation))
        .route("/v1/images/edits", post(image_edit))
        .route(
            "/v1/realtime/calls",
            post(realtime_sideband_bypasses_gateway),
        )
        .route("/v1/live", post(realtime_sideband_bypasses_gateway))
}

fn rejected(error: AuxiliaryError) -> Response {
    match error {
        AuxiliaryError::Invalid(_)
        | AuxiliaryError::Unsupported(_)
        | AuxiliaryError::UnmappedFile => gateway::error(
            StatusCode::BAD_REQUEST,
            "unsupported_auxiliary_request",
            "Auxiliary request contains an invalid or unverified field",
            "辅助请求包含无效或未经核实的字段",
        ),
        AuxiliaryError::UpstreamResponse(error) => error.into_response(),
        AuxiliaryError::Upstream => gateway::error(
            StatusCode::BAD_GATEWAY,
            "auxiliary_upstream_failed",
            "Auxiliary upstream operation failed",
            "辅助上游操作失败",
        ),
    }
}

#[expect(
    clippy::result_large_err,
    reason = "Axum handler boundary returns its HTTP response directly"
)]
fn input_json(payload: Result<Json<Value>, JsonRejection>) -> Result<Value, Response> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        gateway::error(
            rejection.status(),
            "invalid_request_json",
            "A valid bounded JSON body is required",
            "需要有效且未超过限制的 JSON 请求体",
        )
    })
}

#[derive(Clone, Copy)]
enum Operation {
    Search,
    Generate,
    Edit,
}
impl Operation {
    fn endpoint(self) -> &'static str {
        match self {
            Self::Search => "/alpha/search",
            Self::Generate => "/images/generations",
            Self::Edit => "/images/edits",
        }
    }
}

async fn execute_conversation(
    state: Arc<AppState>,
    headers: HeaderMap,
    input: Value,
    operation: Operation,
) -> Response {
    let image_scope = if !matches!(operation, Operation::Search)
        && headers.contains_key("x-codex-image-turn-id")
    {
        match crate::images_scope::resolve(
            &state.sessions,
            &state.scope_dir,
            &state.namespace(&headers),
            &headers,
        ) {
            Ok(scope) => Some(scope),
            Err(reason) => return gateway::protocol_error(reason),
        }
    } else {
        None
    };
    let scope_material = match operation {
        Operation::Search => match crate::metadata::search_scope_material(&input, &headers) {
            Ok(value) => Some(value),
            Err(reason) => return gateway::protocol_error(reason),
        },
        _ => None,
    };
    let (scope_input, scope_headers) = scope_material
        .as_ref()
        .map(|(body, headers)| (body, headers))
        .unwrap_or((&input, &headers));
    let scope = match &image_scope {
        Some(registered) => gateway::Scope {
            key: registered.key.clone(),
            namespace: state.namespace(&headers),
            session: registered.session.clone(),
        },
        None => match gateway::scope(&state, scope_headers, scope_input) {
            Ok(scope) => scope,
            Err(response) => return response,
        },
    };
    let mut conversation = match Conversation::acquire(state.clone(), scope).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(registered) = &image_scope
        && let Err(reason) = registered.validate_current(&conversation.session)
    {
        return gateway::protocol_error(reason);
    }
    // A client operation owns exactly one upstream send. Scheduling changes
    // caused by the response apply only to later independent client requests.
    let (account, _lease) = match conversation.account(&HashSet::new()).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let upstream_turn = if let Some(registered) = &image_scope {
        let turn = match conversation
            .session
            .bind_auxiliary_turn(&registered.logical_turn)
        {
            Ok(turn) => turn,
            Err(reason) => return gateway::protocol_error(reason),
        };
        if let Err(reason) = gateway::persist(&state, &conversation.key, &conversation.session) {
            return gateway::protocol_error(reason);
        }
        turn
    } else {
        let local = gateway::logical_turn(&conversation.namespace, scope_input, scope_headers);
        conversation
            .session
            .upstream_turn_for(&local)
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    };
    let projected = match operation {
        Operation::Search => project_search(&input, &conversation.session)
            .map(|request| Projected::Search(Box::new(request))),
        Operation::Generate => project_image_generation(&input).map(Projected::Generate),
        Operation::Edit => project_image_edit_with_resources(
            &input,
            &conversation.session,
            &ResourceStore::new(&state.config.state_dir),
            &conversation.key,
        )
        .map(Projected::Edit),
    };
    let mut projected = match projected {
        Ok(value) => value,
        Err(reason) => return rejected(reason),
    };
    let search_resources = SearchResourceStore::new(&state.config.state_dir);
    if let Projected::Search(request) = &mut projected {
        let plan = match search_resources.prepare(
            &conversation.key,
            account.id(),
            account.revision(),
            request.commands.take(),
        ) {
            Ok(plan) => plan,
            Err(_) => return rejected(AuxiliaryError::Invalid("search.reference_provenance")),
        };
        request.id = plan.search_id;
        request.commands = plan.commands;
    }
    let model = projected.model();
    let identity = OutboundIdentity {
        account_id: account.id().to_owned(),
        workspace_account_id: account.workspace_account_id().to_owned(),
        auth_revision: account.revision().to_owned(),
        thread_id: conversation.session.thread_id.clone(),
        turn_id: upstream_turn,
        attempt_id: Uuid::new_v4().to_string(),
        endpoint: operation.endpoint().to_owned(),
    };
    let hooks = match state
        .metrics
        .for_account(&account, identity.clone(), model, model)
    {
        Ok(hooks) => hooks,
        Err(_) => return rejected(AuxiliaryError::Upstream),
    };
    let mut outbound_headers = HeaderMap::new();
    if matches!(operation, Operation::Search) {
        let parent = match gateway::parent_request_proof(&conversation, scope_input, scope_headers)
        {
            Ok(parent) => parent,
            Err(response) => return response,
        };
        let metadata = match crate::metadata::classify_request(scope_input, scope_headers) {
            Ok(metadata) => metadata,
            Err(reason) => return gateway::protocol_error(reason),
        };
        let session = &conversation.session;
        let projection = match crate::metadata::project(
            &metadata,
            &crate::metadata::MetadataScope {
                account_id: account.id(),
                auth_revision: account.revision(),
                installation_id: &session.installation_id,
                session_id: &session.session_id,
                thread_id: &session.thread_id,
                turn_id: &identity.turn_id,
                window_id: &session.window_id,
                context_window_id: &session.context_window_id,
                window_number: session.window_number,
                turn_started_at_unix_ms: gateway::now_ms(),
                parent: parent.as_ref(),
            },
        ) {
            Ok(projection) => projection,
            Err(reason) => return gateway::protocol_error(reason),
        };
        // Unlike Responses' compatibility header, the standalone native
        // search tool sends the full canonical metadata including inventory.
        let canonical = projection.client_metadata["x-codex-turn-metadata"]
            .as_str()
            .expect("metadata projection is a canonical string");
        match http::HeaderValue::from_str(canonical) {
            Ok(value) => {
                outbound_headers.insert("x-codex-turn-metadata", value);
            }
            Err(_) => return rejected(AuxiliaryError::Invalid("search.metadata")),
        }
    } else {
        outbound_headers.insert(
            "x-codex-image-turn-id",
            http::HeaderValue::from_str(&identity.turn_id).expect("gateway UUID"),
        );
    }
    let provider = gateway::provider(
        &state,
        &account,
        state.config.base_url.clone(),
        outbound_headers,
    );
    let client = AuxiliaryClient::new(&account, provider, state.ledger.clone(), identity, hooks);
    let result = match projected {
        Projected::Search(request) => client.search(&request).await,
        Projected::Generate(request) => client.generate(&request).await,
        Projected::Edit(request) => client.edit(&request).await,
    };
    let result = match (operation, result) {
        (Operation::Search, Ok(value)) => search_resources
            .observe_and_alias(&conversation.key, account.id(), account.revision(), value)
            .map_err(|_| AuxiliaryError::Upstream),
        (Operation::Generate | Operation::Edit, Ok(value)) => {
            ResourceStore::new(&state.config.state_dir)
                .alias_generated(&conversation.key, account.id(), account.revision(), value)
                .map_err(|_| AuxiliaryError::Upstream)
        }
        (_, result) => result,
    };
    let finished = client.finish_result(&result);
    observe_error(&state, &account, &result);
    if let Err(reason) = result {
        if finished.is_err() {
            tracing::error!("Failed to finalize auxiliary error telemetry");
        }
        return rejected(reason);
    }
    if finished.is_err() {
        return rejected(AuxiliaryError::Upstream);
    }
    if state
        .accounts
        .by_id(account.id())
        .ok()
        .flatten()
        .is_none_or(|current| current.revision() != account.revision())
    {
        return gateway::error(
            StatusCode::SERVICE_UNAVAILABLE,
            "account_revision_changed",
            "OAuth account changed during this request",
            "请求期间 OAuth 账号发生变化",
        );
    }
    match result {
        Ok(value) => Json(value).into_response(),
        Err(reason) => rejected(reason),
    }
}

enum Projected {
    Search(Box<SearchRequest>),
    Generate(ImageGenerationRequest),
    Edit(ImageEditRequest),
}
impl Projected {
    fn model(&self) -> &str {
        match self {
            Self::Search(request) => &request.model,
            Self::Generate(request) => &request.model,
            Self::Edit(request) => &request.model,
        }
    }
}

async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    match input_json(payload) {
        Ok(input) => execute_conversation(state, headers, input, Operation::Search).await,
        Err(response) => response,
    }
}
async fn image_generation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    match input_json(payload) {
        Ok(input) => execute_conversation(state, headers, input, Operation::Generate).await,
        Err(response) => response,
    }
}
async fn image_edit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    match input_json(payload) {
        Ok(input) => execute_conversation(state, headers, input, Operation::Edit).await,
        Err(response) => response,
    }
}

async fn models(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if query
        .iter()
        .any(|(key, value)| key != "client_version" || value != crate::CODEX_VERSION)
    {
        return gateway::error(
            StatusCode::BAD_REQUEST,
            "unsupported_model_catalog_query",
            "Only the pinned Codex client version is accepted",
            "只接受锁定的 Codex 客户端版本",
        );
    }
    // The inbound OAuth account belongs to the client. Catalog requests
    // without a conversation use an eligible gateway account; a request with
    // a thread identity follows that conversation's existing local binding.
    let mut bound = if headers.contains_key("thread-id") || headers.contains_key("session-id") {
        let scope = match gateway::scope(&state, &headers, &json!({})) {
            Ok(scope) => scope,
            Err(response) => return response,
        };
        match Conversation::acquire(state.clone(), scope).await {
            Ok(conversation) => Some(conversation),
            Err(response) => return response,
        }
    } else {
        None
    };
    let (account, _lease) = if let Some(conversation) = bound.as_mut() {
        match conversation.account(&HashSet::new()).await {
            Ok(value) => value,
            Err(response) => return response,
        }
    } else {
        let Ok(Some(account)) = state.accounts.next_eligible_excluding(&HashSet::new()) else {
            return gateway::no_account();
        };
        let Ok(Some(lease)) = state.accounts.lease(account.id(), false) else {
            return gateway::no_account();
        };
        (account, lease)
    };
    let model = "catalog";
    let identity = OutboundIdentity {
        account_id: account.id().to_owned(),
        workspace_account_id: account.workspace_account_id().to_owned(),
        auth_revision: account.revision().to_owned(),
        thread_id: bound
            .as_ref()
            .map(|conversation| conversation.session.thread_id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        turn_id: Uuid::new_v4().to_string(),
        attempt_id: Uuid::new_v4().to_string(),
        endpoint: "/models".to_owned(),
    };
    let hooks = match state
        .metrics
        .for_account(&account, identity.clone(), model, model)
    {
        Ok(hooks) => hooks,
        Err(_) => return rejected(AuxiliaryError::Upstream),
    };
    let provider = gateway::provider(
        &state,
        &account,
        state.config.base_url.clone(),
        HeaderMap::new(),
    );
    let client = AuxiliaryClient::new(&account, provider, state.ledger.clone(), identity, hooks);
    let result = client.models_with_etag().await;
    let finished = client.finish_result(&result);
    observe_error(&state, &account, &result);
    if let Err(reason) = result {
        if finished.is_err() {
            tracing::error!("Failed to finalize auxiliary error telemetry");
        }
        return rejected(reason);
    }
    if finished.is_err() {
        return rejected(AuxiliaryError::Upstream);
    }
    if state
        .accounts
        .by_id(account.id())
        .ok()
        .flatten()
        .is_none_or(|current| current.revision() != account.revision())
    {
        return gateway::error(
            StatusCode::SERVICE_UNAVAILABLE,
            "account_revision_changed",
            "OAuth account changed during this request",
            "请求期间 OAuth 账号发生变化",
        );
    }
    match result {
        Ok((value, etag)) => {
            let mut response = Json(value).into_response();
            if let Some(etag) = etag.and_then(|v| http::HeaderValue::from_str(&v).ok()) {
                response.headers_mut().insert(http::header::ETAG, etag);
            }
            response
        }
        Err(reason) => rejected(reason),
    }
}

fn observe_error<T>(state: &AppState, account: &Account, result: &Result<T, AuxiliaryError>) {
    if let Err(AuxiliaryError::UpstreamResponse(error)) = result
        && crate::upstream_policy::observe_raw_http(&state.accounts, account, error).is_err()
    {
        tracing::error!("Failed to persist auxiliary upstream account state");
    }
}

/// A base-URL override does not redirect the pinned client's WebRTC sideband.
/// The client would join api.openai.com with its own OAuth identity, which may
/// differ from the account selected for call creation by this gateway.
async fn realtime_sideband_bypasses_gateway() -> Response {
    gateway::error(
        StatusCode::NOT_IMPLEMENTED,
        "native_realtime_sideband_bypasses_gateway",
        "The native Realtime sideband bypasses this gateway; this call was not created",
        "原生实时控制连接绕过本网关；本次通话未创建",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxiliaryError {
    Invalid(&'static str),
    Unsupported(&'static str),
    UnmappedFile,
    Upstream,
    UpstreamResponse(Box<RawHttpError>),
}

fn object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, AuxiliaryError> {
    value.as_object().ok_or(AuxiliaryError::Invalid(field))
}

fn fields(
    value: &Map<String, Value>,
    allowed: &[&str],
    field: &'static str,
) -> Result<(), AuxiliaryError> {
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(AuxiliaryError::Unsupported(field));
    }
    Ok(())
}

fn required_text(value: &Map<String, Value>, key: &'static str) -> Result<String, AuxiliaryError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 65_536 && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(AuxiliaryError::Invalid(key))
}

fn required_prompt(value: &Map<String, Value>) -> Result<String, AuxiliaryError> {
    value
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 65_536)
        .map(str::to_owned)
        .ok_or(AuxiliaryError::Invalid("prompt"))
}

fn typed<T: DeserializeOwned + Serialize>(
    value: &Value,
    field: &'static str,
) -> Result<T, AuxiliaryError> {
    let typed: T =
        serde_json::from_value(value.clone()).map_err(|_| AuxiliaryError::Invalid(field))?;
    // The upstream typed API silently drops unknown fields. Reject rather than
    // changing business semantics while forwarding an apparently valid request.
    if serde_json::to_value(&typed).map_err(|_| AuxiliaryError::Invalid(field))? != *value {
        return Err(AuxiliaryError::Unsupported(field));
    }
    Ok(typed)
}

fn reasoning(value: Option<&Value>) -> Result<Option<Reasoning>, AuxiliaryError> {
    let Some(value) = value else { return Ok(None) };
    let body = object(value, "reasoning")?;
    fields(body, &["effort", "summary", "context"], "reasoning")?;
    let effort = body
        .get("effort")
        .map(|value| {
            let text = if let Some(s) = value.as_str() {
                s.to_owned()
            } else if let Some(n) = value.as_u64() {
                n.to_string()
            } else {
                return Err(AuxiliaryError::Invalid("reasoning.effort"));
            };
            text.parse::<ReasoningEffort>()
                .map_err(|_| AuxiliaryError::Invalid("reasoning.effort"))
        })
        .transpose()?;
    let summary = body
        .get("summary")
        .map(|value| {
            serde_json::from_value::<ReasoningSummary>(value.clone())
                .map_err(|_| AuxiliaryError::Invalid("reasoning.summary"))
        })
        .transpose()?;
    let context = body
        .get("context")
        .map(|value| match value.as_str() {
            Some("auto") => Ok(ReasoningContext::Auto),
            Some("current_turn") => Ok(ReasoningContext::CurrentTurn),
            Some("all_turns") => Ok(ReasoningContext::AllTurns),
            _ => Err(AuxiliaryError::Invalid("reasoning.context")),
        })
        .transpose()?;
    Ok(Some(Reasoning {
        effort,
        summary,
        context,
    }))
}

pub fn project_search(input: &Value, session: &Session) -> Result<SearchRequest, AuxiliaryError> {
    let body = object(input, "search")?;
    fields(
        body,
        &[
            "id",
            "model",
            "reasoning",
            "input",
            "commands",
            "settings",
            "max_output_tokens",
        ],
        "search",
    )?;
    let model = required_text(body, "model")?;
    let input = match body.get("input") {
        None => None,
        Some(Value::String(text)) => Some(SearchInput::Text(text.clone())),
        Some(Value::Array(items)) => {
            let projected = protocol::build_request(
                json!({"model":model,"input":items}),
                &RequestContext {
                    gateway_thread_id: &session.thread_id,
                    gateway_turn_id: &Uuid::new_v4().to_string(),
                    cache_key: &session.cache_key,
                    identifiers: session.identifiers(),
                    verified_opaque: &session.verified_opaque,
                },
            )
            .map_err(|_| AuxiliaryError::Invalid("search.input"))?;
            let mapped: Vec<ResponseItem> = serde_json::from_value(projected.body["input"].clone())
                .map_err(|_| AuxiliaryError::Invalid("search.input"))?;
            Some(SearchInput::Items(mapped))
        }
        Some(_) => return Err(AuxiliaryError::Invalid("search.input")),
    };
    let commands = body
        .get("commands")
        .map(|v| typed::<SearchCommands>(v, "search.commands"))
        .transpose()?;
    let settings = body
        .get("settings")
        .map(|v| typed::<SearchSettings>(v, "search.settings"))
        .transpose()?;
    let max_output_tokens = body
        .get("max_output_tokens")
        .map(|v| {
            v.as_u64()
                .filter(|n| *n > 0)
                .ok_or(AuxiliaryError::Invalid("search.max_output_tokens"))
        })
        .transpose()?;
    Ok(SearchRequest {
        id: Uuid::new_v4().to_string(),
        model,
        reasoning: reasoning(body.get("reasoning"))?,
        input,
        commands,
        settings,
        max_output_tokens,
    })
}

type ImageCommon = (
    String,
    String,
    Option<ImageBackground>,
    Option<u64>,
    Option<ImageQuality>,
    Option<String>,
);

fn image_common(input: &Value, edit: bool) -> Result<ImageCommon, AuxiliaryError> {
    let body = object(input, "image")?;
    let allowed = if edit {
        &[
            "images",
            "prompt",
            "background",
            "model",
            "n",
            "quality",
            "size",
        ][..]
    } else {
        &["prompt", "background", "model", "n", "quality", "size"][..]
    };
    fields(body, allowed, "image")?;
    let prompt = required_prompt(body)?;
    let model = required_text(body, "model")?;
    let background = body
        .get("background")
        .map(|v| {
            serde_json::from_value(v.clone())
                .map_err(|_| AuxiliaryError::Invalid("image.background"))
        })
        .transpose()?;
    let quality = body
        .get("quality")
        .map(|v| {
            serde_json::from_value(v.clone()).map_err(|_| AuxiliaryError::Invalid("image.quality"))
        })
        .transpose()?;
    let n = body
        .get("n")
        .map(|v| {
            v.as_u64()
                .filter(|n| (1..=16).contains(n))
                .ok_or(AuxiliaryError::Invalid("image.n"))
        })
        .transpose()?;
    let size = body
        .get("size")
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && s.len() <= 64)
                .map(str::to_owned)
                .ok_or(AuxiliaryError::Invalid("image.size"))
        })
        .transpose()?;
    Ok((prompt, model, background, n, quality, size))
}

pub fn project_image_generation(input: &Value) -> Result<ImageGenerationRequest, AuxiliaryError> {
    let (prompt, model, background, n, quality, size) = image_common(input, false)?;
    Ok(ImageGenerationRequest {
        prompt,
        background,
        model,
        n,
        quality,
        size,
    })
}

pub fn project_image_edit(
    input: &Value,
    session: &Session,
) -> Result<ImageEditRequest, AuxiliaryError> {
    let (prompt, model, background, n, quality, size) = image_common(input, true)?;
    let body = object(input, "image")?;
    let images = body
        .get("images")
        .and_then(Value::as_array)
        .filter(|images| !images.is_empty() && images.len() <= 16)
        .ok_or(AuxiliaryError::Invalid("image.images"))?;
    let mut projected = Vec::with_capacity(images.len());
    for image in images {
        let image: ImageReference = typed(image, "image.images")?;
        match image {
            ImageReference::Inline { image_url } => {
                if image_url.is_empty() || image_url.len() > 16 * 1024 * 1024 {
                    return Err(AuxiliaryError::Invalid("image.image_url"));
                }
                projected.push(ImageReference::Inline { image_url });
            }
            ImageReference::File { file_id } => {
                let mapped = session
                    .file(&file_id)
                    .filter(|file| {
                        file.account_id == session.account_id
                            && file.auth_revision == session.auth_revision
                    })
                    .ok_or(AuxiliaryError::UnmappedFile)?;
                projected.push(ImageReference::File {
                    file_id: mapped.upstream_id.clone(),
                });
            }
        }
    }
    Ok(ImageEditRequest {
        images: projected,
        prompt,
        background,
        model,
        n,
        quality,
        size,
    })
}

/// A locally generated image is always reconstructed from its verified bytes.
/// Its source account's generation id never becomes a later file_id, even if
/// this conversation moves to another OAuth account.
pub fn project_image_edit_with_resources(
    input: &Value,
    session: &Session,
    resources: &ResourceStore,
    session_key: &str,
) -> Result<ImageEditRequest, AuxiliaryError> {
    let mut rewritten = input.clone();
    if let Some(images) = rewritten.get_mut("images").and_then(Value::as_array_mut) {
        for image in images {
            let Some(alias) = image.get("file_id").and_then(Value::as_str) else {
                continue;
            };
            if is_generated_alias(alias) {
                let inline = resources
                    .inline_image(session_key, alias)
                    .map_err(|_| AuxiliaryError::Upstream)?
                    .ok_or(AuxiliaryError::UnmappedFile)?;
                *image = json!({"image_url": inline});
            }
        }
    }
    project_image_edit(&rewritten, session)
}

/// Reconstruct only the official v1/v3 session shapes. Comparing the SDK's
/// serialization with the client wire body rejects silent field loss.
pub fn project_realtime_session(
    input: &Value,
    gateway_session_id: &str,
) -> Result<RealtimeSessionConfig, AuxiliaryError> {
    let body = object(input, "realtime.session")?;
    let parser = if body.get("type") == Some(&Value::String("quicksilver".into())) {
        RealtimeEventParser::V1
    } else if body.get("delegation").is_some() && body.get("type").is_none() {
        RealtimeEventParser::FramelessBidi
    } else {
        return Err(AuxiliaryError::Unsupported("realtime.session.type"));
    };
    let instructions = body
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 65_536)
        .ok_or(AuxiliaryError::Invalid("realtime.instructions"))?
        .to_owned();
    let model = body
        .get("model")
        .map(|v| {
            v.as_str()
                .filter(|m| !m.is_empty() && m.len() <= 256)
                .map(str::to_owned)
                .ok_or(AuxiliaryError::Invalid("realtime.model"))
        })
        .transpose()?;
    let voice: RealtimeVoice = serde_json::from_value(
        input
            .pointer("/audio/output/voice")
            .cloned()
            .ok_or(AuxiliaryError::Invalid("realtime.voice"))?,
    )
    .map_err(|_| AuxiliaryError::Invalid("realtime.voice"))?;
    let mut initial_items = Vec::new();
    if let Some(items) = body.get("initial_items") {
        let items = items
            .as_array()
            .filter(|items| items.len() <= 64)
            .ok_or(AuxiliaryError::Invalid("realtime.initial_items"))?;
        for item in items {
            let role: ConversationTextRole = serde_json::from_value(
                item.get("role")
                    .cloned()
                    .ok_or(AuxiliaryError::Invalid("realtime.initial_items"))?,
            )
            .map_err(|_| AuxiliaryError::Invalid("realtime.initial_items"))?;
            let text = item
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 65_536)
                .ok_or(AuxiliaryError::Invalid("realtime.initial_items"))?;
            initial_items.push(ConversationTextParams {
                text: text.to_owned(),
                role,
            });
        }
    }
    let delegation_ack_filler = input
        .pointer("/delegation/ack_filler")
        .map(|v| {
            v.as_bool()
                .ok_or(AuxiliaryError::Invalid("realtime.delegation"))
        })
        .transpose()?;
    let config = RealtimeSessionConfig {
        instructions,
        initial_items,
        delegation_ack_filler,
        model,
        session_id: Some(gateway_session_id.to_owned()),
        event_parser: parser,
        session_mode: RealtimeSessionMode::Conversational,
        output_modality: RealtimeOutputModality::Audio,
        voice,
    };
    let mut encoded = codex_api::session_update_session_json(config.clone())
        .map_err(|_| AuxiliaryError::Invalid("realtime.session"))?;
    encoded
        .as_object_mut()
        .ok_or(AuxiliaryError::Invalid("realtime.session"))?
        .remove("id");
    let mut supplied = input.clone();
    supplied
        .as_object_mut()
        .ok_or(AuxiliaryError::Invalid("realtime.session"))?
        .remove("id");
    if encoded != supplied {
        return Err(AuxiliaryError::Unsupported("realtime.session"));
    }
    Ok(config)
}

/// Uses the official clients and this account's own HTTP pool/auth provider.
/// Route selection is supplied by the gateway; auxiliary endpoints do not
/// inherit Responses workspace-origin overrides from another account.
pub struct AuxiliaryClient<'a> {
    pub account: &'a Account,
    pub provider: codex_client::Provider,
    pub request_hook: Option<Arc<dyn RequestTelemetry>>,
    journal: Arc<Mutex<JournalState>>,
    ledger: Arc<FactLedger>,
    identity: OutboundIdentity,
}

#[derive(Default)]
struct JournalState {
    actual: Option<AttemptJournal>,
    early_hooks: Vec<ObservedNetworkEvent>,
    response_body: Option<Vec<u8>>,
    error_response: Option<RawHttpError>,
}

#[derive(Clone)]
struct JournalTransport {
    inner: reqwest::Client,
    ledger: Arc<FactLedger>,
    identity: OutboundIdentity,
    state: Arc<Mutex<JournalState>>,
}

fn request_sha(request: &Request) -> String {
    let bytes = match request.body.as_ref() {
        Some(RequestBody::Json(body)) => serde_json::to_vec(body).unwrap_or_default(),
        Some(RequestBody::EncodedJson(body)) => body.as_bytes().to_vec(),
        Some(RequestBody::Raw(body)) => body.to_vec(),
        None => Vec::new(),
    };
    format!("{:x}", Sha256::digest(bytes))
}

impl JournalTransport {
    async fn execute_prepared(&self, request: Request) -> Result<HttpResponse, TransportError> {
        // Preserve the SDK's prepared/signable request, but capture rejected
        // bytes before the stock transport narrows them to a UTF-8 String.
        let response = crate::transport::send_prepared(&self.inner, &request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let limit = request
            .response_body_limit_bytes
            .unwrap_or(64 * 1024 * 1024);
        if !status.is_success() {
            let error = crate::transport::read_http_error(response, limit).await;
            let diagnostic = error
                .complete
                .then(|| String::from_utf8_lossy(&error.body).into_owned());
            let retry_after = error.retry_after;
            if let Ok(mut state) = self.state.lock() {
                state.error_response = Some(error);
            }
            return Err(TransportError::Http {
                status,
                url: Some(request.url),
                retry_after,
                headers: Some(headers),
                body: diagnostic,
            });
        }
        let declared_too_large = response
            .content_length()
            .is_some_and(|len| len > limit as u64);
        let mut bytes = response.bytes_stream();
        let mut body = Vec::new();
        let mut complete = !declared_too_large;
        let mut too_large = declared_too_large;
        if !declared_too_large {
            while let Some(chunk) = bytes.next().await {
                match chunk {
                    Ok(chunk) if chunk.len() <= limit.saturating_sub(body.len()) => {
                        body.extend_from_slice(&chunk)
                    }
                    Ok(_) => {
                        complete = false;
                        too_large = true;
                        break;
                    }
                    Err(_) => {
                        complete = false;
                        break;
                    }
                }
            }
        }
        if too_large {
            return Err(TransportError::ResponseTooLarge { max_bytes: limit });
        }
        if !complete {
            return Err(TransportError::Network(
                "auxiliary response body was interrupted".into(),
            ));
        }
        Ok(HttpResponse {
            status,
            headers,
            body: body.into(),
        })
    }
}

impl HttpTransport for JournalTransport {
    async fn execute(&self, mut request: Request) -> Result<HttpResponse, TransportError> {
        request
            .response_body_limit_bytes
            .get_or_insert(64 * 1024 * 1024);
        let logical = request_sha(&request);
        let prepared = request.into_prepared().map_err(TransportError::Build)?;
        let wire = request_sha(&prepared);
        let mut journal = self
            .ledger
            .begin(self.identity.clone(), &logical, &wire)
            .map_err(|_| TransportError::Build("private auxiliary telemetry unavailable".into()))?;
        {
            let mut guard = self.state.lock().map_err(|_| {
                TransportError::Build("auxiliary telemetry lock unavailable".into())
            })?;
            if guard.actual.is_some() {
                return Err(TransportError::Build(
                    "auxiliary request already sent".into(),
                ));
            }
            for event in std::mem::take(&mut guard.early_hooks) {
                let _ = journal.observe_hook(&event);
            }
            guard.actual = Some(journal);
        }
        let start = Instant::now();
        let result = self.execute_prepared(prepared).await;
        let (status, request_id) = match &result {
            Ok(response) => (
                Some(response.status.as_u16()),
                response
                    .headers
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok()),
            ),
            Err(TransportError::Http {
                status, headers, ..
            }) => (
                Some(status.as_u16()),
                headers
                    .as_ref()
                    .and_then(|h| h.get("x-request-id"))
                    .and_then(|v| v.to_str().ok()),
            ),
            _ => (None, None),
        };
        if let Some(status) = status
            && let Ok(mut guard) = self.state.lock()
        {
            if let Some(journal) = guard.actual.as_mut() {
                let _ = journal.http_response(status, request_id, start.elapsed());
            }
            if let Ok(response) = &result
                && response.status.is_success()
            {
                guard.response_body = Some(response.body.to_vec());
            }
        }
        result
    }

    async fn stream(&self, _request: Request) -> Result<StreamResponse, TransportError> {
        Err(TransportError::Build(
            "auxiliary endpoint requires one-shot HTTP".into(),
        ))
    }
}

impl<'a> AuxiliaryClient<'a> {
    pub fn new(
        account: &'a Account,
        provider: codex_client::Provider,
        ledger: Arc<FactLedger>,
        identity: OutboundIdentity,
        telemetry: Arc<AccountTelemetry>,
    ) -> AuxiliaryClient<'a> {
        let journal = Arc::new(Mutex::new(JournalState::default()));
        let sink = Arc::clone(&journal);
        let _ = telemetry.set_observer(Arc::new(move |event| {
            if let Ok(mut guard) = sink.lock() {
                if let Some(journal) = guard.actual.as_mut() {
                    let _ = journal.observe_hook(&event);
                } else if guard.early_hooks.len() < 32 {
                    guard.early_hooks.push(event);
                }
            }
        }));
        AuxiliaryClient {
            account,
            provider,
            request_hook: Some(telemetry.request_hook()),
            journal,
            ledger,
            identity,
        }
    }

    fn transport(&self) -> JournalTransport {
        JournalTransport {
            inner: self.account.client().clone(),
            ledger: Arc::clone(&self.ledger),
            identity: self.identity.clone(),
            state: Arc::clone(&self.journal),
        }
    }

    pub fn finish(&self, successful: bool) -> Result<(), AuxiliaryError> {
        self.finish_terminal(if successful {
            TerminalKind::HttpCompleted
        } else {
            TerminalKind::Failed
        })
    }

    fn finish_result<T>(&self, result: &Result<T, AuxiliaryError>) -> Result<(), AuxiliaryError> {
        self.finish_terminal(match result {
            Ok(_) => TerminalKind::HttpCompleted,
            Err(AuxiliaryError::UpstreamResponse(error)) if error.complete => TerminalKind::Failed,
            Err(AuxiliaryError::UpstreamResponse(_)) => TerminalKind::Unknown,
            Err(_) => TerminalKind::Unknown,
        })
    }

    fn finish_terminal(&self, terminal: TerminalKind) -> Result<(), AuxiliaryError> {
        let mut guard = self.journal.lock().map_err(|_| AuxiliaryError::Upstream)?;
        let Some(journal) = guard.actual.as_mut() else {
            return if terminal == TerminalKind::HttpCompleted {
                Err(AuxiliaryError::Upstream)
            } else {
                Ok(())
            };
        };
        // Returning a response from this function does not prove that a peer
        // received it; keep downstream delivery separate from source success.
        journal
            .finish(terminal, false)
            .map_err(|_| AuxiliaryError::Upstream)
    }

    fn raw_json_response(&self) -> Result<Value, AuxiliaryError> {
        let guard = self.journal.lock().map_err(|_| AuxiliaryError::Upstream)?;
        let raw = guard
            .response_body
            .as_deref()
            .ok_or(AuxiliaryError::Upstream)?;
        serde_json::from_slice(raw).map_err(|_| AuxiliaryError::Upstream)
    }

    fn sdk_error(&self, _error: codex_api::ApiError) -> AuxiliaryError {
        self.journal
            .lock()
            .ok()
            .and_then(|journal| journal.error_response.clone())
            .map(|response| AuxiliaryError::UpstreamResponse(Box::new(response)))
            .unwrap_or(AuxiliaryError::Upstream)
    }

    pub async fn models(&self) -> Result<Value, AuxiliaryError> {
        self.models_with_etag().await.map(|(value, _)| value)
    }

    async fn models_with_etag(&self) -> Result<(Value, Option<String>), AuxiliaryError> {
        let client = ModelsClient::new(
            self.transport(),
            self.provider.clone(),
            self.account.auth_provider(),
        )
        .with_telemetry(self.request_hook.clone());
        let url =
            ModelsClient::<JournalTransport>::request_url(&self.provider, crate::CODEX_VERSION);
        let (raw, etag) = client
            .list_models_raw(url, http::HeaderMap::new(), Some(8 * 1024 * 1024))
            .await
            .map_err(|error| self.sdk_error(error))?;
        let value: Value = serde_json::from_slice(&raw).map_err(|_| AuxiliaryError::Upstream)?;
        if !value.get("models").is_some_and(Value::is_array) {
            return Err(AuxiliaryError::Upstream);
        }
        Ok((value, etag))
    }

    pub async fn search(&self, request: &SearchRequest) -> Result<Value, AuxiliaryError> {
        let _validated = SearchClient::new(
            self.transport(),
            self.provider.clone(),
            self.account.auth_provider(),
        )
        .with_telemetry(self.request_hook.clone())
        .search(request, http::HeaderMap::new())
        .await
        .map_err(|error| self.sdk_error(error))?;
        self.raw_json_response()
    }

    pub async fn generate(
        &self,
        request: &ImageGenerationRequest,
    ) -> Result<Value, AuxiliaryError> {
        let (_validated, _nested_id) = ImagesClient::new(
            self.transport(),
            self.provider.clone(),
            self.account.auth_provider(),
        )
        .with_telemetry(self.request_hook.clone())
        .generate(request, http::HeaderMap::new())
        .await
        .map_err(|error| self.sdk_error(error.into_parts().0))?;
        self.raw_json_response()
    }

    pub async fn edit(&self, request: &ImageEditRequest) -> Result<Value, AuxiliaryError> {
        let (_validated, _nested_id) = ImagesClient::new(
            self.transport(),
            self.provider.clone(),
            self.account.auth_provider(),
        )
        .with_telemetry(self.request_hook.clone())
        .edit(request, http::HeaderMap::new())
        .await
        .map_err(|error| self.sdk_error(error.into_parts().0))?;
        self.raw_json_response()
    }

    pub async fn create_realtime_call(
        &self,
        sdp: String,
        config: Option<RealtimeSessionConfig>,
    ) -> Result<RealtimeCallResponse, AuxiliaryError> {
        let client = RealtimeCallClient::new(
            self.transport(),
            self.provider.clone(),
            self.account.auth_provider(),
        )
        .with_telemetry(self.request_hook.clone());
        match config {
            Some(config) => client
                .create_with_session_and_headers(sdp, config, http::HeaderMap::new())
                .await
                .map_err(|error| self.sdk_error(error)),
            None => client
                .create_with_headers(sdp, http::HeaderMap::new())
                .await
                .map_err(|error| self.sdk_error(error)),
        }
    }
}

impl Drop for AuxiliaryClient<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.journal.lock()
            && let Some(journal) = state.actual.as_mut()
        {
            let _ = journal.finish(TerminalKind::Unknown, false);
        }
    }
}

/// Scanner for file IDs in endpoint-specific inputs, deliberately not free JSON.
pub fn referenced_file_ids(request: &ImageEditRequest) -> BTreeSet<&str> {
    request
        .images
        .iter()
        .filter_map(|image| match image {
            ImageReference::File { file_id } => Some(file_id.as_str()),
            ImageReference::Inline { .. } => None,
        })
        .collect()
}
