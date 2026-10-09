//! Fixed 0.160 startup-prewarm and persistent WebSocket metadata contracts.
//! These synthetic ingress markers are local routing keys, never upstream IDs.
use http::{HeaderMap, HeaderValue};
use right_codex::metadata::{self, CANONICAL_METADATA, MetadataScope, RequestKind, TaskRole};
use right_codex::protocol::ProtocolError;
use serde_json::{Value, json};

fn current(kind: &str, turn: &str) -> Value {
    json!({
        "request_kind":kind,
        "installation_id":"CLIENT_INSTALL_SECRET",
        "session_id":"CLIENT_SESSION_SECRET",
        "thread_id":"CLIENT_THREAD_SECRET",
        "turn_id":turn,
        "window_id":"CLIENT_WINDOW_SECRET",
        "context_window_id":"CLIENT_CONTEXT_SECRET",
        "window_number":0,
        "turn_started_at_unix_ms":1,
        "workspaces":{"/CLIENT_PATH_SECRET":{"has_changes":false}},
        "tool_namespaces_info":{}
    })
}
fn body(canonical: &Value) -> Value {
    json!({"model":"test-model","stream":true,"input":[],"client_metadata":{
        CANONICAL_METADATA:canonical.to_string(),
        "x-codex-installation-id":canonical["installation_id"],
        "session_id":canonical["session_id"],
        "thread_id":canonical["thread_id"],
        "turn_id":canonical["turn_id"],
        "x-codex-window-id":canonical["window_id"]
    }})
}
fn headers(canonical: &Value, websocket: bool) -> HeaderMap {
    let mut compatible = canonical.clone();
    compatible
        .as_object_mut()
        .unwrap()
        .remove("tool_namespaces_info");
    let mut headers = HeaderMap::new();
    headers.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&compatible.to_string()).unwrap(),
    );
    headers.insert(
        "x-codex-window-id",
        HeaderValue::from_str(canonical["window_id"].as_str().unwrap()).unwrap(),
    );
    if websocket {
        headers.insert("upgrade", HeaderValue::from_static("WebSocket"));
    }
    headers
}
fn project(client: &metadata::ClientMetadata) -> metadata::MetadataProjection {
    metadata::project(
        client,
        &MetadataScope {
            account_id: "gateway-account",
            auth_revision: "gateway-revision",
            installation_id: "gateway-installation",
            session_id: "gateway-session",
            thread_id: "gateway-thread",
            turn_id: "gateway-random-turn",
            window_id: "gateway-window",
            context_window_id: "gateway-context",
            window_number: 0,
            turn_started_at_unix_ms: 2,
            parent: None,
        },
    )
    .unwrap()
}

#[test]
fn detached_memory_extraction_does_not_acquire_native_memgen_header() {
    // core/turn_metadata.rs:123-150 uses request_kind=memory for detached
    // phase 1, while core/client.rs:787-814 adds the header only for the
    // Internal(MemoryConsolidation) session source.
    let mut canonical = current("memory", "native-detached-memory-turn");
    canonical["thread_source"] = json!("memory_consolidation");
    canonical["turn_trigger"] = json!("memory_consolidation");
    let parsed =
        metadata::classify_request(&body(&canonical), &headers(&canonical, false)).unwrap();
    assert_eq!(parsed.kind, RequestKind::Memory);
    assert_eq!(parsed.role, TaskRole::Memory);
    let outbound = project(&parsed);
    assert!(!outbound.headers.contains_key("x-openai-memgen-request"));
    let projected_canonical: Value = serde_json::from_str(
        outbound.client_metadata[CANONICAL_METADATA]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(projected_canonical["request_kind"], "memory");
    assert!(!outbound.client_metadata.to_string().contains("CLIENT_"));

    let mut forged = headers(&canonical, false);
    forged.insert("x-openai-memgen-request", HeaderValue::from_static("true"));
    assert!(matches!(
        metadata::classify_request(&body(&canonical), &forged),
        Err(ProtocolError::Invalid("metadata.memgen_header"))
    ));
}

#[test]
fn native_memory_consolidation_header_requires_exact_internal_shape() {
    let mut canonical = current("turn", "native-consolidation-turn");
    canonical["thread_source"] = json!("memory_consolidation");
    canonical["turn_trigger"] = json!("memory_consolidation");
    let mut native = headers(&canonical, false);
    native.insert(
        "x-openai-subagent",
        HeaderValue::from_static("memory_consolidation"),
    );
    native.insert("x-openai-memgen-request", HeaderValue::from_static("true"));
    let parsed = metadata::classify_request(&body(&canonical), &native).unwrap();
    assert_eq!(parsed.role, TaskRole::Memory);
    assert_eq!(
        project(&parsed).headers["x-openai-memgen-request"],
        HeaderValue::from_static("true")
    );
    assert!(
        !project(&parsed)
            .client_metadata
            .to_string()
            .contains("CLIENT_")
    );

    // The shared textual label does not grant the header on its own. An
    // ordinary MemoryConsolidation subagent omits it in the fixed native code.
    let mut without_native_header = native.clone();
    without_native_header.remove("x-openai-memgen-request");
    let parsed = metadata::classify_request(&body(&canonical), &without_native_header).unwrap();
    assert!(
        !project(&parsed)
            .headers
            .contains_key("x-openai-memgen-request")
    );
    let mut subagent = native.clone();
    subagent.insert("x-openai-subagent", HeaderValue::from_static("review"));
    assert!(matches!(
        metadata::classify_request(&body(&canonical), &subagent),
        Err(ProtocolError::Invalid("metadata.memgen_header"))
    ));
    for wrong in ["false", "CLIENT_SECRET", "TRUE"] {
        let mut headers = native.clone();
        headers.insert(
            "x-openai-memgen-request",
            HeaderValue::from_str(wrong).unwrap(),
        );
        assert!(matches!(
            metadata::classify_request(&body(&canonical), &headers),
            Err(ProtocolError::Invalid("metadata.memgen_header"))
        ));
    }
    let mut duplicate = native.clone();
    duplicate.append("x-openai-memgen-request", HeaderValue::from_static("true"));
    assert!(matches!(
        metadata::classify_request(&body(&canonical), &duplicate),
        Err(ProtocolError::Invalid("metadata.duplicate_header"))
    ));
    let ordinary = current("turn", "native-ordinary-turn");
    let mut unrelated = headers(&ordinary, false);
    unrelated.insert("x-openai-memgen-request", HeaderValue::from_static("true"));
    assert!(matches!(
        metadata::classify_request(&body(&ordinary), &unrelated),
        Err(ProtocolError::Invalid("metadata.memgen_header"))
    ));
}

#[test]
fn standalone_search_uses_full_header_only_canonical_without_relaxing_responses() {
    let mut canonical = current("turn", "native-search-turn");
    canonical.as_object_mut().unwrap().remove("request_kind");
    canonical["tool_namespaces_info"] = json!({"functions":{"functions":{}}});
    let input = json!({"id":"client-search-id","model":"gpt-test","input":"search"});
    let original = input.clone();
    let mut headers = HeaderMap::new();
    headers.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&canonical.to_string()).unwrap(),
    );
    let (local_body, local_headers) = metadata::search_scope_material(&input, &headers).unwrap();
    let parsed = metadata::classify_request(&local_body, &local_headers).unwrap();
    assert_eq!(
        parsed.client_thread_id.as_deref(),
        Some("CLIENT_THREAD_SECRET")
    );
    assert_eq!(parsed.client_turn_id.as_deref(), Some("native-search-turn"));
    assert_eq!(input, original);
    assert!(!local_headers.contains_key(CANONICAL_METADATA));
    assert!(
        !project(&parsed)
            .client_metadata
            .to_string()
            .contains("CLIENT_")
    );
    assert!(matches!(
        metadata::classify_request(&input, &headers),
        Err(ProtocolError::Invalid("metadata.canonical_body_missing"))
    ));
}

#[test]
fn standalone_search_rejects_competing_malformed_and_duplicate_sources() {
    let input = json!({"id":"search","model":"gpt-test","input":"search"});
    let mut headers = HeaderMap::new();
    headers.insert(CANONICAL_METADATA, HeaderValue::from_static("not-json"));
    assert!(matches!(
        metadata::search_scope_material(&input, &headers),
        Err(ProtocolError::Invalid("metadata.canonical"))
    ));
    headers.insert(CANONICAL_METADATA, HeaderValue::from_static("{}"));
    headers.append(CANONICAL_METADATA, HeaderValue::from_static("{}"));
    assert!(matches!(
        metadata::search_scope_material(&input, &headers),
        Err(ProtocolError::Invalid("metadata.duplicate_header"))
    ));
    let competing = json!({"client_metadata":{CANONICAL_METADATA:"{}"}});
    assert!(matches!(
        metadata::search_scope_material(&competing, &HeaderMap::new()),
        Err(ProtocolError::Invalid("search.client_metadata"))
    ));
    let mut oversized = HeaderMap::new();
    oversized.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&format!(
            "{{\"x\":\"{}\"}}",
            "x".repeat(metadata::MAX_METADATA_BYTES)
        ))
        .unwrap(),
    );
    assert!(matches!(
        metadata::search_scope_material(&input, &oversized),
        Err(ProtocolError::Capacity("metadata"))
    ));
}

#[test]
fn original_startup_empty_turn_is_prewarm_only_and_outbound_is_rebuilt() {
    let canonical = current("prewarm", "");
    for websocket in [false, true] {
        let parsed =
            metadata::classify_request(&body(&canonical), &headers(&canonical, websocket)).unwrap();
        assert_eq!(parsed.kind, RequestKind::Prewarm);
        assert!(parsed.client_turn_id.is_none());
        let projected = project(&parsed);
        let wire = projected.client_metadata.to_string();
        assert!(!wire.contains("CLIENT_"));
        assert_eq!(projected.client_metadata["turn_id"], "gateway-random-turn");
        let canonical: Value = serde_json::from_str(
            projected.client_metadata[CANONICAL_METADATA]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(canonical["turn_id"], "gateway-random-turn");
        assert_eq!(canonical["request_kind"], "prewarm");
    }
    for kind in ["turn", "memory", "compaction"] {
        let canonical = current(kind, "");
        assert!(matches!(
            metadata::classify_request(&body(&canonical), &headers(&canonical, false)),
            Err(ProtocolError::Invalid("turn_id"))
        ));
    }
    let mut inconsistent = body(&canonical);
    inconsistent["client_metadata"]["turn_id"] = json!("different-nonempty-turn");
    assert!(matches!(
        metadata::classify_request(&inconsistent, &headers(&canonical, true)),
        Err(ProtocolError::Invalid("metadata.projection_mismatch"))
    ));
}

#[test]
fn websocket_prewarm_handshake_survives_native_turn_and_window_changes() {
    let handshake = current("prewarm", "");
    let headers = headers(&handshake, true);
    let mut next = current("turn", "CLIENT_CURRENT_TURN_SECRET");
    next["window_id"] = json!("CLIENT_NEXT_WINDOW_SECRET");
    next["context_window_id"] = json!("CLIENT_NEXT_CONTEXT_SECRET");
    next["window_number"] = json!(1);
    next["turn_started_at_unix_ms"] = json!(3);
    next["tool_namespaces_info"] = json!({"functions":{"functions":{}}});
    let parsed = metadata::classify_request(&body(&next), &headers).unwrap();
    assert_eq!(parsed.kind, RequestKind::Turn);
    assert_eq!(
        parsed.client_turn_id.as_deref(),
        Some("CLIENT_CURRENT_TURN_SECRET")
    );
    let projected = project(&parsed);
    assert!(!projected.client_metadata.to_string().contains("CLIENT_"));
    assert_eq!(
        serde_json::from_str::<Value>(projected.headers[CANONICAL_METADATA].to_str().unwrap())
            .unwrap()["request_kind"],
        "turn"
    );
    // A stale header on a fresh HTTP request has no persistent-socket meaning.
    let mut http_headers = headers.clone();
    http_headers.remove("upgrade");
    assert!(matches!(
        metadata::classify_request(&body(&next), &http_headers),
        Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"))
    ));
}

#[test]
fn websocket_compaction_and_review_use_frame_metadata_not_handshake_turn_snapshot() {
    let handshake = current("turn", "CLIENT_PRIOR_TURN_SECRET");
    let mut headers = headers(&handshake, true);
    let mut compact = current("compaction", "CLIENT_COMPACT_TURN_SECRET");
    compact["compaction"] = json!({"trigger":"manual","reason":"user_requested",
        "implementation":"responses_compaction_v2","phase":"standalone_turn","strategy":"memento"});
    let parsed = metadata::classify_request(&body(&compact), &headers).unwrap();
    assert_eq!(parsed.kind, RequestKind::Compaction);
    assert_eq!(
        project(&parsed).client_metadata["turn_id"],
        "gateway-random-turn"
    );
    headers.insert("x-openai-subagent", HeaderValue::from_static("review"));
    let review = current("turn", "CLIENT_REVIEW_TURN_SECRET");
    let parsed = metadata::classify_request(&body(&review), &headers).unwrap();
    assert_eq!(parsed.role, TaskRole::Review);
    assert!(
        !project(&parsed)
            .client_metadata
            .to_string()
            .contains("CLIENT_")
    );
}

#[test]
fn persistent_websocket_keeps_thread_session_installation_and_parent_fences() {
    let handshake = current("prewarm", "");
    let mut headers = headers(&handshake, true);
    for field in ["thread_id", "session_id", "installation_id"] {
        let mut next = current("turn", "current-turn");
        next[field] = json!("FOREIGN_SCOPE_SECRET");
        assert!(matches!(
            metadata::classify_request(&body(&next), &headers),
            Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"))
        ));
    }
    let mut next = current("turn", "current-turn");
    next["parent_thread_id"] = json!("current-parent");
    headers.insert(
        "x-codex-parent-thread-id",
        HeaderValue::from_static("foreign-parent"),
    );
    assert!(matches!(
        metadata::classify_request(&body(&next), &headers),
        Err(ProtocolError::Invalid("metadata.projection_mismatch"))
    ));
}

#[test]
fn body_flat_projection_and_header_parse_remain_strict_on_websocket() {
    let canonical = current("turn", "native-turn");
    let headers = headers(&canonical, true);
    for flat_field in ["thread_id", "session_id", "turn_id", "x-codex-window-id"] {
        let mut input = body(&canonical);
        input["client_metadata"][flat_field] = json!("different-local-projection");
        assert!(matches!(
            metadata::classify_request(&input, &headers),
            Err(ProtocolError::Invalid("metadata.projection_mismatch"))
        ));
    }
    let mut input = body(&canonical);
    input["client_metadata"]
        .as_object_mut()
        .unwrap()
        .remove(CANONICAL_METADATA);
    assert!(matches!(
        metadata::classify_request(&input, &headers),
        Err(ProtocolError::Invalid("metadata.canonical_body_missing"))
    ));
    let mut invalid = headers.clone();
    invalid.insert(CANONICAL_METADATA, HeaderValue::from_static("not-json"));
    assert!(matches!(
        metadata::classify_request(&body(&canonical), &invalid),
        Err(ProtocolError::Invalid("metadata.canonical"))
    ));
    let mut duplicate = headers.clone();
    duplicate.append(CANONICAL_METADATA, HeaderValue::from_static("{}"));
    assert!(matches!(
        metadata::classify_request(&body(&canonical), &duplicate),
        Err(ProtocolError::Invalid("metadata.duplicate_header"))
    ));
}

#[test]
fn ordinary_http_projection_stays_equal_except_body_only_inventory() {
    let canonical = current("turn", "native-turn");
    metadata::classify_request(&body(&canonical), &headers(&canonical, false)).unwrap();
    let mut changed = canonical.clone();
    changed["turn_id"] = json!("different-turn");
    assert!(matches!(
        metadata::classify_request(&body(&changed), &headers(&canonical, false)),
        Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"))
    ));
}

#[test]
fn failure_diagnostics_expose_shapes_and_fixed_names_without_identity_values() {
    let handshake = current("prewarm", "");
    let next = current("turn", "CLIENT_TURN_SECRET");
    let shape = metadata::diagnostic_shape(&body(&next), &headers(&handshake, true));
    assert_eq!(shape["websocket_handshake"], true);
    assert_eq!(shape["turn_is_string"], true);
    assert_eq!(shape["turn_is_empty"], false);
    assert_eq!(shape["turn_is_uuid"], false);
    assert_eq!(
        shape["different_fields"],
        json!(["turn_id", "request_kind", "tool_namespaces_info"])
    );
    assert!(!shape.to_string().contains("CLIENT_"));
    let mut malformed = body(&next);
    malformed["client_metadata"][CANONICAL_METADATA] = json!("CLIENT_SECRET_NOT_JSON");
    let shape = metadata::diagnostic_shape(&malformed, &headers(&handshake, true));
    assert_eq!(shape["canonical_body_valid"], false);
    assert!(!shape.to_string().contains("CLIENT_"));
}
