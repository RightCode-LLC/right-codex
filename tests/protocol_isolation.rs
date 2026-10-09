use http::{HeaderMap, HeaderValue};
use right_codex::metadata::{CANONICAL_METADATA, LITE_METADATA, RequestKind, TaskRole};
use right_codex::protocol::{IdentityKind, ProtocolError};
use right_codex::session::{
    AttemptState, ConnectionSideband, FileProvenance, Session, SessionStore, ToolDelivery,
};
use serde_json::{Value, json};

fn request(items: Value) -> Value {
    json!({"model":"gpt-test","input":items})
}

#[test]
fn realtime_call_aliases_are_persisted_only_with_their_actual_account_revision() {
    let mut session = Session::new("alpha".into(), "revision-one".into());
    session
        .register_realtime_call("local-call".into(), "upstream-call".into())
        .unwrap();
    assert_eq!(session.realtime_call("local-call"), Some("upstream-call"));
    assert!(
        session
            .register_realtime_call("local-call".into(), "different-call".into())
            .is_err()
    );
    assert!(
        session
            .register_realtime_call("other-local".into(), "upstream-call".into())
            .is_err()
    );
    let snapshot = session.snapshot().unwrap();
    let mut restored = Session::restore(snapshot.clone()).unwrap();
    assert_eq!(restored.realtime_call("local-call"), Some("upstream-call"));
    let mut foreign = snapshot.clone();
    foreign["realtime_calls"]["local-call"]["auth_revision"] = json!("different-revision");
    assert!(Session::restore(foreign).is_err());
    restored
        .switch_account("alpha".into(), "revision-two".into())
        .unwrap();
    assert_eq!(restored.realtime_call("local-call"), None);
    session
        .switch_account("beta".into(), "revision-one".into())
        .unwrap();
    assert_eq!(session.realtime_call("local-call"), None);
}

#[test]
fn connection_sideband_receipts_are_bounded_ordered_and_never_attempt_facts() {
    let mut session = Session::new("alpha".into(), "revision".into());
    let fact = ConnectionSideband {
        connection_id: "connection".into(),
        frame_index: 1,
        account_id: "alpha".into(),
        auth_revision: "revision".into(),
        kind: "codex.rate_limits".into(),
        raw_sha256: "a".repeat(64),
        bytes: 42,
        observed_at_unix_ms: 1,
        client_socket_written: true,
    };
    session.observe_connection_sideband(fact.clone()).unwrap();
    assert!(!session.connection_sidebands()[0].client_socket_written);
    assert!(session.observe_connection_sideband(fact.clone()).is_err());
    assert!(
        session
            .connection_sideband_written("connection", 1, &"b".repeat(64))
            .is_err()
    );
    session
        .connection_sideband_written("connection", 1, &"a".repeat(64))
        .unwrap();
    assert!(session.connection_sidebands()[0].client_socket_written);
    let mut foreign = fact.clone();
    foreign.frame_index = 2;
    foreign.auth_revision = "different".into();
    assert!(session.observe_connection_sideband(foreign).is_err());
    let snapshot = session.snapshot().unwrap();
    assert!(snapshot["attempts"].as_object().unwrap().is_empty());
    let restored = Session::restore(snapshot.clone()).unwrap();
    assert_eq!(restored.connection_sidebands().len(), 1);
    let mut forged = snapshot;
    forged["connection_sidebands"][0]["kind"] = json!("response.completed");
    assert!(Session::restore(forged).is_err());
}

#[test]
fn every_official_item_kind_gets_its_typed_id_prefix_and_same_label_never_crosses_types() {
    let mut session = Session::new("alpha".into(), "revision".into());
    let old = begin(&mut session, request(json!([])), "old");
    finish(
        &mut session,
        &old,
        json!([{"type":"compaction","id":"cmp_real","encrypted_content":"own-cipher"}]),
    );
    let mut items = vec![
        json!({"type":"additional_tools","role":"developer","tools":[]}),
        json!({"type":"message","role":"user","content":"hello"}),
        json!({"type":"agent_message","author":"worker","recipient":"root","content":[{"type":"input_text","text":"hello"}]}),
        json!({"type":"reasoning","summary":[]}),
        json!({"type":"local_shell_call","call_id":null,"status":"completed","action":{"type":"exec","command":["true"]}}),
        json!({"type":"function_call","name":"run","arguments":"{\"id\":\"literal\"}","call_id":"call-function"}),
        json!({"type":"tool_search_call","arguments":{"id":"literal"},"execution":"client","call_id":null}),
        json!({"type":"function_call_output","output":"literal","call_id":null}),
        json!({"type":"custom_tool_call","name":"run","input":"literal","call_id":"call-custom"}),
        json!({"type":"custom_tool_call_output","output":"literal","call_id":"call-custom"}),
        json!({"type":"tool_search_output","tools":[],"status":"completed","execution":"client","call_id":null}),
        json!({"type":"web_search_call","status":"completed","action":{"type":"search","query":"literal"}}),
        json!({"type":"image_generation_call","status":"completed","result":"base64-image"}),
        json!({"type":"compaction","encrypted_content":"own-cipher"}),
        json!({"type":"context_compaction","encrypted_content":"own-cipher"}),
    ];
    for item in &mut items {
        item["id"] = json!("shared-client-label");
        if item["type"] == "message" {
            item["content"] = json!([{"type":"input_text","text":"hello"}]);
        }
    }
    let prefixes = [
        "at", "msg", "amsg", "rs", "lsh", "fc", "tsc", "fco", "ctc", "ctco", "tso", "ws", "ig",
        "cmp", "cmp",
    ];
    for (item, prefix) in items.iter().zip(prefixes) {
        let official: codex_protocol::models::ResponseItem =
            serde_json::from_value(item.clone()).unwrap();
        assert_eq!(official.id_prefix(), Some(prefix));
    }
    let p = session
        .prepare_request(request(json!(items)), &HeaderMap::new(), "first")
        .unwrap();
    let first = session.commit_request(p).unwrap();
    for (item, prefix) in first.request.body["input"]
        .as_array()
        .unwrap()
        .iter()
        .zip(prefixes)
    {
        assert!(
            item["id"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{prefix}_"))
        );
        assert_ne!(item["id"], "shared-client-label");
    }
    assert_eq!(
        first.request.body["input"][5]["arguments"],
        "{\"id\":\"literal\"}"
    );
    assert_eq!(first.request.body["input"][6]["arguments"]["id"], "literal");
    assert_ne!(
        first.request.body["input"][0]["id"],
        first.request.body["input"][1]["id"]
    );
    session
        .switch_account("beta".into(), "other-revision".into())
        .unwrap();
    let p=session.prepare_request(request(json!([{"type":"additional_tools","id":"shared-client-label","role":"developer","tools":[]}])),&HeaderMap::new(),"second").unwrap();
    let second = session.commit_request(p).unwrap();
    assert!(
        second.request.body["input"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("at_")
    );
    assert_ne!(
        first.request.body["input"][0]["id"],
        second.request.body["input"][0]["id"]
    );
}

#[test]
fn nullable_call_delivery_needs_actual_item_source_and_never_invents_call_reference() {
    let mut session = Session::new("alpha".into(), "revision".into());
    begin(&mut session, request(json!([])), "turn");
    let item = json!({"type":"tool_search_call","id":"tsc_real","call_id":null,"execution":"client","arguments":{"id":"literal"}});
    assert!(
        session
            .record_delivery(&json!({"type":"response.output_item.done","item":item}))
            .is_err()
    );
    let mut event = json!({"type":"response.output_item.done","item":item});
    session.rewrite_event(&mut event).unwrap();
    assert_eq!(
        session.record_delivery(&event).unwrap(),
        ToolDelivery::Deliver
    );
    assert_eq!(
        session.record_delivery(&event).unwrap(),
        ToolDelivery::AlreadyDelivered
    );
    assert!(event["item"]["call_id"].is_null());
    assert!(
        !session
            .identifiers()
            .keys()
            .any(|(kind, _)| *kind == IdentityKind::Call)
    );
}

#[tokio::test]
async fn evicted_parent_lazily_loads_and_parallel_same_key_restores_share_one_live_scope() {
    let store = std::sync::Arc::new(SessionStore::default());
    let key = SessionStore::local_key("namespace", "parent");
    let arc = store
        .get_or_insert(key.clone(), "alpha".into(), "revision".into())
        .unwrap();
    let mut session = arc.lock().await;
    let id = begin(&mut session, request(json!([])), "turn");
    let event = finish(&mut session, &id, json!([]));
    let alias = event["response"]["id"].as_str().unwrap().to_owned();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("sessions");
    right_codex::storage::directory(&root).unwrap();
    right_codex::storage::save(&root, &key, &session).unwrap();
    drop(session);
    assert!(
        store
            .evict_idle_persisted(&key, &root.join(format!("{key}.json")), u64::MAX, 0)
            .unwrap()
    );
    assert!(store.get(&key).is_none());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let mut joins = vec![];
    for _ in 0..4 {
        let store = store.clone();
        let key = key.clone();
        let root = root.clone();
        let barrier = barrier.clone();
        joins.push(std::thread::spawn(move || {
            barrier.wait();
            store.get_or_load_scope(&key, &root).unwrap().unwrap()
        }));
    }
    let scopes: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert!(scopes.iter().all(|s| std::sync::Arc::ptr_eq(&scopes[0], s)));
    assert_eq!(
        store.scope_owner(&key, &root).unwrap(),
        Some(("alpha".into(), "revision".into()))
    );
    assert_eq!(
        store
            .parent_proof_for_response("namespace", "parent", "alpha", "revision", Some(alias))
            .unwrap()
            .response_id
            .as_deref(),
        Some("upstream-response")
    );
}

#[tokio::test]
async fn busy_parent_proof_uses_exact_persisted_created_response_and_scope() {
    let store = SessionStore::default();
    let key = SessionStore::local_key("namespace", "client-parent");
    let parent = store
        .get_or_insert(key.clone(), "alpha".into(), "revision".into())
        .unwrap();
    let mut held = parent.lock().await;
    let attempt = begin(
        &mut held,
        request(json!([{"role":"user","content":"parent"}])),
        "logical-parent-turn",
    );
    let mut created = json!({"type":"response.created","response":{"id":"real-parent-response","status":"in_progress"}});
    held.rewrite_event(&mut created).unwrap();
    let alias = created["response"]["id"].as_str().unwrap().to_owned();
    assert!(
        store
            .parent_proof_for_response(
                "namespace",
                "client-parent",
                "alpha",
                "revision",
                Some(alias.clone())
            )
            .is_none()
    );
    let directory = tempfile::tempdir().unwrap();
    let scopes = directory.path().join("sessions");
    right_codex::storage::directory(&scopes).unwrap();
    let file = scopes.join(format!("{key}.json"));
    let snapshot = held.snapshot().unwrap();
    let encoded = json!({"key":key,"session":snapshot});
    right_codex::storage::atomic(&file, &serde_json::to_vec(&encoded).unwrap()).unwrap();
    let proof = store
        .parent_proof_from_file(
            "namespace",
            "client-parent",
            "alpha",
            "revision",
            Some(alias.clone()),
            &scopes,
        )
        .unwrap();
    assert_eq!(proof.response_id.as_deref(), Some("real-parent-response"));
    assert_eq!(proof.thread_id, held.thread_id);
    assert!(
        store
            .parent_proof_from_file(
                "namespace",
                "client-parent",
                "alpha",
                "foreign-revision",
                Some(alias.clone()),
                &scopes
            )
            .is_none()
    );
    assert!(
        store
            .parent_proof_from_file(
                "namespace",
                "client-parent",
                "alpha",
                "revision",
                Some("unknown-alias".into()),
                &scopes
            )
            .is_none()
    );
    assert!(
        store
            .parent_proof_from_file(
                "other-namespace",
                "client-parent",
                "alpha",
                "revision",
                Some(alias.clone()),
                &scopes
            )
            .is_none()
    );
    // An actual unresolved persisted source never becomes resend permission.
    let restored = Session::restore(encoded["session"].clone()).unwrap();
    assert_eq!(
        restored.attempt(&attempt).unwrap().state,
        AttemptState::Unknown
    );
    let mut unknown = encoded.clone();
    unknown["session"]["attempts"][&attempt]["state"] = json!("unknown");
    right_codex::storage::atomic(&file, &serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(
        store
            .parent_proof_from_file(
                "namespace",
                "client-parent",
                "alpha",
                "revision",
                Some(alias.clone()),
                &scopes
            )
            .is_none()
    );
    right_codex::storage::atomic(&file, &serde_json::to_vec(&encoded).unwrap()).unwrap();
    drop(held);
    let proof = store
        .parent_proof_for_response(
            "namespace",
            "client-parent",
            "alpha",
            "revision",
            Some(alias),
        )
        .unwrap();
    assert_eq!(proof.response_id.as_deref(), Some("real-parent-response"));
}
fn canonical(body: &Value) -> Value {
    serde_json::from_str(
        body["client_metadata"][CANONICAL_METADATA]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}
fn with_metadata(mut body: Value, metadata: Value) -> Value {
    body["client_metadata"] = json!({CANONICAL_METADATA:metadata.to_string()});
    body
}
fn begin(session: &mut Session, body: Value, turn: &str) -> String {
    let p = session
        .prepare_request(body, &HeaderMap::new(), turn)
        .unwrap();
    let r = session.commit_request(p).unwrap();
    session.mark_sending(&r.attempt_id).unwrap();
    r.attempt_id
}
fn finish(session: &mut Session, attempt: &str, output: Value) -> Value {
    let mut event =
        json!({"type":"response.completed","response":{"id":"upstream-response","output":output}});
    session.rewrite_event(&mut event).unwrap();
    session.finish_attempt(attempt, &event).unwrap();
    event
}

#[test]
fn image_sized_native_history_roundtrip_does_not_hit_former_eight_mib_aggregate() {
    let directory = tempfile::TempDir::new().unwrap();
    let key = SessionStore::local_key("image-fixture", "thread");
    let mut session = Session::new("alpha".into(), "revision".into());
    let image = format!("data:image/png;base64,{}", "A".repeat(3 * 1024 * 1024));
    let mut input = vec![];
    for turn in 0..2 {
        input.push(json!({"type":"message","role":"user","content":[
            {"type":"input_text","text":"image fixture"},
            {"type":"input_image","image_url":image,"detail":"auto"}]}));
        let attempt = begin(&mut session, request(json!(input)), &format!("turn-{turn}"));
        let mut event = json!({"type":"response.completed","response":{
            "id":format!("upstream-image-response-{turn}"),"output":[{
                "type":"message","id":format!("upstream-message-{turn}"),"role":"assistant",
                "content":[{"type":"output_text","text":"image observed"}]}]}});
        session.rewrite_event(&mut event).unwrap();
        session.finish_attempt(&attempt, &event).unwrap();
        right_codex::storage::save(directory.path(), &key, &session).unwrap();
        session = right_codex::storage::load(directory.path(), &key)
            .unwrap()
            .unwrap();
    }
    assert_eq!(session.history().len(), 3);
    assert_eq!(session.history()[0]["content"][1]["image_url"], image);
    let bytes = std::fs::metadata(right_codex::storage::path(directory.path(), &key).unwrap())
        .unwrap()
        .len();
    assert!(bytes > 8 * 1024 * 1024);
    assert!(bytes < right_codex::session::MAX_PERSISTENCE_BYTES as u64);
}

#[test]
fn canonical_and_headers_are_one_gateway_projection() {
    let mut session = Session::new("account".into(), "revision".into());
    let incoming = json!({"request_kind":"turn","thread_id":"client-thread","session_id":"client-session","turn_id":"client-turn","window_id":"client-window","installation_id":"client-install","workspaces":{"/private/client":{"latest_git_commit_hash":"client-git"}},"agent_name":"client-name","analytics_enabled":true});
    let mut body = with_metadata(
        request(json!([{"role":"user","content":"hi"}])),
        incoming.clone(),
    );
    body["client_metadata"]["thread_id"] = json!("client-thread");
    let mut headers = HeaderMap::new();
    headers.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&incoming.to_string()).unwrap(),
    );
    let p = session
        .prepare_request(body, &headers, "gateway-turn")
        .unwrap();
    let r = session.commit_request(p).unwrap();
    let canonical = canonical(&r.request.body);
    assert_eq!(canonical["thread_id"], session.thread_id);
    assert_eq!(canonical["session_id"], session.session_id);
    assert_eq!(canonical["turn_id"], r.upstream_turn_id);
    assert_ne!(canonical["turn_id"], "gateway-turn");
    let wire = serde_json::to_string(&r.request.body["client_metadata"]).unwrap();
    for secret in [
        "client-thread",
        "client-session",
        "client-turn",
        "client-window",
        "client-install",
        "client-git",
        "client-name",
        "/private/client",
    ] {
        assert!(!wire.contains(secret));
    }
    assert_eq!(canonical["analytics_enabled"], true);
    assert_eq!(
        serde_json::from_str::<Value>(r.outbound_headers[CANONICAL_METADATA].to_str().unwrap())
            .unwrap(),
        canonical
    );
}

#[test]
fn compatible_header_omits_inventory_but_mismatch_is_rejected() {
    let metadata = json!({"request_kind":"turn","thread_id":"client","tool_namespaces_info":{}});
    let body = with_metadata(request(json!([])), metadata.clone());
    let mut compatible = metadata.clone();
    compatible
        .as_object_mut()
        .unwrap()
        .remove("tool_namespaces_info");
    let mut headers = HeaderMap::new();
    headers.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&compatible.to_string()).unwrap(),
    );
    let session = Session::new("a".into(), "r".into());
    assert!(
        session
            .prepare_request(body.clone(), &headers, "turn")
            .is_ok()
    );
    compatible["thread_id"] = json!("foreign");
    headers.insert(
        CANONICAL_METADATA,
        HeaderValue::from_str(&compatible.to_string()).unwrap(),
    );
    assert!(matches!(
        session.prepare_request(body, &headers, "turn"),
        Err(ProtocolError::Invalid("metadata.canonical_header_mismatch"))
    ));
}

#[test]
fn request_kind_and_roles_do_not_run_client_work_again() {
    for (kind, source, subagent, guardian, expected) in [
        ("turn", "thread_title", None, None, TaskRole::Title),
        (
            "turn",
            "subagent",
            Some("collab_spawn"),
            None,
            TaskRole::Subagent,
        ),
        ("turn", "subagent", Some("review"), None, TaskRole::Review),
        (
            "memory",
            "memory_consolidation",
            None,
            None,
            TaskRole::Memory,
        ),
        (
            "turn",
            "guardian_review",
            Some("guardian"),
            Some("reviewer"),
            TaskRole::GuardianReviewer,
        ),
    ] {
        let mut body = with_metadata(
            request(json!([])),
            json!({"request_kind":kind,"thread_source":source}),
        );
        let mut headers = HeaderMap::new();
        if let Some(subagent) = subagent {
            body["client_metadata"]["x-openai-subagent"] = json!(subagent);
        }
        if let Some(guardian) = guardian {
            headers.insert("x-codex-guardian", HeaderValue::from_str(guardian).unwrap());
        }
        let mut session = Session::new("a".into(), "r".into());
        let p = session.prepare_request(body, &headers, "turn").unwrap();
        let scoped = session.commit_request(p).unwrap();
        assert_eq!(scoped.metadata.role, expected);
        if scoped.metadata.kind == RequestKind::Memory {
            assert!(canonical(&scoped.request.body).get("thread_id").is_none());
        }
    }
}

#[test]
fn lite_and_direct_preserve_preprocessed_semantics_and_free_json() {
    let mut body = request(
        json!([{"type":"additional_tools","id":"at-local","role":"developer","tools":[{"type":"function","name":"run","parameters":{"properties":{"id":{"const":"free-id"}}}}]},{"type":"message","id":"msg-local","role":"developer","content":[{"type":"input_text","text":"native instructions"}]},{"type":"function_call_output","id":"direct-local","call_id":null,"name":"send_message_to_thread","namespace":"codex_app","output":"native message"}]),
    );
    body["instructions"] = json!("");
    body["client_metadata"] = json!({LITE_METADATA:"true"});
    let mut session = Session::new("a".into(), "r".into());
    let p = session
        .prepare_request(body.clone(), &HeaderMap::new(), "turn")
        .unwrap();
    let r = session.commit_request(p).unwrap();
    assert_eq!(
        r.request.body["input"][0]["tools"],
        body["input"][0]["tools"]
    );
    assert!(r.request.body["input"][2].get("call_id").is_none());
    assert_ne!(r.request.body["input"][0]["id"], "at-local");
    assert_eq!(
        r.outbound_headers["x-openai-internal-codex-responses-lite"],
        "true"
    );
}

#[test]
fn staged_mapping_and_stale_prepare_never_overwrite_current_aliases() {
    let mut session = Session::new("a".into(), "r".into());
    let before = session.snapshot().unwrap();
    let mut body = request(json!([{"id":"new","role":"user","content":"hi"}]));
    body["unknown"] = json!(true);
    assert!(
        session
            .prepare_request(body, &HeaderMap::new(), "turn")
            .is_err()
    );
    assert_eq!(session.snapshot().unwrap(), before);
    let p = session
        .prepare_request(request(json!([])), &HeaderMap::new(), "turn")
        .unwrap();
    let mut event = json!({"type":"response.created","response":{"id":"actual","output":[]}});
    session.rewrite_event(&mut event).unwrap();
    assert!(matches!(
        session.commit_request(p),
        Err(ProtocolError::Invalid("session.stale_prepare"))
    ));
}

#[test]
fn own_upstream_metadata_is_normalized_only_in_durable_history_not_delivered_wire() {
    for terminal_has_items in [false, true] {
        let mut session = Session::new("alpha".into(), "revision".into());
        let first = begin(
            &mut session,
            request(json!([{ "role":"user", "content":"run" }])),
            "first",
        );
        let call = json!({"type":"custom_tool_call","id":"ctc_actual","call_id":"call_actual","name":"execute","input":"literal metadata JSON","metadata":{"turn_id":"backend-turn"}});
        let official: codex_protocol::models::ResponseItem =
            serde_json::from_value(call.clone()).unwrap();
        assert!(
            serde_json::to_value(official)
                .unwrap()
                .get("metadata")
                .is_none()
        );
        let mut done = json!({"type":"response.output_item.done","item":call.clone()});
        session.rewrite_event(&mut done).unwrap();
        session.record_delivery(&done).unwrap();
        assert_eq!(done["item"]["metadata"]["turn_id"], "backend-turn");
        let completed = finish(
            &mut session,
            &first,
            if terminal_has_items {
                json!([call])
            } else {
                json!([])
            },
        );
        if terminal_has_items {
            assert_eq!(
                completed["response"]["output"][0]["metadata"]["turn_id"],
                "backend-turn"
            );
        }
        assert!(session.history()[1].get("metadata").is_none());
        let mut follow = request(
            json!([{"type":"custom_tool_call_output","call_id":done["item"]["call_id"],"output":"result"}]),
        );
        follow["previous_response_id"] = completed["response"]["id"].clone();
        let prepared = session
            .prepare_request(follow, &HeaderMap::new(), "follow")
            .unwrap();
        let scoped = session.commit_request(prepared).unwrap();
        assert_eq!(scoped.request.body["input"][1]["call_id"], "call_actual");
        assert_eq!(scoped.request.body["input"][2]["call_id"], "call_actual");
        assert!(scoped.request.body["input"][1].get("metadata").is_none());
        assert_eq!(
            scoped.request.body["input"][1]["input"],
            "literal metadata JSON"
        );
    }

    let mut partial = Session::new("alpha".into(), "revision".into());
    let id = begin(&mut partial, request(json!([])), "partial");
    let mut event = json!({"type":"response.output_item.done","item":{"type":"message","id":"msg_partial","role":"assistant","content":[{"type":"output_text","text":"literal","annotations":[]}],"metadata":{"turn_id":"backend-partial"}}});
    partial.rewrite_event(&mut event).unwrap();
    partial.record_delivery(&event).unwrap();
    let continuation = partial
        .continuation_request(&id, request(json!([])))
        .unwrap();
    assert!(continuation["input"][0].get("metadata").is_none());
    assert_eq!(event["item"]["metadata"]["turn_id"], "backend-partial");

    let before = partial.snapshot().unwrap();
    assert!(partial.prepare_request(request(json!([{"type":"message","role":"user","content":"hello","metadata":{"turn_id":"client-field"}}])), &HeaderMap::new(), "unknown-client-field").is_err());
    assert_eq!(partial.snapshot().unwrap(), before);
}

#[test]
fn empty_completed_envelope_retains_actual_done_calls_for_full_and_incremental_history() {
    for (kind, output_kind, payload) in [
        (
            "function_call",
            "function_call_output",
            json!({"arguments":"{\"id\":\"literal\"}"}),
        ),
        (
            "custom_tool_call",
            "custom_tool_call_output",
            json!({"input":"literal source"}),
        ),
    ] {
        let mut session = Session::new("alpha".into(), "revision-one".into());
        let original = json!({"type":"message","role":"user","content":"run a tool"});
        let id = begin(&mut session, request(json!([original.clone()])), "turn");
        let mut item = json!({"type":kind,"id":"actual-item","call_id":"actual-call","name":"run"});
        item.as_object_mut()
            .unwrap()
            .extend(payload.as_object().unwrap().clone());
        let mut done = json!({"type":"response.output_item.done","output_index":0,"item":item});
        session.rewrite_event(&mut done).unwrap();
        session.record_delivery(&done).unwrap();
        let terminal = finish(&mut session, &id, json!([]));
        assert_eq!(terminal["response"]["output"], json!([]));
        assert_eq!(session.history().len(), 2);
        let alias = done["item"]["call_id"].clone();
        let output = json!({"type":output_kind,"call_id":alias,"output":"literal result"});
        let before = session.snapshot().unwrap();
        assert!(
            session
                .prepare_request(
                    request(json!([output.clone()])),
                    &HeaderMap::new(),
                    "orphan"
                )
                .is_err()
        );
        assert_eq!(session.snapshot().unwrap(), before);

        // Full HTTP input and native WS delta both retain the exact call
        // declaration before the output, never merely a local alias entry.
        let full = request(json!([
            original.clone(),
            done["item"].clone(),
            output.clone()
        ]));
        let prepared = session
            .prepare_request(full, &HeaderMap::new(), "full")
            .unwrap();
        let scoped = session.commit_request(prepared).unwrap();
        assert_eq!(scoped.request.body["input"][1]["call_id"], "actual-call");
        assert_eq!(scoped.request.body["input"][2]["call_id"], "actual-call");

        let mut restored = Session::restore(before).unwrap();
        let mut delta = request(json!([output]));
        delta["previous_response_id"] = terminal["response"]["id"].clone();
        let prepared = restored
            .prepare_request(delta.clone(), &HeaderMap::new(), "delta")
            .unwrap();
        let scoped = restored.commit_request(prepared).unwrap();
        assert!(scoped.request.body.get("previous_response_id").is_none());
        assert_eq!(scoped.request.body["input"].as_array().unwrap().len(), 3);
        assert_eq!(scoped.request.body["input"][1]["type"], kind);
        assert_eq!(scoped.request.body["input"][2]["type"], output_kind);
        assert_eq!(scoped.request.body["input"][1]["call_id"], "actual-call");
        assert_eq!(scoped.request.body["input"][2]["call_id"], "actual-call");

        restored
            .switch_account("beta".into(), "revision-two".into())
            .unwrap();
        let prepared = restored
            .prepare_request(delta, &HeaderMap::new(), "switched")
            .unwrap();
        let fresh = restored.commit_request(prepared).unwrap();
        assert_ne!(fresh.request.body["input"][1]["call_id"], "actual-call");
        assert_eq!(
            fresh.request.body["input"][1]["call_id"],
            fresh.request.body["input"][2]["call_id"]
        );
        assert_eq!(fresh.request.body["input"][2]["output"], "literal result");
    }
}

#[test]
fn previous_response_expands_only_a_known_completed_local_history() {
    let mut session = Session::new("a".into(), "r".into());
    let id = begin(
        &mut session,
        request(json!([{"role":"user","content":"first"}])),
        "turn",
    );
    let done = finish(
        &mut session,
        &id,
        json!([{"type":"message","id":"upstream-msg","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]),
    );
    let mut body = request(json!([{"role":"user","content":"second"}]));
    body["previous_response_id"] = done["response"]["id"].clone();
    let p = session
        .prepare_request(body, &HeaderMap::new(), "next")
        .unwrap();
    let r = session.commit_request(p).unwrap();
    assert_eq!(r.request.body["input"].as_array().unwrap().len(), 3);
    assert!(r.request.body.get("previous_response_id").is_none());
    let mut foreign = request(json!([]));
    foreign["previous_response_id"] = json!("foreign");
    assert!(
        session
            .prepare_request(foreign, &HeaderMap::new(), "next")
            .is_err()
    );
}

#[test]
fn account_revision_switch_changes_every_upstream_domain_and_memento_replays_plaintext() {
    let mut session = Session::new("a".into(), "r1".into());
    let old = (
        session.thread_id.clone(),
        session.session_id.clone(),
        session.cache_key.clone(),
        session.window_id.clone(),
    );
    let id = begin(
        &mut session,
        request(json!([{"role":"user","content":"remember"},{"type":"compaction_trigger"}])),
        "turn",
    );
    finish(
        &mut session,
        &id,
        json!([{"type":"compaction","id":"comp-up","encrypted_content":"own-cipher"}]),
    );
    session
        .set_sticky_from_upstream("a", "r1", "sticky".into())
        .unwrap();
    session.switch_account("b".into(), "r2".into()).unwrap();
    assert_ne!(
        old,
        (
            session.thread_id.clone(),
            session.session_id.clone(),
            session.cache_key.clone(),
            session.window_id.clone()
        )
    );
    assert!(session.verified_opaque.is_empty());
    let body = request(
        json!([{"type":"compaction","encrypted_content":"own-cipher"},{"role":"user","content":"continue"}]),
    );
    let p = session
        .prepare_request(body, &HeaderMap::new(), "next")
        .unwrap();
    let r = session.commit_request(p).unwrap();
    assert_eq!(
        r.request.body["input"][0]["content"],
        json!([{"type":"input_text","text":"remember"}])
    );
    assert!(!r.request.body.to_string().contains("own-cipher"));
    assert!(!r.outbound_headers.contains_key("x-codex-turn-state"));
}

#[test]
fn file_reference_requires_current_content_provenance() {
    let mut session = Session::new("a".into(), "r".into());
    let image =
        request(json!([{"role":"user","content":[{"type":"input_image","file_id":"file-local"}]}]));
    assert!(
        session
            .prepare_request(image.clone(), &HeaderMap::new(), "turn")
            .is_err()
    );
    session
        .register_file(FileProvenance {
            account_id: "a".into(),
            auth_revision: "r".into(),
            client_id: "file-local".into(),
            upstream_id: "file-own".into(),
            content_sha256: "a".repeat(64),
        })
        .unwrap();
    let p = session
        .prepare_request(image.clone(), &HeaderMap::new(), "turn")
        .unwrap();
    let r = session.commit_request(p).unwrap();
    assert_eq!(
        r.request.body["input"][0]["content"][0]["file_id"],
        "file-own"
    );
    session
        .switch_account("a".into(), "new-revision".into())
        .unwrap();
    assert!(
        session
            .prepare_request(image, &HeaderMap::new(), "next")
            .is_err()
    );
}

#[test]
fn restart_preserves_unknown_and_cannot_replay_the_send() {
    let mut session = Session::new("a".into(), "r".into());
    let id = begin(&mut session, request(json!([])), "turn");
    let mut restored = Session::restore(session.snapshot().unwrap()).unwrap();
    assert_eq!(restored.attempt(&id).unwrap().state, AttemptState::Unknown);
    assert!(restored.mark_sending(&id).is_err());
    assert!(!restored.is_idle(u64::MAX, 1));
    restored.cancel_attempt(&id).unwrap();
    assert!(restored.is_idle(u64::MAX, 1));
}

#[test]
fn completed_cipher_and_terminal_are_atomic_and_scope_bound() {
    let mut session = Session::new("a".into(), "r".into());
    let id = begin(&mut session, request(json!([])), "turn");
    let mut event = json!({"type":"response.incomplete","response":{"id":"up","output":[{"type":"reasoning","summary":[],"encrypted_content":"partial"}]}});
    session.rewrite_event(&mut event).unwrap();
    session.finish_attempt(&id, &event).unwrap();
    assert!(session.verified_opaque.is_empty());
    assert_eq!(session.attempt(&id).unwrap().state, AttemptState::Failed);
    assert!(
        session
            .finish_attempt(
                &id,
                &json!({"type":"response.completed","response":{"id":"up","output":[]}})
            )
            .is_err()
    );
}

#[test]
fn duplicate_tool_write_is_scoped_to_logical_turn_and_never_an_execution_fact() {
    let mut session = Session::new("a".into(), "r".into());
    let id = begin(&mut session, request(json!([])), "logical-turn");
    let mut event = json!({"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc-1","call_id":"call-1","name":"run","arguments":"{\"id\":\"literal\"}"}});
    session.rewrite_event(&mut event).unwrap();
    assert_eq!(
        session.record_delivery(&event).unwrap(),
        ToolDelivery::Deliver
    );
    assert_eq!(
        session.record_delivery(&event).unwrap(),
        ToolDelivery::AlreadyDelivered
    );
    session.mark_unknown(&id).unwrap();
    let continued = session
        .continuation_request(&id, request(json!([])))
        .unwrap();
    assert_eq!(continued["input"][0]["arguments"], "{\"id\":\"literal\"}");
    session.switch_account("b".into(), "r2".into()).unwrap();
    let new = begin(&mut session, continued, "logical-turn");
    let mut event2 = json!({"type":"response.output_item.done","item":{"type":"function_call","id":"fc-2","call_id":"call-2","name":"run","arguments":"{\"id\":\"literal\"}"}});
    session.rewrite_event(&mut event2).unwrap();
    assert_eq!(
        session.record_delivery(&event2).unwrap(),
        ToolDelivery::AlreadyDelivered
    );
    assert_eq!(session.attempt(&new).unwrap().state, AttemptState::Sending);
}

#[test]
fn namespaces_and_plain_agent_messages_do_not_rewrite_free_business_text() {
    let mut session = Session::new("a".into(), "r".into());
    let body = request(
        json!([{"type":"agent_message","id":"same","author":"worker","recipient":"root","content":[{"type":"input_text","text":"id=client-uuid"}]},{"type":"local_shell_call","id":"same","call_id":"same","status":"completed","action":{"type":"exec","command":["echo","client-uuid"],"env":{"ID":"client-uuid"}}}]),
    );
    let p = session
        .prepare_request(body, &HeaderMap::new(), "turn")
        .unwrap();
    let scoped = session.commit_request(p).unwrap();
    assert_ne!(
        scoped.request.body["input"][1]["id"],
        scoped.request.body["input"][1]["call_id"]
    );
    assert_eq!(scoped.request.body["input"][0]["author"], "worker");
    assert_eq!(
        scoped.request.body["input"][1]["action"]["env"]["ID"],
        "client-uuid"
    );
    assert!(
        scoped.request.body["input"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("amsg_")
    );
    assert!(
        scoped.request.body["input"][1]["id"]
            .as_str()
            .unwrap()
            .starts_with("lsh_")
    );
}

#[test]
fn parent_proof_is_registered_and_never_cross_account() {
    let mut parent = Session::new("a".into(), "r".into());
    assert!(parent.parent_proof(None, None).is_err());
    let id = begin(&mut parent, request(json!([])), "turn");
    let done = finish(&mut parent, &id, json!([]));
    let proof = parent
        .parent_proof(
            Some("turn".into()),
            Some(done["response"]["id"].as_str().unwrap().into()),
        )
        .unwrap();
    let mut body = request(json!([]));
    body["client_metadata"] = json!({"parent_response_id":"client-parent"});
    let mut headers = HeaderMap::new();
    headers.insert("x-codex-guardian", HeaderValue::from_static("reviewer"));
    let mut child = Session::new("a".into(), "r".into());
    let p = child
        .prepare_request_with_parent(body.clone(), &headers, "child", Some(&proof))
        .unwrap();
    let r = child.commit_request(p).unwrap();
    assert_eq!(
        r.request.body["client_metadata"]["parent_response_id"],
        "upstream-response"
    );
    child.switch_account("b".into(), "new".into()).unwrap();
    assert!(
        child
            .prepare_request_with_parent(body, &headers, "child", Some(&proof))
            .is_err()
    );
}

#[tokio::test]
async fn protected_persistence_and_configured_capacity_do_not_evict_unknown() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("private");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = SessionStore::with_capacity(1).unwrap();
    let key = SessionStore::local_key("client", "thread");
    let session = store
        .get_or_insert(key.clone(), "a".into(), "r".into())
        .unwrap();
    let id = {
        let mut s = session.lock().await;
        begin(&mut s, request(json!([])), "turn")
    };
    let path = dir.join("all.json");
    store.save(&path).await.unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = SessionStore::load(&path).unwrap();
    let arc = loaded.get(&key).unwrap();
    assert_eq!(
        arc.lock().await.attempt(&id).unwrap().state,
        AttemptState::Unknown
    );
    assert!(
        store
            .get_or_insert("other".into(), "b".into(), "r".into())
            .is_none()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SessionStore::load(&path).is_err());
}

#[test]
fn same_turn_identical_distinct_calls_are_not_collapsed_and_replay_uses_slots() {
    let mut session = Session::new("a".into(), "r".into());
    let first = begin(&mut session, request(json!([])), "logical");
    for number in 0..2 {
        let mut event = json!({"type":"response.output_item.done","item":{"type":"function_call","id":format!("fc-{number}"),"call_id":format!("call-{number}"),"name":"run","arguments":"{}"}});
        session.rewrite_event(&mut event).unwrap();
        assert_eq!(
            session.record_delivery(&event).unwrap(),
            ToolDelivery::Deliver
        );
    }
    session.mark_unknown(&first).unwrap();
    let full = session
        .continuation_request(&first, request(json!([])))
        .unwrap();
    session.switch_account("b".into(), "r2".into()).unwrap();
    begin(&mut session, full, "logical");
    for number in 0..3 {
        let mut event = json!({"type":"response.output_item.done","item":{"type":"function_call","id":format!("new-fc-{number}"),"call_id":format!("new-call-{number}"),"name":"run","arguments":"{}"}});
        session.rewrite_event(&mut event).unwrap();
        assert_eq!(
            session.record_delivery(&event).unwrap(),
            if number < 2 {
                ToolDelivery::AlreadyDelivered
            } else {
                ToolDelivery::Deliver
            }
        );
    }
}

#[test]
fn partial_call_added_does_not_claim_a_tool_was_dispatched() {
    let mut session = Session::new("a".into(), "r".into());
    begin(&mut session, request(json!([])), "logical");
    let mut added = json!({"type":"response.output_item.added","item":{"type":"function_call","id":"fc","call_id":"call","name":"run","arguments":""}});
    session.rewrite_event(&mut added).unwrap();
    assert_eq!(
        session.record_delivery(&added).unwrap(),
        ToolDelivery::Deliver
    );
    let mut done = added;
    done["type"] = json!("response.output_item.done");
    done["item"]["arguments"] = json!("{}");
    assert_eq!(
        session.record_delivery(&done).unwrap(),
        ToolDelivery::Deliver
    );
}

#[test]
fn same_logical_turn_has_a_new_outbound_identity_after_switch() {
    let mut session = Session::new("a".into(), "r".into());
    let prepared = session
        .prepare_request(request(json!([])), &HeaderMap::new(), "logical")
        .unwrap();
    let first = session.commit_request(prepared).unwrap();
    session.switch_account("b".into(), "r2".into()).unwrap();
    let prepared = session
        .prepare_request(request(json!([])), &HeaderMap::new(), "logical")
        .unwrap();
    let next = session.commit_request(prepared).unwrap();
    assert_ne!(first.upstream_turn_id, next.upstream_turn_id);
    assert_eq!(
        canonical(&next.request.body)["turn_id"],
        next.upstream_turn_id
    );
    assert_eq!(
        session.attempt(&first.attempt_id).unwrap().turn_id,
        session.attempt(&next.attempt_id).unwrap().turn_id
    );
}

#[test]
fn tool_identity_fields_are_rejected_but_schema_identity_words_are_preserved() {
    let session = Session::new("a".into(), "r".into());
    let mut body = request(json!([]));
    body["tools"] = json!([{"type":"function","name":"run","id":"client-secret","parameters":{"properties":{"id":{"const":"literal"}}}}]);
    assert!(
        matches!(session.prepare_request(body.clone(),&HeaderMap::new(),"turn"),Err(ProtocolError::Unsupported(ref field)) if field=="tools.item.id")
    );
    body["tools"][0].as_object_mut().unwrap().remove("id");
    let p = session
        .prepare_request(body, &HeaderMap::new(), "turn")
        .unwrap();
    let mut session = session;
    let projected = session.commit_request(p).unwrap();
    assert_eq!(
        projected.request.body["tools"][0]["parameters"]["properties"]["id"]["const"],
        "literal"
    );
}

#[test]
fn real_done_items_support_a_completed_terminal_without_repeated_output() {
    let mut session = Session::new("a".into(), "r".into());
    let attempt = begin(
        &mut session,
        request(json!([{"role":"user","content":"remember"},{"type":"compaction_trigger"}])),
        "turn",
    );
    let mut output = json!({"type":"response.output_item.done","item":{"type":"compaction","id":"comp","encrypted_content":"native-own"}});
    session.rewrite_event(&mut output).unwrap();
    let mut done = json!({"type":"response.completed","response":{"id":"response-without-output"}});
    session.rewrite_event(&mut done).unwrap();
    session.finish_attempt(&attempt, &done).unwrap();
    assert!(session.verified_opaque.contains("native-own"));
    assert_eq!(
        session.attempt(&attempt).unwrap().state,
        AttemptState::Completed
    );
}

fn delivered_parent_message(namespace: &str, name: &str, delivered: bool) -> Session {
    let mut parent = Session::new("alpha".into(), "revision".into());
    let attempt = begin(&mut parent, request(json!([])), "parent-turn");
    let mut created =
        json!({"type":"response.created","response":{"id":"actual-parent","status":"in_progress"}});
    parent.rewrite_event(&mut created).unwrap();
    let mut done = json!({"type":"response.output_item.done","response_id":"actual-parent","item":{
        "type":"function_call","id":"fc_actual","call_id":"call_actual","namespace":namespace,"name":name,
        "arguments":json!({"message":"parent-actual-cipher","task_name":"child"}).to_string()
    }});
    parent.rewrite_event(&mut done).unwrap();
    if delivered {
        parent.record_delivery(&done).unwrap();
    }
    assert_eq!(
        parent.attempt(&attempt).unwrap().state,
        AttemptState::Sending
    );
    parent
}
fn child_encrypted_message(cipher: &str) -> Value {
    with_metadata(
        request(
            json!([{"type":"agent_message","id":"amsg_client","author":"root","recipient":"root/child",
        "content":[{"type":"input_text","text":"Message Type: NEW_TASK"},{"type":"encrypted_content","encrypted_content":cipher}]}]),
        ),
        json!({"request_kind":"turn","thread_id":"child","parent_thread_id":"parent"}),
    )
}
fn child_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-openai-subagent",
        HeaderValue::from_static("thread_spawn"),
    );
    headers
}
#[test]
fn actual_delivered_parent_collaboration_cipher_is_only_agent_message_authority() {
    for name in ["spawn_agent", "send_message", "followup_task"] {
        let parent = delivered_parent_message("collaboration", name, true);
        let proof = parent.parent_proof(None, None).unwrap();
        let mut child = Session::new("alpha".into(), "revision".into());
        let prepared = child
            .prepare_request_with_parent(
                child_encrypted_message("parent-actual-cipher"),
                &child_headers(),
                "child-turn",
                Some(&proof),
            )
            .unwrap();
        let scoped = child.commit_request(prepared).unwrap();
        assert_eq!(
            scoped.request.body["input"][0]["content"][1]["encrypted_content"],
            "parent-actual-cipher"
        );
        assert!(child.verified_opaque.is_empty());
        let reasoning = with_metadata(
            request(
                json!([{"type":"reasoning","summary":[],"encrypted_content":"parent-actual-cipher"}]),
            ),
            json!({"request_kind":"turn","thread_id":"child","parent_thread_id":"parent"}),
        );
        let prepared = child
            .prepare_request_with_parent(
                reasoning,
                &child_headers(),
                "reasoning-turn",
                Some(&proof),
            )
            .unwrap();
        assert!(
            child.commit_request(prepared).unwrap().request.body["input"][0]
                .get("encrypted_content")
                .is_none()
        );
        let compaction = with_metadata(
            request(json!([{"type":"compaction","encrypted_content":"parent-actual-cipher"}])),
            json!({"request_kind":"turn","thread_id":"child","parent_thread_id":"parent"}),
        );
        assert!(
            child
                .prepare_request_with_parent(
                    compaction,
                    &child_headers(),
                    "compact-turn",
                    Some(&proof)
                )
                .is_err()
        );
        child.switch_account("beta".into(), "other".into()).unwrap();
        assert!(
            child
                .prepare_request_with_parent(
                    child_encrypted_message("parent-actual-cipher"),
                    &child_headers(),
                    "foreign-turn",
                    Some(&proof)
                )
                .is_err()
        );
    }
}
#[test]
fn parent_cipher_rejects_unwritten_other_tools_other_cipher_and_unrelated_role() {
    for (namespace, name, delivered) in [
        ("collaboration", "spawn_agent", false),
        ("functions", "spawn_agent", true),
        ("collaboration", "wait", true),
    ] {
        let parent = delivered_parent_message(namespace, name, delivered);
        let proof = parent.parent_proof(None, None).unwrap();
        let child = Session::new("alpha".into(), "revision".into());
        assert!(
            child
                .prepare_request_with_parent(
                    child_encrypted_message("parent-actual-cipher"),
                    &child_headers(),
                    "child",
                    Some(&proof)
                )
                .is_err()
        );
    }
    let parent = delivered_parent_message("collaboration", "spawn_agent", true);
    let proof = parent.parent_proof(None, None).unwrap();
    let child = Session::new("alpha".into(), "revision".into());
    assert!(
        child
            .prepare_request_with_parent(
                child_encrypted_message("other-cipher"),
                &child_headers(),
                "child",
                Some(&proof)
            )
            .is_err()
    );
    assert!(
        child
            .prepare_request_with_parent(
                child_encrypted_message("parent-actual-cipher"),
                &HeaderMap::new(),
                "ordinary",
                Some(&proof)
            )
            .is_err()
    );
    let changed = Session::new("alpha".into(), "new-revision".into());
    assert!(
        changed
            .prepare_request_with_parent(
                child_encrypted_message("parent-actual-cipher"),
                &child_headers(),
                "child",
                Some(&proof)
            )
            .is_err()
    );
}
#[tokio::test]
async fn busy_parent_message_proof_reads_delivered_source_from_protected_same_scope() {
    let store = SessionStore::default();
    let key = SessionStore::local_key("namespace", "parent");
    let parent = store
        .get_or_insert(key.clone(), "alpha".into(), "revision".into())
        .unwrap();
    let mut held = parent.lock().await;
    *held = delivered_parent_message("collaboration", "spawn_agent", true);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("sessions");
    right_codex::storage::directory(&root).unwrap();
    right_codex::storage::save(&root, &key, &held).unwrap();
    assert!(
        store
            .parent_proof_for_response("namespace", "parent", "alpha", "revision", None)
            .is_none()
    );
    let proof = store
        .parent_proof_from_file("namespace", "parent", "alpha", "revision", None, &root)
        .unwrap();
    let child = Session::new("alpha".into(), "revision".into());
    assert!(
        child
            .prepare_request_with_parent(
                child_encrypted_message("parent-actual-cipher"),
                &child_headers(),
                "child",
                Some(&proof)
            )
            .is_ok()
    );
    for (ns, parent, account, rev) in [
        ("foreign", "parent", "alpha", "revision"),
        ("namespace", "other", "alpha", "revision"),
        ("namespace", "parent", "beta", "revision"),
        ("namespace", "parent", "alpha", "new"),
    ] {
        assert!(
            store
                .parent_proof_from_file(ns, parent, account, rev, None, &root)
                .is_none()
        );
    }
}
#[test]
fn auxiliary_local_turn_survives_switch_but_upstream_turn_is_fresh() {
    let mut session = Session::new("alpha".into(), "revision".into());
    let attempt = begin(&mut session, request(json!([])), "local-turn");
    finish(&mut session, &attempt, json!([]));
    let old = session.bind_auxiliary_turn("local-turn").unwrap();
    session
        .switch_account("beta".into(), "other".into())
        .unwrap();
    let fresh = session.bind_auxiliary_turn("local-turn").unwrap();
    assert_ne!(old, fresh);
    assert_eq!(session.bind_auxiliary_turn("local-turn").unwrap(), fresh);
    assert!(session.bind_auxiliary_turn("unregistered").is_err());
    let mut restored = Session::restore(session.snapshot().unwrap()).unwrap();
    assert_eq!(restored.bind_auxiliary_turn("local-turn").unwrap(), fresh);
}
