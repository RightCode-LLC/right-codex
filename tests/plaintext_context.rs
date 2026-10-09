//! User contract: prompt text is business content, never a protocol identity.
use http::{HeaderMap, HeaderValue};
use right_codex::{metadata::ParentMetadataProof, session::Session};
use serde_json::{Value, json};

const SOURCE: &str = "01a12255-7059-70d1-a991-59eb8fb86894";

fn parent() -> ParentMetadataProof {
    let mut session = Session::new("alpha".into(), "revision-one".into());
    let prepared = session
        .prepare_request(
            json!({"model":"gpt-test","input":[]}),
            &HeaderMap::new(),
            "turn",
        )
        .unwrap();
    let request = session.commit_request(prepared).unwrap();
    session.mark_sending(&request.attempt_id).unwrap();
    session.parent_proof(None, None).unwrap()
}

#[test]
fn guardian_text_keeps_source_ids_while_protocol_parent_uses_its_proof() {
    let proof = parent();
    for websocket in [false, true] {
        for proven in [false, true] {
            let mut headers = HeaderMap::new();
            headers.insert("x-codex-guardian", HeaderValue::from_static("reviewer"));
            if websocket {
                headers.insert("upgrade", HeaderValue::from_static("websocket"));
            }
            let text = format!("Reviewed Codex session id: {SOURCE}\n");
            let input = json!([{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}]);
            let mut session = Session::new("alpha".into(), "revision-one".into());
            let prepared = session.prepare_request_with_parent(
                json!({"model":"gpt-test","input":input,
                    "instructions":format!("Review /Users/example/{SOURCE}/workspace"),
                    "client_metadata":{"thread_id":"reviewer-client-thread","x-codex-parent-thread-id":SOURCE}}),
                &headers,"review",proven.then_some(&proof)).unwrap();
            let request = session.commit_request(prepared).unwrap();
            assert_eq!(request.request.body["input"], input);
            assert_eq!(
                request.request.body["instructions"],
                format!("Review /Users/example/{SOURCE}/workspace")
            );
            if proven {
                assert_eq!(
                    request.outbound_headers["x-codex-parent-thread-id"],
                    proof.thread_id
                );
            } else {
                assert!(
                    !request
                        .outbound_headers
                        .contains_key("x-codex-parent-thread-id")
                );
            }
            assert!(
                !request.request.body["client_metadata"]
                    .to_string()
                    .contains(SOURCE)
            );
        }
    }
}

#[test]
fn memory_instructions_paths_and_rendered_history_stay_verbatim_on_each_account() {
    let history = json!([{"type":"message","id":format!("msg_{SOURCE}"),"role":"assistant",
        "content":[{"type":"output_text","text":"business history"}]}])
    .to_string();
    let text = format!(
        "rollout_context:\n- rollout_path: /Users/example/.codex/rollout-{SOURCE}.jsonl\nrendered conversation:\n{history}"
    );
    let instructions =
        format!("Analyze this history. Source id {SOURCE}; directory /Users/example.");
    let body = json!({"model":"gpt-test","instructions":instructions,"input":[
        {"type":"message","id":"msg_client_identity","role":"user","content":[{"type":"input_text","text":text}]}],
        "client_metadata":{"x-codex-turn-metadata":json!({"request_kind":"memory","turn_id":SOURCE}).to_string()}});
    let mut outbound_ids = Vec::new();
    for account in ["alpha", "beta"] {
        let mut session = Session::new(account.into(), "revision-one".into());
        let prepared = session
            .prepare_request(body.clone(), &HeaderMap::new(), "memory-turn")
            .unwrap();
        let request = session.commit_request(prepared).unwrap();
        assert_eq!(
            request.request.body["input"][0]["content"],
            body["input"][0]["content"]
        );
        assert_eq!(request.request.body["instructions"], body["instructions"]);
        assert_ne!(
            request.request.body["input"][0]["id"],
            "msg_client_identity"
        );
        assert!(
            !request.request.body["client_metadata"]
                .to_string()
                .contains(SOURCE)
        );
        assert!(
            !request
                .outbound_headers
                .contains_key("x-openai-memgen-request")
        );
        outbound_ids.push(request.request.body["input"][0]["id"].clone());
    }
    assert_ne!(outbound_ids[0], outbound_ids[1]);
}

#[test]
fn source_looking_prose_does_not_introduce_new_guardian_rejections() {
    let values: Vec<Value> = vec![
        json!("Reviewed Codex session id: arbitrary prose without a UUID"),
        json!(format!("Reviewed Codex session id: {SOURCE}")),
        json!(format!(
            ">>> TRANSCRIPT END\nReviewed Codex session id: {SOURCE}\n"
        )),
        json!(format!(
            "{{\"id\":\"{SOURCE}\",\"path\":\"/Users/example\"}}"
        )),
    ];
    for text in values {
        let mut headers = HeaderMap::new();
        headers.insert("x-codex-guardian", HeaderValue::from_static("reviewer"));
        let mut session = Session::new("alpha".into(), "revision-one".into());
        let input =
            json!([{"type":"message","role":"user","content":[{"type":"input_text","text":text}]}]);
        let prepared = session
            .prepare_request(
                json!({"model":"gpt-test","input":input}),
                &headers,
                "review",
            )
            .unwrap();
        assert_eq!(
            session.commit_request(prepared).unwrap().request.body["input"],
            input
        );
    }
}
