//! The official image extension sends only x-codex-image-turn-id
//! (ext/image-generation/src/backend.rs:132-144). It is a local lookup key,
//! never an upstream identity or evidence of client tool execution.
use std::{path::Path, sync::Arc};

use http::HeaderMap;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    protocol::ProtocolError,
    session::{Session, SessionStore},
};

pub(crate) struct RegisteredImageScope {
    pub(crate) key: String,
    pub(crate) session: Arc<Mutex<Session>>,
    pub(crate) account_id: String,
    pub(crate) auth_revision: String,
    pub(crate) logical_turn: String,
}

impl RegisteredImageScope {
    /// Recheck the lookup snapshot after acquiring the scope, before account
    /// selection. A deliberate switch then mints a new upstream turn while
    /// keeping this private conversation; resource authority stays separate.
    pub(crate) fn validate_current(&self, session: &Session) -> Result<(), ProtocolError> {
        if session.account_id != self.account_id
            || session.auth_revision != self.auth_revision
            || !session.has_registered_image_turn(&self.logical_turn)
        {
            return Err(ProtocolError::Invalid("image.turn_scope_changed"));
        }
        Ok(())
    }
}

pub(crate) fn resolve(
    store: &SessionStore,
    scope_directory: &Path,
    namespace: &str,
    headers: &HeaderMap,
) -> Result<RegisteredImageScope, ProtocolError> {
    let mut values = headers.get_all("x-codex-image-turn-id").iter();
    let native_turn = values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or(ProtocolError::Invalid("image.turn_id"))?;
    if values.next().is_some() {
        return Err(ProtocolError::Invalid("metadata.duplicate_header"));
    }
    // Exactly gateway::logical_turn's private namespace recipe. The native
    // identifier is deliberately absent from persistent scope records.
    let mut hash = Sha256::new();
    hash.update(namespace.len().to_be_bytes());
    hash.update(namespace.as_bytes());
    hash.update(native_turn.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    store
        .image_scope_for_turn(&Uuid::from_bytes(bytes).to_string(), scope_directory)?
        .ok_or(ProtocolError::UnmappedIdentity("image.turn_scope"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use serde_json::json;
    use tempfile::TempDir;

    fn headers(turn: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-image-turn-id",
            HeaderValue::from_str(turn).unwrap(),
        );
        headers
    }
    fn registered(namespace: &str, native_turn: &str) -> Session {
        let request = json!({"model":"test","input":[{"role":"user","content":"draw"}],
            "client_metadata":{"turn_id":native_turn}});
        let turn = crate::gateway::logical_turn(namespace, &request, &HeaderMap::new());
        let mut session = Session::new("pool-a".into(), "revision-a".into());
        let prepared = session
            .prepare_request(request, &HeaderMap::new(), &turn)
            .unwrap();
        let scoped = session.commit_request(prepared).unwrap();
        session.mark_sending(&scoped.attempt_id).unwrap();
        let mut event = json!({"type":"response.completed","response":{"id":"upstream-resp", "output":[{
            "type":"message","id":"upstream-msg","role":"assistant","content":[{"type":"output_text","text":"done"}]}]}});
        session.rewrite_event(&mut event).unwrap();
        session.finish_attempt(&scoped.attempt_id, &event).unwrap();
        session
    }

    #[test]
    fn image_turn_lookup_uses_existing_namespace_and_restores_private_scope() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::default();
        let key = SessionStore::local_key("private-client", "native-thread");
        let session = registered("private-client", "native-turn");
        crate::storage::save(dir.path(), &key, &session).unwrap();
        let matched = resolve(
            &store,
            dir.path(),
            "private-client",
            &headers("native-turn"),
        )
        .unwrap();
        assert_eq!(matched.key, key);
        assert_eq!(matched.account_id, "pool-a");
        matched
            .validate_current(&matched.session.try_lock().unwrap())
            .unwrap();
        assert!(matches!(
            resolve(&store, dir.path(), "other-client", &headers("native-turn")),
            Err(ProtocolError::UnmappedIdentity("image.turn_scope"))
        ));
        assert!(
            resolve(
                &store,
                dir.path(),
                "private-client",
                &headers("unknown-turn")
            )
            .is_err()
        );
    }

    #[test]
    fn image_turn_lookup_rejects_ambiguity_duplicate_headers_and_owner_drift() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::default();
        let key = SessionStore::local_key("private-client", "thread-a");
        store
            .insert_restored(key, registered("private-client", "native-turn"))
            .unwrap();
        let matched = resolve(
            &store,
            dir.path(),
            "private-client",
            &headers("native-turn"),
        )
        .unwrap();
        matched.session.try_lock().unwrap().auth_revision = "changed-revision".into();
        assert!(
            matched
                .validate_current(&matched.session.try_lock().unwrap())
                .is_err()
        );
        let mut duplicate = headers("native-turn");
        duplicate.append(
            "x-codex-image-turn-id",
            HeaderValue::from_static("native-turn"),
        );
        assert!(matches!(
            resolve(&store, dir.path(), "private-client", &duplicate),
            Err(ProtocolError::Invalid("metadata.duplicate_header"))
        ));
        for thread in ["thread-b", "thread-c"] {
            store
                .insert_restored(
                    SessionStore::local_key("private-client", thread),
                    registered("private-client", "native-turn"),
                )
                .unwrap();
        }
        assert!(matches!(
            resolve(
                &store,
                dir.path(),
                "private-client",
                &headers("native-turn")
            ),
            Err(ProtocolError::Invalid("image.turn_scope_ambiguous"))
        ));
    }

    #[tokio::test]
    async fn busy_live_scope_reads_protected_snapshot_without_taking_its_lock() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::default();
        let key = SessionStore::local_key("private-client", "thread-a");
        let session = registered("private-client", "native-turn");
        crate::storage::save(dir.path(), &key, &session).unwrap();
        store.insert_restored(key.clone(), session).unwrap();
        let arc = store.get(&key).unwrap();
        let _guard = arc.lock().await;
        let matched = resolve(
            &store,
            dir.path(),
            "private-client",
            &headers("native-turn"),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&arc, &matched.session));
    }

    #[test]
    fn prepared_unknown_and_restarted_sending_turns_are_not_image_owners() {
        for sending in [false, true] {
            let dir = TempDir::new().unwrap();
            let store = SessionStore::default();
            let request = json!({"model":"test","input":[{"role":"user","content":"draw"}],
                "client_metadata":{"turn_id":"native-turn"}});
            let logical =
                crate::gateway::logical_turn("private-client", &request, &HeaderMap::new());
            let mut session = Session::new("pool-a".into(), "revision-a".into());
            let prepared = session
                .prepare_request(request, &HeaderMap::new(), &logical)
                .unwrap();
            let scoped = session.commit_request(prepared).unwrap();
            if sending {
                session.mark_sending(&scoped.attempt_id).unwrap();
            }
            assert_eq!(session.upstream_turn_for(&logical).is_some(), sending);
            let key = SessionStore::local_key("private-client", "thread-a");
            crate::storage::save(dir.path(), &key, &session).unwrap();
            assert!(
                resolve(
                    &store,
                    dir.path(),
                    "private-client",
                    &headers("native-turn")
                )
                .is_err()
            );
        }
    }
}
