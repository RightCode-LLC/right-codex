//! Private provenance for standalone Search references. A backend `ref_id`
//! belongs to the Search session and OAuth revision that returned it; it is
//! never treated as a portable identifier merely because its text matches.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use codex_api::SearchCommands;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const MAX_STATE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SCOPES: usize = 64;
const MAX_REFS: usize = 4096;
const MAX_REF_LEN: usize = 256;
const MAX_URL_LEN: usize = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SearchResourceError {
    #[error("search scope is invalid")]
    Scope,
    #[error("search reference is not from this account")]
    UnknownReference,
    #[error("search reference cannot cross accounts")]
    ForeignReference,
    #[error("search resource storage is unavailable")]
    Storage,
    #[error("search resource capacity is exhausted")]
    Capacity,
}

#[derive(Clone)]
pub struct SearchPlan {
    pub search_id: String,
    pub commands: Option<SearchCommands>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SearchState {
    session_key: String,
    scopes: BTreeMap<String, SearchScope>,
    refs: BTreeMap<String, SearchRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchScope {
    account_id: String,
    auth_revision: String,
    search_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRef {
    scope_key: String,
    upstream_ref: String,
    url: Option<String>,
}

#[derive(Clone)]
pub struct SearchResourceStore {
    root: PathBuf,
}

impl SearchResourceStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("search-resources"),
        }
    }

    /// Reserve one backend Search ID per local conversation and account
    /// revision. Persistence precedes the network send so a crash cannot
    /// silently assign the next request a different Search identity.
    pub fn prepare(
        &self,
        session_key: &str,
        account_id: &str,
        auth_revision: &str,
        commands: Option<SearchCommands>,
    ) -> Result<SearchPlan, SearchResourceError> {
        let scope_key = scope_key(session_key, account_id, auth_revision)?;
        let mut state = self.load(session_key)?;
        if !state.scopes.contains_key(&scope_key) {
            if state.scopes.len() >= MAX_SCOPES {
                return Err(SearchResourceError::Capacity);
            }
            state.scopes.insert(
                scope_key.clone(),
                SearchScope {
                    account_id: account_id.to_owned(),
                    auth_revision: auth_revision.to_owned(),
                    search_id: Uuid::new_v4().to_string(),
                },
            );
            self.save(session_key, &state)?;
        }
        let scope = state
            .scopes
            .get(&scope_key)
            .filter(|scope| scope.account_id == account_id && scope.auth_revision == auth_revision)
            .ok_or(SearchResourceError::Scope)?;
        let mut commands = commands;
        if let Some(commands) = commands.as_mut() {
            rewrite_commands(commands, &state.refs, &scope_key)?;
        }
        Ok(SearchPlan {
            search_id: scope.search_id.clone(),
            commands,
        })
    }

    /// Register only structured references observed in an actual Search
    /// response. The free-form `output` stays byte-equivalent JSON content;
    /// unseen references in that text never gain send authority.
    pub fn observe_and_alias(
        &self,
        session_key: &str,
        account_id: &str,
        auth_revision: &str,
        mut response: Value,
    ) -> Result<Value, SearchResourceError> {
        let scope_key = scope_key(session_key, account_id, auth_revision)?;
        let mut state = self.load(session_key)?;
        if !state.scopes.get(&scope_key).is_some_and(|scope| {
            scope.account_id == account_id && scope.auth_revision == auth_revision
        }) {
            return Err(SearchResourceError::Scope);
        }
        let Some(results) = response.get_mut("results").and_then(Value::as_array_mut) else {
            return Ok(response);
        };
        if results.len() > MAX_REFS || state.refs.len().saturating_add(results.len()) > MAX_REFS {
            return Err(SearchResourceError::Capacity);
        }
        for result in results {
            let Some(object) = result.as_object_mut() else {
                continue;
            };
            let Some(upstream_ref) = object.get("ref_id").and_then(Value::as_str) else {
                continue;
            };
            if !bounded(upstream_ref, MAX_REF_LEN) {
                return Err(SearchResourceError::Scope);
            }
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .filter(|url| bounded(url, MAX_URL_LEN))
                .map(str::to_owned);
            let alias = if let Some((alias, _)) = state.refs.iter().find(|(_, prior)| {
                prior.scope_key == scope_key
                    && prior.upstream_ref == upstream_ref
                    && prior.url == url
            }) {
                alias.clone()
            } else {
                loop {
                    let candidate = format!("sref_{}", Uuid::new_v4().simple());
                    if !state.refs.contains_key(&candidate) {
                        break candidate;
                    }
                }
            };
            state.refs.insert(
                alias.clone(),
                SearchRef {
                    scope_key: scope_key.clone(),
                    upstream_ref: upstream_ref.to_owned(),
                    url,
                },
            );
            object.insert("ref_id".to_owned(), Value::String(alias));
        }
        self.save(session_key, &state)?;
        Ok(response)
    }

    fn path(&self, session_key: &str) -> PathBuf {
        self.root.join(format!("{session_key}.json"))
    }

    fn load(&self, session_key: &str) -> Result<SearchState, SearchResourceError> {
        if !digest(session_key) {
            return Err(SearchResourceError::Scope);
        }
        let path = self.path(session_key);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SearchState {
                    session_key: session_key.to_owned(),
                    ..SearchState::default()
                });
            }
            Err(_) => return Err(SearchResourceError::Storage),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_STATE_BYTES
        {
            return Err(SearchResourceError::Storage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(SearchResourceError::Storage);
            }
        }
        let raw = fs::read(path).map_err(|_| SearchResourceError::Storage)?;
        if raw.len() as u64 != metadata.len() {
            return Err(SearchResourceError::Storage);
        }
        let state: SearchState =
            serde_json::from_slice(&raw).map_err(|_| SearchResourceError::Storage)?;
        if state.session_key != session_key
            || state.scopes.len() > MAX_SCOPES
            || state.refs.len() > MAX_REFS
        {
            return Err(SearchResourceError::Storage);
        }
        for (key, scope) in &state.scopes {
            let expected = scope_key(session_key, &scope.account_id, &scope.auth_revision)
                .map_err(|_| SearchResourceError::Storage)?;
            if expected != *key || Uuid::parse_str(&scope.search_id).is_err() {
                return Err(SearchResourceError::Storage);
            }
        }
        for (alias, reference) in &state.refs {
            if !local_alias(alias)
                || !state.scopes.contains_key(&reference.scope_key)
                || !bounded(&reference.upstream_ref, MAX_REF_LEN)
                || reference
                    .url
                    .as_ref()
                    .is_some_and(|url| !bounded(url, MAX_URL_LEN))
            {
                return Err(SearchResourceError::Storage);
            }
        }
        Ok(state)
    }

    fn save(&self, session_key: &str, state: &SearchState) -> Result<(), SearchResourceError> {
        let bytes = serde_json::to_vec(state).map_err(|_| SearchResourceError::Storage)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(SearchResourceError::Capacity);
        }
        crate::storage::atomic(&self.path(session_key), &bytes)
            .map_err(|_| SearchResourceError::Storage)
    }
}

#[derive(Clone, Copy)]
enum ReferenceUse {
    Open,
    Find,
    Click,
    Screenshot,
}

fn rewrite_commands(
    commands: &mut SearchCommands,
    refs: &BTreeMap<String, SearchRef>,
    current_scope: &str,
) -> Result<(), SearchResourceError> {
    if let Some(operations) = commands.open.as_mut() {
        for operation in operations {
            operation.ref_id = resolve(&operation.ref_id, ReferenceUse::Open, refs, current_scope)?;
        }
    }
    if let Some(operations) = commands.find.as_mut() {
        for operation in operations {
            operation.ref_id = resolve(&operation.ref_id, ReferenceUse::Find, refs, current_scope)?;
        }
    }
    if let Some(operations) = commands.click.as_mut() {
        for operation in operations {
            operation.ref_id =
                resolve(&operation.ref_id, ReferenceUse::Click, refs, current_scope)?;
        }
    }
    if let Some(operations) = commands.screenshot.as_mut() {
        for operation in operations {
            operation.ref_id = resolve(
                &operation.ref_id,
                ReferenceUse::Screenshot,
                refs,
                current_scope,
            )?;
        }
    }
    Ok(())
}

fn resolve(
    supplied: &str,
    operation: ReferenceUse,
    refs: &BTreeMap<String, SearchRef>,
    current_scope: &str,
) -> Result<String, SearchResourceError> {
    if local_alias(supplied) {
        let reference = refs
            .get(supplied)
            .ok_or(SearchResourceError::UnknownReference)?;
        return resolve_observed(reference, operation, current_scope);
    }
    let matching = refs
        .values()
        .filter(|reference| reference.upstream_ref == supplied)
        .collect::<Vec<_>>();
    // Raw backend references can also appear in official free-form output.
    // If two revisions issued the same spelling, the client did not name an
    // unambiguous source; never guess that it meant the current account.
    if matching
        .iter()
        .map(|reference| reference.scope_key.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > 1
    {
        return Err(SearchResourceError::ForeignReference);
    }
    if let Some(reference) = matching.first() {
        return resolve_observed(reference, operation, current_scope);
    }
    if literal_url(supplied).is_some() {
        return Ok(supplied.to_owned());
    }
    Err(SearchResourceError::UnknownReference)
}

fn resolve_observed(
    reference: &SearchRef,
    operation: ReferenceUse,
    current_scope: &str,
) -> Result<String, SearchResourceError> {
    if reference.scope_key == current_scope {
        return Ok(reference.upstream_ref.clone());
    }
    if !matches!(operation, ReferenceUse::Open | ReferenceUse::Find) {
        return Err(SearchResourceError::ForeignReference);
    }
    reference
        .url
        .as_deref()
        .and_then(portable_url)
        .map(str::to_owned)
        .ok_or(SearchResourceError::ForeignReference)
}

fn literal_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    matches!(url.scheme(), "http" | "https").then_some(url)
}

fn portable_url(value: &str) -> Option<&str> {
    let url = literal_url(value)?;
    (url.username().is_empty() && url.password().is_none() && url.query().is_none())
        .then_some(value)
}

fn scope_key(
    session_key: &str,
    account_id: &str,
    auth_revision: &str,
) -> Result<String, SearchResourceError> {
    if !digest(session_key) || !digest(auth_revision) || !bounded(account_id, MAX_REF_LEN) {
        return Err(SearchResourceError::Scope);
    }
    let mut hash = Sha256::new();
    hash.update(account_id.len().to_be_bytes());
    hash.update(account_id.as_bytes());
    hash.update(auth_revision.as_bytes());
    Ok(format!("{digest:x}", digest = hash.finalize()))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn local_alias(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("sref_")
        && value[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn session() -> String {
        "a".repeat(64)
    }

    fn revision(value: char) -> String {
        value.to_string().repeat(64)
    }

    fn commands(value: Value) -> SearchCommands {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn search_id_is_stable_only_inside_one_account_revision() {
        let directory = TempDir::new().unwrap();
        let store = SearchResourceStore::new(directory.path());
        let first = store
            .prepare(&session(), "pool-a", &revision('a'), None)
            .unwrap();
        let restored = SearchResourceStore::new(directory.path())
            .prepare(&session(), "pool-a", &revision('a'), None)
            .unwrap();
        let switched = store
            .prepare(&session(), "pool-b", &revision('b'), None)
            .unwrap();
        assert_eq!(first.search_id, restored.search_id);
        assert_ne!(first.search_id, switched.search_id);
    }

    #[test]
    fn observed_refs_follow_current_scope_and_portable_url_only_after_switch() {
        let directory = TempDir::new().unwrap();
        let store = SearchResourceStore::new(directory.path());
        store
            .prepare(&session(), "pool-a", &revision('a'), None)
            .unwrap();
        let response = store
            .observe_and_alias(
                &session(),
                "pool-a",
                &revision('a'),
                json!({"output":"open turn0search0", "results":[
                    {"ref_id":"turn0search0","url":"https://example.com/page"},
                    {"ref_id":"turn0search1"},
                    {"ref_id":"turn0search2","url":"https://example.com/private?auth=opaque"}
                ]}),
            )
            .unwrap();
        assert_eq!(response["output"], "open turn0search0");
        let alias = response["results"][0]["ref_id"].as_str().unwrap();
        assert!(local_alias(alias));
        assert_ne!(alias, "turn0search0");
        let same = store
            .prepare(
                &session(),
                "pool-a",
                &revision('a'),
                Some(commands(json!({"open":[{"ref_id":alias}]}))),
            )
            .unwrap();
        assert_eq!(
            same.commands.unwrap().open.unwrap()[0].ref_id,
            "turn0search0"
        );

        let changed = store
            .prepare(
                &session(),
                "pool-b",
                &revision('b'),
                Some(commands(json!({"open":[{"ref_id":alias}]}))),
            )
            .unwrap();
        assert_eq!(
            changed.commands.unwrap().open.unwrap()[0].ref_id,
            "https://example.com/page"
        );
        for operation in [
            json!({"click":[{"ref_id":alias,"id":3}]}),
            json!({"screenshot":[{"ref_id":alias,"pageno":0}]}),
            json!({"open":[{"ref_id":"turn0search1"}]}),
            json!({"find":[{"ref_id":"turn0search2","pattern":"x"}]}),
        ] {
            assert_eq!(
                store
                    .prepare(
                        &session(),
                        "pool-b",
                        &revision('b'),
                        Some(commands(operation))
                    )
                    .err(),
                Some(SearchResourceError::ForeignReference)
            );
        }
    }

    #[test]
    fn repeated_backend_ref_across_accounts_is_ambiguous_without_alias() {
        let directory = TempDir::new().unwrap();
        let store = SearchResourceStore::new(directory.path());
        for (account, revision, url) in [
            ("pool-a", revision('a'), "https://example.com/old"),
            ("pool-b", revision('b'), "https://example.com/new"),
        ] {
            store.prepare(&session(), account, &revision, None).unwrap();
            store
                .observe_and_alias(
                    &session(),
                    account,
                    &revision,
                    json!({"results":[{"ref_id":"turn0search0","url":url}]}),
                )
                .unwrap();
        }
        assert_eq!(
            store
                .prepare(
                    &session(),
                    "pool-b",
                    &revision('b'),
                    Some(commands(json!({"open":[{"ref_id":"turn0search0"}]}))),
                )
                .err(),
            Some(SearchResourceError::ForeignReference)
        );
    }

    #[test]
    fn unobserved_reference_and_invalid_scope_are_refused() {
        let directory = TempDir::new().unwrap();
        let store = SearchResourceStore::new(directory.path());
        assert_eq!(
            store
                .prepare("../escape", "pool-a", &revision('a'), None)
                .err(),
            Some(SearchResourceError::Scope)
        );
        assert_eq!(
            store
                .prepare(
                    &session(),
                    "pool-a",
                    &revision('a'),
                    Some(commands(json!({"open":[{"ref_id":"turn9search9"}]}))),
                )
                .err(),
            Some(SearchResourceError::UnknownReference)
        );
        let literal = store
            .prepare(
                &session(),
                "pool-a",
                &revision('a'),
                Some(commands(
                    json!({"open":[{"ref_id":"https://example.com/?q=plain"}]}),
                )),
            )
            .unwrap();
        assert_eq!(
            literal.commands.unwrap().open.unwrap()[0].ref_id,
            "https://example.com/?q=plain"
        );
    }
}
