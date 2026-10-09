//! Conversation-scoped image bytes. An upstream generation id is never used
//! as a future request credential, especially after an OAuth account switch.
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_IMAGE_BYTES: usize = 11 * 1024 * 1024;
const MAX_RESOURCES_PER_SESSION: usize = 256;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResourceError {
    #[error("image resource scope is invalid")]
    Scope,
    #[error("upstream image bytes are invalid or unsupported")]
    Image,
    #[error("private image resource storage is unavailable")]
    Storage,
    #[error("private image resource capacity is exhausted")]
    Capacity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageRecord {
    session_key: String,
    alias: String,
    source_account: String,
    source_revision: String,
    content_sha256: String,
    mime: String,
    b64_json: String,
}

pub struct ResourceStore {
    root: PathBuf,
}

impl ResourceStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join("generated-images"),
        }
    }

    /// Creates local aliases for actual image bytes and replaces only the
    /// generation_id identity field. Unknown response fields stay untouched.
    pub fn alias_generated(
        &self,
        session_key: &str,
        account_id: &str,
        auth_revision: &str,
        response: Value,
    ) -> Result<Value, ResourceError> {
        if !sha_component(session_key)
            || !sha_component(auth_revision)
            || account_id.is_empty()
            || account_id.len() > 256
            || account_id.chars().any(char::is_control)
        {
            return Err(ResourceError::Scope);
        }
        let mut response = response;
        let images = response
            .get_mut("data")
            .and_then(Value::as_array_mut)
            .filter(|items| !items.is_empty() && items.len() <= 16)
            .ok_or(ResourceError::Image)?;
        let directory = self.root.join(session_key);
        if directory.exists() {
            checked_directory(&directory)?;
            let count = fs::read_dir(&directory)
                .map_err(|_| ResourceError::Storage)?
                .try_fold(0usize, |count, entry| {
                    entry
                        .map(|_| count.saturating_add(1))
                        .map_err(|_| ResourceError::Storage)
                })?;
            if count.saturating_add(images.len()) > MAX_RESOURCES_PER_SESSION {
                return Err(ResourceError::Capacity);
            }
        }
        let mut prepared = Vec::with_capacity(images.len());
        for item in images.iter() {
            let object = item.as_object().ok_or(ResourceError::Image)?;
            let encoded = object
                .get("b64_json")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 16 * 1024 * 1024)
                .ok_or(ResourceError::Image)?;
            let bytes = STANDARD.decode(encoded).map_err(|_| ResourceError::Image)?;
            if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
                return Err(ResourceError::Image);
            }
            let mime = image_mime(&bytes).ok_or(ResourceError::Image)?;
            prepared.push((
                encoded.to_owned(),
                mime.to_owned(),
                format!("{:x}", Sha256::digest(&bytes)),
            ));
        }
        let mut created = Vec::new();
        for (item, (encoded, mime, content_sha256)) in images.iter_mut().zip(prepared) {
            let alias = format!("gen_{}", Uuid::new_v4().simple());
            let record = ImageRecord {
                session_key: session_key.to_owned(),
                alias: alias.clone(),
                source_account: account_id.to_owned(),
                source_revision: auth_revision.to_owned(),
                content_sha256,
                mime,
                b64_json: encoded,
            };
            let path = directory.join(format!("{alias}.json"));
            let write = (|| {
                let body = serde_json::to_vec(&record).map_err(|_| ResourceError::Storage)?;
                if body.len() as u64 > MAX_RECORD_BYTES {
                    return Err(ResourceError::Image);
                }
                if fs::symlink_metadata(&path).is_ok() {
                    return Err(ResourceError::Storage);
                }
                crate::storage::atomic(&path, &body).map_err(|_| ResourceError::Storage)
            })();
            if let Err(error) = write {
                for path in created {
                    let _ = fs::remove_file(path);
                }
                return Err(error);
            }
            created.push(path);
            item.as_object_mut()
                .ok_or(ResourceError::Image)?
                .insert("generation_id".to_owned(), Value::String(alias));
        }
        Ok(response)
    }

    /// Reads source bytes only from the same local conversation. This remains
    /// valid after an account switch, while old upstream IDs never leave here.
    pub fn inline_image(
        &self,
        session_key: &str,
        alias: &str,
    ) -> Result<Option<String>, ResourceError> {
        if !sha_component(session_key) || !local_alias(alias) {
            return Err(ResourceError::Scope);
        }
        let directory = self.root.join(session_key);
        if !directory.exists() {
            return Ok(None);
        }
        checked_directory(&directory)?;
        let path = directory.join(format!("{alias}.json"));
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ResourceError::Storage),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_RECORD_BYTES
        {
            return Err(ResourceError::Storage);
        }
        let raw = fs::read(&path).map_err(|_| ResourceError::Storage)?;
        if raw.len() as u64 != metadata.len() {
            return Err(ResourceError::Storage);
        }
        let record: ImageRecord =
            serde_json::from_slice(&raw).map_err(|_| ResourceError::Storage)?;
        if record.session_key != session_key
            || record.alias != alias
            || !sha_component(&record.source_revision)
            || record.source_account.is_empty()
            || record.b64_json.len() > 16 * 1024 * 1024
        {
            return Err(ResourceError::Storage);
        }
        let bytes = STANDARD
            .decode(&record.b64_json)
            .map_err(|_| ResourceError::Storage)?;
        if bytes.is_empty()
            || bytes.len() > MAX_IMAGE_BYTES
            || image_mime(&bytes) != Some(record.mime.as_str())
            || format!("{:x}", Sha256::digest(&bytes)) != record.content_sha256
        {
            return Err(ResourceError::Storage);
        }
        Ok(Some(format!(
            "data:{};base64,{}",
            record.mime, record.b64_json
        )))
    }
}

pub fn is_generated_alias(value: &str) -> bool {
    local_alias(value)
}

fn local_alias(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("gen_")
        && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha_component(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn checked_directory(path: &Path) -> Result<(), ResourceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ResourceError::Storage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ResourceError::Storage);
    }
    Ok(())
}

fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}
