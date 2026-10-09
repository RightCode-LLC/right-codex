//! Private atomic scope persistence. Committed network sends never revert on restart.
use crate::{protocol::ProtocolError, session::Session};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn directory(path: &Path) -> Result<(), ProtocolError> {
    crate::accounts::create_private_directory(path)
        .map_err(|_| ProtocolError::Invalid("storage.directory"))
}
pub fn path(root: &Path, key: &str) -> Result<PathBuf, ProtocolError> {
    if key.len() != 64 || !key.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProtocolError::Invalid("storage.key"));
    }
    Ok(root.join(format!("{key}.json")))
}
pub fn save(root: &Path, key: &str, session: &Session) -> Result<(), ProtocolError> {
    let dest = path(root, key)?;
    let bytes = serde_json::to_vec(&json!({"key":key,"session":session.snapshot()?}))
        .map_err(|_| ProtocolError::Invalid("storage.encode"))?;
    if bytes.len() > crate::session::MAX_PERSISTENCE_BYTES {
        return Err(ProtocolError::Capacity("storage.snapshot"));
    }
    atomic(&dest, &bytes)
}
pub fn load(root: &Path, key: &str) -> Result<Option<Session>, ProtocolError> {
    let dest = path(root, key)?;
    match fs::symlink_metadata(&dest) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ProtocolError::Invalid("storage.read")),
        Ok(m) => {
            if !m.is_file() || m.len() > crate::session::MAX_PERSISTENCE_BYTES as u64 {
                return Err(ProtocolError::Invalid("storage.file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o077 != 0 {
                    return Err(ProtocolError::Invalid("storage.permissions"));
                }
            }
        }
    }
    let v: Value = serde_json::from_slice(
        &fs::read(dest).map_err(|_| ProtocolError::Invalid("storage.read"))?,
    )
    .map_err(|_| ProtocolError::Invalid("storage.json"))?;
    if v["key"] != key || v.as_object().is_none_or(|o| o.len() != 2) {
        return Err(ProtocolError::Invalid("storage.scope"));
    }
    Ok(Some(Session::restore(v["session"].clone())?))
}
pub fn atomic(dest: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
    let parent = dest
        .parent()
        .ok_or(ProtocolError::Invalid("storage.path"))?;
    directory(parent)?;
    if fs::symlink_metadata(dest).is_ok_and(|m| !m.is_file()) {
        return Err(ProtocolError::Invalid("storage.file"));
    }
    let temp = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, dest)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
        return Err(ProtocolError::Invalid("storage.write"));
    }
    Ok(())
}
