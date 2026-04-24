use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Persisted ingestor state — survives restarts.
#[derive(Debug, Serialize, Deserialize)]
pub struct IngestorState {
    /// CouchDB `last_seq` cursor. Starts at `"0"` for a fresh run.
    pub last_seq: String,
    /// Deduplication set: `"<pkg>@<version>"` → `true`.
    pub seen: HashMap<String, bool>,
}

impl Default for IngestorState {
    fn default() -> Self {
        Self {
            //now is now, 0 is beginning of time
            //last_seq: "0".to_string(),
            last_seq: "0".to_string(),
            seen: HashMap::new(),
        }
    }
}

impl IngestorState {
    /// Load state from `path`, or return a default (fresh) state if the file
    /// does not exist yet. Also repairs state files that somehow ended up with
    /// an empty `last_seq` (e.g. deserialised from a pre-fix build).
    pub fn load(path: &Path) -> Self {
        let mut state: Self = match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        };
        if state.last_seq.is_empty() {
            //now is now, 0 is beginning of time
            //state.last_seq = "0".to_string();
            state.last_seq = "0".to_string();
        }
        state
    }

    /// Atomically write state to `path` (write → rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, contents)?;
        std::fs::rename(tmp, path)
    }

    /// Mark a `"<pkg>@<ver>"` key as seen.
    pub fn mark_seen(&mut self, pkg: &str, ver: &str) {
        self.seen.insert(format!("{}@{}", pkg, ver), true);
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from("vk-ingestor-state.json")
    }
}
