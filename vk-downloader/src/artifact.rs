use std::path::Path;

use serde::{Deserialize, Serialize};

/// Schema version for `Artifact`. Increment on breaking field changes.
pub const ARTIFACT_SCHEMA_VERSION: u8 = 1;

/// A successfully extracted npm package artifact — the output contract of
/// `vk-downloader`. Serialised as JSON pushed to Redis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Wire schema version — always `ARTIFACT_SCHEMA_VERSION` when produced.
    pub schema_version: u8,
    pub package: String,
    pub version: String,
    /// Absolute path to the extracted package directory on disk.
    pub artifact_path: String,
    /// SHA-256 hex digest of the raw tarball bytes.
    pub sha256: String,
    /// Relative paths of all JS/TS source files inside the package.
    pub files: Vec<String>,
}

/// An `IngestJob` as received from `vk-ingestor` over Redis.
///
/// All fields are preserved from the wire format even if the downloader
/// doesn't act on every one of them.
#[derive(Debug, Deserialize)]
pub struct IngestJob {
    pub schema_version: u8,
    pub package: String,
    pub version: String,
    pub tarball_url: String,
    /// ISO-8601 publish timestamp passed through from the change feed.
    #[allow(dead_code)]
    pub last_modified: Option<String>,
    pub priority: f32,
}

impl Artifact {
    /// Build an `Artifact` by scanning an already-extracted package directory.
    pub fn from_dir(package: &str, version: &str, dir: &Path, sha256: &str) -> Self {
        let files = collect_js_files(dir);
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            package: package.to_string(),
            version: version.to_string(),
            artifact_path: dir.to_string_lossy().into_owned(),
            sha256: sha256.to_string(),
            files,
        }
    }
}

/// Collect all JS/TS files relative to `dir`, sorted for deterministic output.
pub fn collect_js_files(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_recursive(dir, dir, &mut files);
    files.sort();
    files
}

fn collect_recursive(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(root, &path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs") {
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
}
