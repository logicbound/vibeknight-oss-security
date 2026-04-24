use std::path::{Path, PathBuf};

use crate::artifact::Artifact;

/// Return the artifact directory path for a given SHA-256 hash.
pub fn artifact_dir(artifacts_root: &Path, sha256: &str) -> PathBuf {
    artifacts_root.join(sha256)
}

/// Write `artifact.json` into the artifact directory so future runs can detect
/// that this tarball has already been processed (dedup).
pub fn write_artifact_descriptor(dir: &Path, artifact: &Artifact) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(artifact)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(dir.join("artifact.json"), json)
}

/// Read the cached `artifact.json` from a previously processed artifact dir.
pub fn read_artifact_descriptor(dir: &Path) -> Option<Artifact> {
    let contents = std::fs::read_to_string(dir.join("artifact.json")).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Delete a partially-extracted artifact directory, ignoring errors.
pub fn cleanup_dir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Ensure the artifacts root directory exists.
pub fn ensure_artifacts_root(root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root)
}
