use std::path::Path;

use hex::encode as hex_encode;
use sha2::{Digest, Sha256};

/// Compute the SHA-256 hex digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes))
}

/// Check whether an artifact with this SHA-256 has already been fully extracted.
///
/// Returns `true` if `<artifacts_dir>/<sha256>/artifact.json` exists, meaning
/// this exact tarball was already processed and can be skipped.
pub fn already_extracted(artifacts_dir: &Path, sha256: &str) -> bool {
    artifacts_dir
        .join(sha256)
        .join("artifact.json")
        .exists()
}
