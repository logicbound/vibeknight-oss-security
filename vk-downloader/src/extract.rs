use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;

/// Hard limits applied during extraction.
const MAX_ENTRIES: usize = 5_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB

#[derive(Debug)]
pub enum ExtractError {
    Io(std::io::Error),
    PathTraversal(PathBuf),
    TooManyEntries,
    FileTooLarge { path: String, size: u64 },
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::Io(e) => write!(f, "I/O error: {}", e),
            ExtractError::PathTraversal(p) => write!(f, "Path traversal rejected: {}", p.display()),
            ExtractError::TooManyEntries => write!(f, "Archive exceeds {} entries", MAX_ENTRIES),
            ExtractError::FileTooLarge { path, size } => {
                write!(f, "File {} ({} bytes) exceeds size limit", path, size)
            }
        }
    }
}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        ExtractError::Io(e)
    }
}

/// Extract a `.tgz` tarball `bytes` into `dest_dir` safely.
///
/// Safety guarantees:
/// - Path traversal entries (`../`) are rejected.
/// - Symlinks are skipped.
/// - Files larger than `max_file_bytes` are rejected.
/// - Archives with more than `MAX_ENTRIES` entries are rejected.
pub fn extract_tgz(
    bytes: &[u8],
    dest_dir: &Path,
    max_file_bytes: Option<u64>,
) -> Result<(), ExtractError> {
    let max_bytes = max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);

    std::fs::create_dir_all(dest_dir)?;

    let gz = GzDecoder::new(bytes);
    let mut archive = Archive::new(gz);

    // Canonicalise the destination so we can validate entry paths against it.
    // `dest_dir` may not exist yet; we already created it above.
    let dest_canonical = dest_dir
        .canonicalize()
        .map_err(ExtractError::Io)?;

    let mut entry_count = 0usize;

    for entry_result in archive.entries()? {
        let entry = entry_result?;

        entry_count += 1;
        if entry_count > MAX_ENTRIES {
            return Err(ExtractError::TooManyEntries);
        }

        // Skip symlinks — entry is only immutably borrowed from here on
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            continue;
        }

        // npm tarballs nest content under a `package/` directory; strip it.
        let raw_path = entry.path()?.into_owned();
        let stripped = strip_first_component(&raw_path);

        let dest_path = dest_canonical.join(&stripped);

        // Path traversal guard: the resolved path must be inside dest_canonical.
        // We normalise manually without calling canonicalize() (file doesn't exist yet).
        if !dest_path.starts_with(&dest_canonical) {
            return Err(ExtractError::PathTraversal(dest_path));
        }

        // Size guard (skip directories)
        if entry_type.is_file() {
            let size = entry.header().size()?;
            if size > max_bytes {
                return Err(ExtractError::FileTooLarge {
                    path: stripped.to_string_lossy().into_owned(),
                    size,
                });
            }

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut dest_file = std::fs::File::create(&dest_path)?;
            let mut limited = entry.take(max_bytes);
            std::io::copy(&mut limited, &mut dest_file)?;
        }
    }

    Ok(())
}

/// Strip the first path component (e.g. `package/index.js` → `index.js`).
fn strip_first_component(path: &Path) -> PathBuf {
    let mut components = path.components();
    components.next(); // skip first segment
    components.as_path().to_path_buf()
}
