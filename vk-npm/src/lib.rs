use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod error;
pub use error::NpmError;

// ── Entry point types ─────────────────────────────────────────────────────────

/// An execution entry point discovered in the package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntryPoint {
    /// A JS/TS file referenced as the package main, exports, or bin entry.
    File { path: String },

    /// A lifecycle script declared in package.json `scripts`.
    /// These are execution triggers during `npm install`, not passive metadata.
    InstallScript { script: String, command: String },
}

// ── Package graph output ──────────────────────────────────────────────────────

/// The Stage 1 output: file tree + entry points + integrity hash.
/// Serialised as `package_graph.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageGraph {
    pub package: String,
    pub version: String,
    /// SHA-256 of the raw tarball bytes.
    /// Stable across identical publishes; enables dedup and OSINT cross-reference.
    pub integrity_hash: String,
    /// All JS/TS source files in the package.
    pub files: Vec<String>,
    pub entry_points: Vec<EntryPoint>,
    /// Absolute path of the extracted package on disk (not serialised).
    #[serde(skip)]
    pub extracted_dir: PathBuf,
}

// ── Input modes ───────────────────────────────────────────────────────────────

/// How the caller is supplying the package.
pub enum PackageInput<'a> {
    /// A path to a `.tgz` tarball on disk.
    Tarball(&'a Path),
    /// A package name, optionally with a version tag: `"lodash"` or `"lodash@4.17.21"`.
    Registry(&'a str),
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a `PackageGraph` from an already-extracted package directory on disk.
///
/// This is used by the analyzer daemon when it receives an `Artifact` from the
/// downloader — the tarball has already been fetched and extracted, so there is
/// no need to download anything again.
///
/// Parses `package.json` inside `dir` to obtain entry points.
pub fn from_extracted_dir(
    dir: &Path,
    package: &str,
    version: &str,
    integrity_hash: &str,
) -> Result<PackageGraph, NpmError> {
    let manifest = read_package_json(dir)?;
    let files = collect_js_files(dir);
    let entry_points = collect_entry_points(&manifest, dir);
    Ok(PackageGraph {
        package: package.to_string(),
        version: version.to_string(),
        integrity_hash: integrity_hash.to_string(),
        files,
        entry_points,
        extracted_dir: dir.to_path_buf(),
    })
}

/// Ingest an npm package and return its `PackageGraph`.
///
/// The extracted source files remain on disk inside a `TempDir` whose path is
/// stored in `PackageGraph::extracted_dir`.  The caller is responsible for
/// keeping the `TempDir` alive as long as the files are needed.
pub fn ingest(input: PackageInput<'_>) -> Result<(PackageGraph, tempfile::TempDir), NpmError> {
    match input {
        PackageInput::Tarball(path) => ingest_tarball(path),
        PackageInput::Registry(spec) => {
            let tgz_bytes = fetch_from_registry(spec)?;
            ingest_bytes(&tgz_bytes)
        }
    }
}

// ── Registry fetch ────────────────────────────────────────────────────────────

fn fetch_from_registry(spec: &str) -> Result<Vec<u8>, NpmError> {
    let (name, version) = split_spec(spec);

    let meta_url = if version.is_empty() {
        format!("https://registry.npmjs.org/{}/latest", name)
    } else {
        format!("https://registry.npmjs.org/{}/{}", name, version)
    };

    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .build()
        .map_err(|e| NpmError::Network(e.to_string()))?;

    let meta: serde_json::Value = client
        .get(&meta_url)
        .send()
        .map_err(|e| NpmError::Network(e.to_string()))?
        .json()
        .map_err(|e| NpmError::Network(e.to_string()))?;

    let tarball_url = meta["dist"]["tarball"]
        .as_str()
        .ok_or_else(|| NpmError::Parse("missing dist.tarball in registry metadata".to_string()))?
        .to_string();

    let bytes = client
        .get(&tarball_url)
        .send()
        .map_err(|e| NpmError::Network(e.to_string()))?
        .bytes()
        .map_err(|e| NpmError::Network(e.to_string()))?
        .to_vec();

    Ok(bytes)
}

fn split_spec(spec: &str) -> (&str, &str) {
    // Handle scoped packages like "@scope/pkg@1.0.0"
    if let Some(at_pos) = spec[1..].find('@') {
        let split = at_pos + 1;
        (&spec[..split], &spec[split + 1..])
    } else {
        (spec, "")
    }
}

// ── Tarball ingestion ─────────────────────────────────────────────────────────

fn ingest_tarball(path: &Path) -> Result<(PackageGraph, tempfile::TempDir), NpmError> {
    let bytes = std::fs::read(path)
        .map_err(|e| NpmError::Io(e.to_string()))?;
    ingest_bytes(&bytes)
}

fn ingest_bytes(tgz_bytes: &[u8]) -> Result<(PackageGraph, tempfile::TempDir), NpmError> {
    let integrity_hash = sha256_hex(tgz_bytes);
    let tmp = tempfile::TempDir::new().map_err(|e| NpmError::Io(e.to_string()))?;
    extract_tgz(tgz_bytes, tmp.path())?;

    // npm tarballs always unpack into a "package/" subdirectory
    let pkg_dir = find_package_dir(tmp.path())?;
    let manifest = read_package_json(&pkg_dir)?;

    let name = manifest["name"].as_str().unwrap_or("unknown").to_string();
    let version = manifest["version"].as_str().unwrap_or("0.0.0").to_string();

    let files = collect_js_files(&pkg_dir);
    let entry_points = collect_entry_points(&manifest, &pkg_dir);

    let graph = PackageGraph {
        package: name,
        version,
        integrity_hash,
        files,
        entry_points,
        extracted_dir: pkg_dir,
    };

    Ok((graph, tmp))
}

fn extract_tgz(bytes: &[u8], dest: &Path) -> Result<(), NpmError> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest).map_err(|e| NpmError::Extract(e.to_string()))
}

fn find_package_dir(tmp: &Path) -> Result<PathBuf, NpmError> {
    // Prefer "package/" (npm convention); fall back to the first directory.
    let pkg = tmp.join("package");
    if pkg.is_dir() {
        return Ok(pkg);
    }
    for entry in std::fs::read_dir(tmp).map_err(|e| NpmError::Io(e.to_string()))? {
        let e = entry.map_err(|e| NpmError::Io(e.to_string()))?;
        if e.path().is_dir() {
            return Ok(e.path());
        }
    }
    Err(NpmError::Parse("no package directory found in tarball".to_string()))
}

fn read_package_json(pkg_dir: &Path) -> Result<serde_json::Value, NpmError> {
    let path = pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&path)
        .map_err(|e| NpmError::Io(format!("package.json: {}", e)))?;
    serde_json::from_str(&content).map_err(|e| NpmError::Parse(e.to_string()))
}

// ── File collection ───────────────────────────────────────────────────────────

const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts", "jsx", "tsx"];

fn collect_js_files(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_js_recursive(root, root, &mut files);
    files.sort();
    files
}

fn collect_js_recursive(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip node_modules and hidden dirs
            if path.file_name().map(|n| n.to_string_lossy().starts_with('.')).unwrap_or(false) {
                continue;
            }
            if path.file_name().map(|n| n == "node_modules").unwrap_or(false) {
                continue;
            }
            collect_js_recursive(root, &path, out);
        } else if let Some(ext) = path.extension() {
            if JS_EXTENSIONS.contains(&ext.to_string_lossy().as_ref()) {
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
}

// ── Entry point extraction ────────────────────────────────────────────────────

/// Lifecycle script names that act as execution triggers during install.
const INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

fn collect_entry_points(manifest: &serde_json::Value, pkg_dir: &Path) -> Vec<EntryPoint> {
    let mut eps = Vec::new();

    // Lifecycle install scripts — execution triggers, not passive metadata
    if let Some(scripts) = manifest["scripts"].as_object() {
        for &name in INSTALL_SCRIPTS {
            if let Some(cmd) = scripts.get(name).and_then(|v| v.as_str()) {
                eps.push(EntryPoint::InstallScript {
                    script: name.to_string(),
                    command: cmd.to_string(),
                });
            }
        }
    }

    // `main` field
    if let Some(main) = manifest["main"].as_str() {
        let candidate = pkg_dir.join(main);
        if candidate.exists() {
            eps.push(EntryPoint::File { path: normalise(main) });
        }
    }

    // `bin` entries (single string or map)
    match &manifest["bin"] {
        serde_json::Value::String(s) => {
            eps.push(EntryPoint::File { path: normalise(s) });
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map {
                if let Some(s) = v.as_str() {
                    eps.push(EntryPoint::File { path: normalise(s) });
                }
            }
        }
        _ => {}
    }

    eps
}

fn normalise(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
