use serde_json::Value;

/// A single package version extracted from a packument.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub package: String,
    pub version: String,
    pub tarball_url: String,
    pub last_modified: Option<String>,
    /// Names of scripts present in this version's `package.json`.
    pub scripts: Vec<String>,
}

/// Parse a packument (the JSON document returned by
/// `https://registry.npmjs.org/<name>`) and emit a single `RawEvent` for the
/// `dist-tags.latest` version.
///
/// Only the latest version is emitted to avoid exploding every change into
/// hundreds of historical-version events. Per-version deduplication in the
/// caller keeps steady-state volume low.
pub fn parse_packument_latest(packument: &Value, fallback_name: &str) -> Option<RawEvent> {
    let package = packument
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| fallback_name.to_string());

    let latest = packument
        .pointer("/dist-tags/latest")
        .and_then(Value::as_str)?;

    let version_doc = packument
        .pointer(&format!("/versions/{}", latest))?;

    let tarball_url = version_doc
        .pointer("/dist/tarball")
        .and_then(Value::as_str)
        .map(str::to_string)?;

    let last_modified = packument
        .pointer(&format!("/time/{}", latest))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            packument
                .pointer("/time/modified")
                .and_then(Value::as_str)
                .map(str::to_string)
        });

    let scripts = extract_scripts(version_doc);

    Some(RawEvent {
        package,
        version: latest.to_string(),
        tarball_url,
        last_modified,
        scripts,
    })
}

fn extract_scripts(manifest: &Value) -> Vec<String> {
    manifest
        .get("scripts")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}
