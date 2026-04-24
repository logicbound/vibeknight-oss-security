use serde_json::Value;

/// A single package version extracted from a raw `_changes` event.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub seq: String,
    pub package: String,
    pub version: String,
    pub tarball_url: String,
    pub last_modified: Option<String>,
    /// The raw `scripts` map from `package.json`, if present.
    pub scripts: Vec<String>,
}

/// Deserialize a single line from the `_changes` continuous feed.
///
/// A change event looks like:
/// ```json
/// {"seq":"...","id":"lodash","changes":[{"rev":"..."}],"doc":{...}}
/// ```
/// We extract every version present in `doc.versions` that has a dist tarball.
/// Returns `None` for heartbeat lines (`{}`) and malformed entries.
pub fn parse_change_line(line: &str) -> Vec<RawEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return vec![];
    }

    let Ok(value): Result<Value, _> = serde_json::from_str(trimmed) else {
        return vec![];
    };

    let seq = match value.get("seq") {
        Some(s) => json_to_string(s),
        None => return vec![],
    };

    let id = match value.get("id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return vec![],
    };

    // The `doc` field holds the full package manifest.
    let doc = match value.get("doc") {
        Some(d) => d,
        None => return vec![],
    };

    let modified = doc
        .get("time")
        .and_then(|t| t.get("modified"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let Some(versions_map) = doc.get("versions").and_then(Value::as_object) else {
        return vec![];
    };

    let mut events = Vec::new();

    for (ver, manifest) in versions_map {
        let tarball_url = manifest
            .pointer("/dist/tarball")
            .and_then(Value::as_str)
            .map(str::to_string);

        let Some(tarball_url) = tarball_url else { continue };

        let scripts = extract_scripts(manifest);

        events.push(RawEvent {
            seq: seq.clone(),
            package: id.clone(),
            version: ver.clone(),
            tarball_url,
            last_modified: modified.clone(),
            scripts,
        });
    }

    events
}

fn extract_scripts(manifest: &Value) -> Vec<String> {
    manifest
        .get("scripts")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn json_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

