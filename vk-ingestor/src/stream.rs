use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::Value;

/// npm's new replication endpoint (since March 2025).
/// See: https://github.com/npm/feedback/discussions/152515
const CHANGES_URL: &str = "https://replicate.npmjs.com/registry/_changes";

/// Packument fetch endpoint. `include_docs=true` is no longer supported on
/// `_changes`, so we fetch package metadata separately from here.
const REGISTRY_URL: &str = "https://registry.npmjs.org";

/// npm enforces a default limit of 1000 and a maximum of 10000.
pub const DEFAULT_LIMIT: u32 = 1000;

/// A single poll of the `_changes` endpoint returns a cursor plus the list of
/// package names that had any change since `since`.
#[derive(Debug)]
pub struct ChangesResponse {
    pub last_seq: String,
    pub package_ids: Vec<String>,
}

/// Poll the `_changes` endpoint for up to `limit` changes since `since`.
/// Returns the new cursor and the list of changed package IDs.
pub fn poll_changes(
    client: &Client,
    since: &str,
    limit: u32,
) -> Result<ChangesResponse, reqwest::Error> {
    let url = format!("{}?since={}&limit={}", CHANGES_URL, since, limit);

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(60))
        .send()?;

    eprintln!(
        "[ingestor] HTTP {} from /registry/_changes (since={}, limit={})",
        resp.status(),
        since,
        limit
    );

    let resp = resp.error_for_status()?;
    let body: Value = resp.json()?;

    let last_seq = body
        .get("last_seq")
        .map(value_to_string)
        .unwrap_or_else(|| since.to_string());

    let package_ids = body
        .get("results")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(ChangesResponse {
        last_seq,
        package_ids,
    })
}

/// Look up the current tip sequence so a fresh start can begin at "now" rather
/// than replaying all of npm history.
pub fn fetch_current_seq(client: &Client) -> Result<String, reqwest::Error> {
    let url = format!(
        "{}?since=0&limit=1&descending=true",
        CHANGES_URL
    );

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(30))
        .send()?
        .error_for_status()?;

    let body: Value = resp.json()?;
    Ok(body
        .get("last_seq")
        .map(value_to_string)
        .unwrap_or_else(|| "0".to_string()))
}

/// Fetch the full packument (version map, dist-tags, etc.) for a package.
///
/// Scoped packages (`@scope/pkg`) need their slash percent-encoded.
pub fn fetch_packument(client: &Client, name: &str) -> Result<Value, reqwest::Error> {
    let encoded = if name.starts_with('@') {
        name.replacen('/', "%2F", 1)
    } else {
        name.to_string()
    };
    let url = format!("{}/{}", REGISTRY_URL, encoded);

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(30))
        .send()?
        .error_for_status()?;

    resp.json()
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Build a blocking `reqwest` client with a real User-Agent and the
/// `npm-replication-opt-in` header set during the API transition window.
pub fn build_client() -> reqwest::Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("npm-replication-opt-in"),
        reqwest::header::HeaderValue::from_static("true"),
    );

    Client::builder()
        .use_rustls_tls()
        .tcp_keepalive(Duration::from_secs(30))
        .user_agent(concat!(
            "vk-ingestor/",
            env!("CARGO_PKG_VERSION"),
            " (+https://www.npmjs.com/)"
        ))
        .default_headers(headers)
        .build()
}
