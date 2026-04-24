use redis::Connection;

/// Artifact wire type received from `vk-downloader` via `vk:artifact_jobs`.
#[derive(Debug, serde::Deserialize)]
pub struct Artifact {
    pub schema_version: u8,
    pub package: String,
    pub version: String,
    pub artifact_path: String,
    pub sha256: String,
    #[allow(dead_code)]
    pub files: Vec<String>,
}

/// Queue keys consumed/produced by the analyzer daemon.
pub const ARTIFACT_QUEUE: &str = "vk:artifact_jobs";
pub const FINDINGS_QUEUE: &str = "vk:findings";
pub const DEAD_LETTER_QUEUE: &str = "vk:dead_letter";

/// Maximum consecutive failures before a job is dead-lettered.
pub const MAX_RETRIES: u32 = 3;

/// Open a blocking connection to the Redis server at `url`.
pub fn connect(url: &str) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url)?;
    client.get_connection()
}

/// Block until an `Artifact` JSON payload is available on `vk:artifact_jobs`.
/// Returns the raw JSON string and the parsed `Artifact`.
pub fn pop_artifact(con: &mut Connection) -> redis::RedisResult<(String, Artifact)> {
    loop {
        let (_, raw): (String, String) = redis::cmd("BRPOP")
            .arg(ARTIFACT_QUEUE)
            .arg(0)
            .query(con)?;

        match serde_json::from_str::<Artifact>(&raw) {
            Ok(artifact) => return Ok((raw, artifact)),
            Err(e) => {
                eprintln!("[analyzer/queue] Malformed artifact, skipping: {}", e);
            }
        }
    }
}

/// Push a serialised finding JSON string to `vk:findings`.
pub fn push_finding(con: &mut Connection, finding_json: &str) -> redis::RedisResult<()> {
    redis::cmd("LPUSH")
        .arg(FINDINGS_QUEUE)
        .arg(finding_json)
        .query::<i64>(con)?;
    Ok(())
}

/// Send a failed payload to the dead-letter queue with error annotation.
pub fn push_dead_letter(con: &mut Connection, raw_payload: &str, error: &str) -> redis::RedisResult<()> {
    let payload = serde_json::json!({
        "raw_payload": raw_payload,
        "error":       error,
        "ts":          std::time::SystemTime::now()
                           .duration_since(std::time::UNIX_EPOCH)
                           .map(|d| d.as_secs())
                           .unwrap_or(0),
    });
    redis::cmd("LPUSH")
        .arg(DEAD_LETTER_QUEUE)
        .arg(payload.to_string())
        .query::<i64>(con)?;
    Ok(())
}
