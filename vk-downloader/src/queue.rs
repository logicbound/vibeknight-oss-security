use redis::Connection;

use crate::artifact::{Artifact, IngestJob};

/// Queue keys — namespaced to avoid collisions with other applications.
pub const INGEST_QUEUE: &str = "vk:ingest_jobs";
pub const ARTIFACT_QUEUE: &str = "vk:artifact_jobs";
pub const DEAD_LETTER_QUEUE: &str = "vk:dead_letter";

/// Maximum consecutive failures before a job is sent to the dead-letter queue.
pub const MAX_RETRIES: u32 = 3;

/// Open a blocking connection to the Redis server at `url`.
pub fn connect(url: &str) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url)?;
    client.get_connection()
}

/// Block until a job is available on `vk:ingest_jobs`, then pop and return
/// the raw JSON string and the parsed `IngestJob`.
///
/// `BRPOP` with timeout=0 blocks indefinitely, giving FIFO ordering when
/// paired with `vk-ingestor`'s `LPUSH`.
pub fn pop_ingest_job(con: &mut Connection) -> redis::RedisResult<(String, IngestJob)> {
    loop {
        let (_, raw): (String, String) = redis::cmd("BRPOP")
            .arg(INGEST_QUEUE)
            .arg(0)
            .query(con)?;

        match serde_json::from_str::<IngestJob>(&raw) {
            Ok(job) => return Ok((raw, job)),
            Err(e) => {
                eprintln!("[downloader/queue] Malformed job, skipping: {}", e);
            }
        }
    }
}

/// Push an `Artifact` to `vk:artifact_jobs` for the analyzer daemon.
pub fn push_artifact(con: &mut Connection, artifact: &Artifact) -> redis::RedisResult<()> {
    let json = serde_json::to_string(artifact)
        .map_err(|e| redis::RedisError::from((redis::ErrorKind::IoError, "serialise", e.to_string())))?;
    redis::cmd("LPUSH")
        .arg(ARTIFACT_QUEUE)
        .arg(json)
        .query::<i64>(con)?;
    Ok(())
}

/// Send a failed job payload to the dead-letter queue with an error annotation.
pub fn push_dead_letter(con: &mut Connection, raw_job: &str, error: &str) -> redis::RedisResult<()> {
    let payload = serde_json::json!({
        "raw_job": raw_job,
        "error":   error,
        "ts":      std::time::SystemTime::now()
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
