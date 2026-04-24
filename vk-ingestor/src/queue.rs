use redis::Connection;

use crate::emitter::IngestJob;

/// Redis key for the ingest job queue consumed by `vk-downloader`.
pub const INGEST_QUEUE: &str = "vk:ingest_jobs";

/// Push one serialised `IngestJob` to the head of `vk:ingest_jobs`.
///
/// We use `LPUSH` so `vk-downloader` can use `BRPOP` (which pops from the
/// tail, giving approximate FIFO ordering without a separate sorted set).
pub fn push_job(con: &mut Connection, job: &IngestJob) -> redis::RedisResult<()> {
    let json = serde_json::to_string(job)
        .map_err(|e| redis::RedisError::from((redis::ErrorKind::IoError, "serialise", e.to_string())))?;
    redis::cmd("LPUSH")
        .arg(INGEST_QUEUE)
        .arg(json)
        .query::<i64>(con)?;
    Ok(())
}

/// Open a connection to the Redis server at `url`.
pub fn connect(url: &str) -> redis::RedisResult<Connection> {
    let client = redis::Client::open(url)?;
    client.get_connection()
}
