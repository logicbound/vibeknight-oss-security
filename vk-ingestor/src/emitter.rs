use std::io::Write;

use serde::{Deserialize, Serialize};

/// Schema version for `IngestJob`. Increment on breaking field changes so
/// consumers can detect and reject stale payloads.
pub const INGEST_JOB_SCHEMA_VERSION: u8 = 1;

/// A normalised analysis-ready job produced by the ingestor and consumed by
/// the downloader. This is the wire contract between the two services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestJob {
    /// Wire schema version — always `INGEST_JOB_SCHEMA_VERSION` when produced.
    pub schema_version: u8,
    pub package: String,
    pub version: String,
    pub tarball_url: String,
    /// ISO-8601 publish/modified timestamp, if present in the change event.
    pub last_modified: Option<String>,
    /// Heuristic priority score in [0.0, 1.0]. Higher → more suspicious.
    pub priority: f32,
}

/// Write one `IngestJob` as a single NDJSON line to `writer`.
pub fn emit<W: Write>(writer: &mut W, job: &IngestJob) -> std::io::Result<()> {
    let line = serde_json::to_string(job)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writeln!(writer, "{}", line)
}
