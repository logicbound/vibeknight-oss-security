mod artifact;
mod extract;
mod fetch;
mod fs;
mod queue;
mod verify;

use std::collections::HashMap;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::PathBuf;

use artifact::{Artifact, IngestJob, ARTIFACT_SCHEMA_VERSION};
use fetch::FetchError;
use queue::MAX_RETRIES;

// ── CLI args ──────────────────────────────────────────────────────────────────

struct Args {
    artifacts_dir: PathBuf,
    /// Redis URL.  `REDIS_URL` env var is the fallback.
    redis_url: Option<String>,
    /// Debug: read IngestJob NDJSON from this file instead of Redis/stdin.
    input_path: Option<PathBuf>,
    max_file_bytes: Option<u64>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut artifacts_dir = PathBuf::from("artifacts");
    let mut redis_url: Option<String> = std::env::var("REDIS_URL").ok();
    let mut input_path: Option<PathBuf> = None;
    let mut max_file_bytes: Option<u64> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--artifacts" => {
                if let Some(v) = args.next() { artifacts_dir = PathBuf::from(v); }
            }
            "--redis-url" => {
                if let Some(v) = args.next() { redis_url = Some(v); }
            }
            "--input" => {
                if let Some(v) = args.next() { input_path = Some(PathBuf::from(v)); }
            }
            "--max-file-bytes" => {
                if let Some(v) = args.next() { max_file_bytes = v.parse().ok(); }
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: vk-downloader [--artifacts <dir>] [--redis-url <url>] [--input <file>] [--max-file-bytes <n>]\n\n\
                     Options:\n  \
                       --artifacts <dir>     Artifact root (default: ./artifacts)\n  \
                       --redis-url <url>     Redis URL (default: $REDIS_URL; fallback: stdin NDJSON)\n  \
                       --input <file>        Read IngestJob NDJSON from file\n  \
                       --max-file-bytes <n>  Per-file extraction limit (default: 10 MiB)"
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                std::process::exit(1);
            }
        }
    }

    Args { artifacts_dir, redis_url, input_path, max_file_bytes }
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

fn process_job(
    job: &IngestJob,
    artifacts_dir: &std::path::Path,
    max_file_bytes: Option<u64>,
    client: &reqwest::blocking::Client,
) -> Result<Artifact, String> {
    let bytes = fetch::download_tarball(client, &job.tarball_url)
        .map_err(|e: FetchError| e.to_string())?;

    let sha256 = verify::sha256_hex(&bytes);
    let dest_dir = fs::artifact_dir(artifacts_dir, &sha256);

    if verify::already_extracted(artifacts_dir, &sha256) {
        if let Some(cached) = fs::read_artifact_descriptor(&dest_dir) {
            eprintln!(
                "[downloader] Cache hit for {}@{} ({})",
                job.package, job.version, &sha256[..12]
            );
            return Ok(cached);
        }
    }

    if let Err(e) = extract::extract_tgz(&bytes, &dest_dir, max_file_bytes) {
        fs::cleanup_dir(&dest_dir);
        return Err(format!("Extraction failed: {}", e));
    }

    let mut artifact = Artifact::from_dir(&job.package, &job.version, &dest_dir, &sha256);
    artifact.schema_version = ARTIFACT_SCHEMA_VERSION;

    if let Err(e) = fs::write_artifact_descriptor(&dest_dir, &artifact) {
        eprintln!("[downloader] Warning: could not write artifact.json: {}", e);
    }

    Ok(artifact)
}

// ── Redis daemon loop ─────────────────────────────────────────────────────────

fn run_redis_loop(
    redis_url: &str,
    artifacts_dir: &PathBuf,
    max_file_bytes: Option<u64>,
    client: &reqwest::blocking::Client,
) {
    let mut con = queue::connect(redis_url).unwrap_or_else(|e| {
        eprintln!("[downloader] Cannot connect to Redis ({}): {}", redis_url, e);
        std::process::exit(1);
    });

    eprintln!("[downloader] Redis daemon started, consuming {}", queue::INGEST_QUEUE);

    // In-memory retry counter: "package@version" → failure count.
    let mut retry_counts: HashMap<String, u32> = HashMap::new();

    loop {
        let (raw_json, job) = match queue::pop_ingest_job(&mut con) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[downloader] Redis pop error: {}. Reconnecting.", e);
                con = loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    match queue::connect(redis_url) {
                        Ok(c) => break c,
                        Err(e) => eprintln!("[downloader] Reconnect failed: {}", e),
                    }
                };
                continue;
            }
        };

        // Reject jobs with an unexpected schema version
        if job.schema_version != 1 {
            eprintln!(
                "[downloader] Unsupported schema_version={} for {}@{} — dead-lettering.",
                job.schema_version, job.package, job.version
            );
            let _ = queue::push_dead_letter(
                &mut con,
                &raw_json,
                &format!("unsupported schema_version={}", job.schema_version),
            );
            continue;
        }

        let key = format!("{}@{}", job.package, job.version);
        eprintln!(
            "[downloader] Processing {}@{} (priority={:.2})",
            job.package, job.version, job.priority
        );

        match process_job(&job, artifacts_dir, max_file_bytes, client) {
            Ok(artifact) => {
                retry_counts.remove(&key);
                if let Err(e) = queue::push_artifact(&mut con, &artifact) {
                    eprintln!("[downloader] Failed to push artifact to Redis: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[downloader] Failed {}@{}: {}", job.package, job.version, e);
                let count = retry_counts.entry(key.clone()).or_insert(0);
                *count += 1;
                if *count > MAX_RETRIES {
                    eprintln!("[downloader] Max retries exceeded for {} — dead-lettering.", key);
                    let _ = queue::push_dead_letter(&mut con, &raw_json, &e);
                    retry_counts.remove(&key);
                } else {
                    // Requeue for another attempt
                    let _ = redis::cmd("LPUSH")
                        .arg(queue::INGEST_QUEUE)
                        .arg(&raw_json)
                        .query::<i64>(&mut con);
                    eprintln!("[downloader] Requeued {} (attempt {}/{})", key, count, MAX_RETRIES);
                }
            }
        }
    }
}

// ── Fallback: NDJSON stdin/file loop ─────────────────────────────────────────

fn run_ndjson_loop(
    input_path: Option<&PathBuf>,
    artifacts_dir: &PathBuf,
    max_file_bytes: Option<u64>,
    client: &reqwest::blocking::Client,
) {
    let stdin_handle;
    let file_handle;
    let reader: Box<dyn BufRead> = match input_path {
        Some(p) => {
            let f = std::fs::File::open(p).unwrap_or_else(|e| {
                eprintln!("Cannot open input file {}: {}", p.display(), e);
                std::process::exit(1);
            });
            file_handle = io::BufReader::new(f);
            Box::new(file_handle)
        }
        None => {
            stdin_handle = io::BufReader::new(io::stdin());
            Box::new(stdin_handle)
        }
    };

    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut processed = 0u64;
    let mut skipped = 0u64;
    let mut errors = 0u64;

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[downloader] Read error: {}", e);
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let job: IngestJob = match serde_json::from_str(trimmed) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[downloader] Skipping malformed job line: {}", e);
                skipped += 1;
                continue;
            }
        };

        eprintln!(
            "[downloader] Processing {}@{} (priority={:.2})",
            job.package, job.version, job.priority
        );

        match process_job(&job, artifacts_dir, max_file_bytes, client) {
            Ok(artifact) => {
                let json = serde_json::to_string(&artifact).unwrap_or_else(|_| "{}".to_string());
                if let Err(e) = writeln!(writer, "{}", json) {
                    eprintln!("[downloader] Output write error: {}", e);
                    std::process::exit(1);
                }
                let _ = writer.flush();
                processed += 1;
            }
            Err(e) => {
                eprintln!("[downloader] Failed {}@{}: {}", job.package, job.version, e);
                errors += 1;
            }
        }
    }

    eprintln!(
        "[downloader] Done. processed={} skipped={} errors={}",
        processed, skipped, errors
    );
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();

    fs::ensure_artifacts_root(&args.artifacts_dir).unwrap_or_else(|e| {
        eprintln!("Cannot create artifacts dir {}: {}", args.artifacts_dir.display(), e);
        std::process::exit(1);
    });

    let client = fetch::build_client().unwrap_or_else(|e| {
        eprintln!("Failed to build HTTP client: {}", e);
        std::process::exit(1);
    });

    if let Some(url) = &args.redis_url {
        eprintln!("[downloader] Redis mode: {}", url);
        run_redis_loop(url, &args.artifacts_dir, args.max_file_bytes, &client);
    } else {
        eprintln!("[downloader] NDJSON mode (no REDIS_URL)");
        run_ndjson_loop(args.input_path.as_ref(), &args.artifacts_dir, args.max_file_bytes, &client);
    }
}
