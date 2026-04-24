mod emitter;
mod filter;
mod parser;
mod queue;
mod state;
mod stream;

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use emitter::{IngestJob, INGEST_JOB_SCHEMA_VERSION};
use state::IngestorState;
use stream::{build_client, fetch_current_seq, fetch_packument, poll_changes, DEFAULT_LIMIT};

// ── CLI args ──────────────────────────────────────────────────────────────────

struct Args {
    state_path: PathBuf,
    /// Redis URL.  `REDIS_URL` env var is the fallback.  If neither is set,
    /// fall back to writing NDJSON to stdout (useful for local testing).
    redis_url: Option<String>,
    /// Write NDJSON to this file instead of Redis/stdout (debug mode).
    output_path: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut state_path = IngestorState::default_path();
    let mut redis_url: Option<String> = std::env::var("REDIS_URL").ok();
    let mut output_path: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => {
                if let Some(v) = args.next() { state_path = PathBuf::from(v); }
            }
            "--redis-url" => {
                if let Some(v) = args.next() { redis_url = Some(v); }
            }
            "--output" => {
                if let Some(v) = args.next() { output_path = Some(PathBuf::from(v)); }
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: vk-ingestor [--state <path>] [--redis-url <url>] [--output <path>]\n\n\
                     Options:\n  \
                       --state <path>      State file for seq + seen set (default: vk-ingestor-state.json)\n  \
                       --redis-url <url>   Redis URL (default: $REDIS_URL; fallback: stdout NDJSON)\n  \
                       --output <path>     Write NDJSON to file instead of Redis/stdout"
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                std::process::exit(1);
            }
        }
    }

    Args { state_path, redis_url, output_path }
}

// ── Output sink ───────────────────────────────────────────────────────────────

enum Sink {
    Redis(redis::Connection),
    Writer(Box<dyn Write>),
}

impl Sink {
    fn emit(&mut self, job: &IngestJob) -> Result<(), String> {
        match self {
            Sink::Redis(con) => queue::push_job(con, job).map_err(|e| e.to_string()),
            Sink::Writer(w) => emitter::emit(w, job).map_err(|e| e.to_string()),
        }
    }

    fn flush(&mut self) {
        if let Sink::Writer(w) = self {
            let _ = w.flush();
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args = parse_args();
    let mut state = IngestorState::load(&args.state_path);

    let mut sink: Sink = if let Some(url) = &args.redis_url {
        match queue::connect(url) {
            Ok(con) => {
                eprintln!("[ingestor] Redis sink: {}", url);
                Sink::Redis(con)
            }
            Err(e) => {
                eprintln!("[ingestor] Cannot connect to Redis ({}): {}. Falling back to stdout.", url, e);
                Sink::Writer(Box::new(BufWriter::new(io::stdout())))
            }
        }
    } else if let Some(p) = &args.output_path {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap_or_else(|e| {
                eprintln!("Cannot open output file {}: {}", p.display(), e);
                std::process::exit(1);
            });
        Sink::Writer(Box::new(BufWriter::new(file)))
    } else {
        Sink::Writer(Box::new(BufWriter::new(io::stdout())))
    };

    let http = build_client().unwrap_or_else(|e| {
        eprintln!("Failed to build HTTP client: {}", e);
        std::process::exit(1);
    });

    // On a fresh start, jump to the current tip instead of replaying history.
    // "0" is the sentinel for "starting fresh" written by IngestorState::default.
    if state.last_seq == "0" {
        match fetch_current_seq(&http) {
            Ok(seq) => {
                eprintln!("[ingestor] Fresh start: jumping to current tip seq={}", seq);
                state.last_seq = seq;
                let _ = state.save(&args.state_path);
            }
            Err(e) => {
                eprintln!(
                    "[ingestor] Failed to fetch current tip ({}). Falling back to since=0.",
                    e
                );
            }
        }
    }

    let mut backoff_secs: u64 = 1;

    loop {
        match poll_changes(&http, &state.last_seq, DEFAULT_LIMIT) {
            Err(e) => {
                eprintln!(
                    "[ingestor] Poll error: {}. Retrying in {}s.",
                    e, backoff_secs
                );
                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
            Ok(changes) => {
                backoff_secs = 1;

                let num_changed = changes.package_ids.len();
                let mut jobs_emitted: u64 = 0;
                let mut fetch_errors: u64 = 0;

                for pkg in &changes.package_ids {
                    let packument = match fetch_packument(&http, pkg) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[ingestor] Packument fetch failed for {}: {}", pkg, e);
                            fetch_errors += 1;
                            continue;
                        }
                    };

                    let Some(event) = parser::parse_packument_latest(&packument, pkg) else {
                        continue;
                    };

                    let pkg_ver = format!("{}@{}", event.package, event.version);
                    if state.seen.contains_key(&pkg_ver) {
                        continue;
                    }

                    if let Some(priority) = filter::score(&event, &state) {
                        let job = IngestJob {
                            schema_version: INGEST_JOB_SCHEMA_VERSION,
                            package: event.package.clone(),
                            version: event.version.clone(),
                            tarball_url: event.tarball_url.clone(),
                            last_modified: event.last_modified.clone(),
                            priority,
                        };

                        if let Err(e) = sink.emit(&job) {
                            eprintln!("[ingestor] Emit error: {}", e);
                            std::process::exit(1);
                        }

                        jobs_emitted += 1;
                        if jobs_emitted % 100 == 0 {
                            sink.flush();
                        }

                        state.mark_seen(&event.package, &event.version);
                    }
                }

                // Advance the cursor once we've processed this batch, and
                // persist so restarts don't re-process.
                if changes.last_seq != state.last_seq {
                    state.last_seq = changes.last_seq.clone();
                    if let Err(e) = state.save(&args.state_path) {
                        eprintln!("[ingestor] State save error: {}", e);
                    }
                }
                sink.flush();

                eprintln!(
                    "[ingestor] Batch done: changes={}, jobs_emitted={}, fetch_errors={}, new_seq={}",
                    num_changed, jobs_emitted, fetch_errors, state.last_seq
                );

                // If we got fewer than `limit` results we've caught up; wait
                // a bit before polling again. Otherwise poll immediately — we
                // may still be behind the tip.
                if (num_changed as u32) < DEFAULT_LIMIT {
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }
}
