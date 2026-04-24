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
use stream::{build_client, ChangeStream};

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

    // Build the output sink: Redis > file > stdout
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

    let mut backoff_secs: u64 = 1;

    loop {
        eprintln!("[ingestor] Connecting from seq={}", state.last_seq);

        match ChangeStream::connect(&http, &state.last_seq) {
            Err(e) => {
                eprintln!("[ingestor] Connection error: {}. Retrying in {}s.", e, backoff_secs);
                std::thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
            Ok(stream) => {
                backoff_secs = 1;
                let mut jobs_emitted: u64 = 0;

                for line_result in stream {
                    let line = match line_result {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("[ingestor] Stream read error: {}. Reconnecting.", e);
                            break;
                        }
                    };

                    for event in &line.events {
                        let pkg_ver = format!("{}@{}", event.package, event.version);

                        if state.seen.contains_key(&pkg_ver) {
                            continue;
                        }

                        if let Some(priority) = filter::score(event, &state) {
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

                    if let Some(seq) = line.seq {
                        state.last_seq = seq;
                        if let Err(e) = state.save(&args.state_path) {
                            eprintln!("[ingestor] State save error: {}", e);
                        }
                    }
                }

                eprintln!("[ingestor] Stream ended. Reconnecting in {}s.", backoff_secs);
                std::thread::sleep(Duration::from_secs(backoff_secs));
            }
        }
    }
}
