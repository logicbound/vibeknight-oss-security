/// Persistent storage helpers for the vk-cli daemon and query subcommands.
///
/// Directory layout under `<output_root>`:
/// ```
/// <output_root>/
///   index.jsonl              ← append-only finding summaries (source of truth)
///   state/<pkg>@<ver>.json   ← per-package analysis state markers
///   <pkg>/<ver>/             ← full JSON artifacts written by the daemon
/// ```
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use vk_core::signals::Signal;

// ── Finding summary ───────────────────────────────────────────────────────────

/// Compact, append-only record written to `index.jsonl` after each analysis.
///
/// This is the "source of truth" scanned by `vk list` and `vk triage`.
/// It intentionally omits the full execution chain — those remain in the
/// per-package artifact files for deep inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub package: String,
    pub version: String,
    pub risk_score: f32,
    pub signals: Vec<Signal>,
    /// Unix timestamp (seconds) when this analysis completed.
    pub ts: u64,
}

/// Append one `FindingSummary` to `<output_root>/index.jsonl`.
///
/// Creates the file (and any parent directories) if they do not exist.
/// Each call holds the file open only long enough to write one line,
/// so concurrent writers from separate processes are safe on POSIX.
pub fn append_finding(output_root: &Path, summary: &FindingSummary) -> std::io::Result<()> {
    let path = output_root.join("index.jsonl");
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(summary)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writeln!(file, "{}", line)
}

/// Read all `FindingSummary` records from `<output_root>/index.jsonl`.
///
/// Malformed lines are silently skipped so that a corrupt append cannot
/// bring down the query tools.
pub fn read_findings(output_root: &Path) -> Vec<FindingSummary> {
    let path = output_root.join("index.jsonl");
    let Ok(file) = fs::File::open(&path) else { return Vec::new() };
    BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<FindingSummary>(&l).ok())
        .collect()
}

// ── Analysis state markers ────────────────────────────────────────────────────

/// Per-package analysis state, written to `<output_root>/state/<pkg>@<ver>.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateMarker {
    pub state: AnalysisState,
    /// Unix timestamp (seconds) of the last state transition.
    pub ts: u64,
    /// Optional human-readable detail (e.g. error message on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The lifecycle state of a package analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisState {
    /// The artifact job was received but analysis has not yet started.
    Queued,
    /// Analysis completed successfully.
    Analyzed,
    /// Analysis failed after all retries.
    Failed,
}

/// Write (or overwrite) the state marker for `<pkg>@<ver>`.
pub fn write_state(
    output_root: &Path,
    package: &str,
    version: &str,
    state: AnalysisState,
    detail: Option<String>,
) -> std::io::Result<()> {
    let state_dir = output_root.join("state");
    fs::create_dir_all(&state_dir)?;

    let filename = format!("{}@{}.json", package.replace('/', "_"), version);
    let path = state_dir.join(filename);

    let marker = StateMarker {
        state,
        ts: now_secs(),
        detail,
    };
    let json = serde_json::to_string_pretty(&marker)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(path, json)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
