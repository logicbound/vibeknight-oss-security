mod queue;
mod store;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use store::{AnalysisState, FindingSummary};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "vk", about = "Behavioural npm package analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyse a single package from a tarball or registry spec.
    Analyze {
        #[arg(long, value_name = "PATH_OR_SPEC")]
        input: String,
        #[arg(long, value_name = "DIR", default_value = "./vk-output")]
        output: PathBuf,
    },

    /// Streaming daemon: consume artifacts from Redis, analyse, push findings.
    Daemon {
        #[arg(long, value_name = "URL", env = "REDIS_URL", default_value = "redis://127.0.0.1:6379/")]
        redis_url: String,
        #[arg(long, value_name = "DIR", default_value = "./vk-output")]
        output: PathBuf,
    },

    /// List completed findings filtered by minimum risk score.
    List {
        /// Minimum risk_score threshold in [0.0, 1.0].
        #[arg(long, value_name = "SCORE", default_value = "0.0")]
        min_risk: f32,
        /// Root output directory (same as used by daemon/analyze).
        #[arg(long, value_name = "DIR", default_value = "./vk-output")]
        output: PathBuf,
    },

    /// Show the top-N most suspicious packages ranked by risk score.
    Triage {
        /// Number of results to show.
        #[arg(long, value_name = "N", default_value = "20")]
        top: usize,
        /// Root output directory (same as used by daemon/analyze).
        #[arg(long, value_name = "DIR", default_value = "./vk-output")]
        output: PathBuf,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { input, output } => cmd_analyze(&input, &output),
        Commands::Daemon { redis_url, output } => cmd_daemon(&redis_url, &output),
        Commands::List { min_risk, output }  => cmd_list(min_risk, &output),
        Commands::Triage { top, output }     => cmd_triage(top, &output),
    }
}

// ── analyze ───────────────────────────────────────────────────────────────────

fn cmd_analyze(input: &str, output: &Path) {
    let input_path = Path::new(input);
    let pkg_input = if input_path.exists() && input.ends_with(".tgz") {
        vk_npm::PackageInput::Tarball(input_path)
    } else {
        vk_npm::PackageInput::Registry(input)
    };

    eprint!("[ 1/4 ] Ingesting package... ");
    let (package_graph, _tmp) = vk_npm::ingest(pkg_input).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        std::process::exit(1);
    });
    eprintln!(
        "ok  ({} files, {} entry points)",
        package_graph.files.len(),
        package_graph.entry_points.len()
    );

    eprint!("[ 2/4 ] Analysing {} JS/TS files... ", package_graph.files.len());
    let (ir_graph, behavior_graph, finding) = vk_core::analyse(&package_graph);
    eprintln!("ok  ({} IR nodes, risk={:.2})", ir_graph.nodes.len(), finding.risk_score);

    eprint!("[ 3/4 ] Writing artifacts to {}... ", output.display());
    std::fs::create_dir_all(output).unwrap_or_else(|e| {
        eprintln!("error creating output dir: {}", e);
        std::process::exit(1);
    });

    write_json(&output.join("package_graph.json"), &package_graph);
    write_json(&output.join("ir_graph.json"),       &ir_graph);
    write_json(&output.join("behavior_graph.json"), &behavior_graph);
    write_json(&output.join("finding.json"),        &finding);

    // Append to the shared findings log
    let summary = FindingSummary {
        package: finding.package.clone(),
        version: finding.version.clone(),
        risk_score: finding.risk_score,
        signals: finding.signals.clone(),
        ts: store::now_secs(),
    };
    let _ = store::append_finding(output, &summary);
    eprintln!("ok");

    eprintln!("[ 4/4 ] Done.");
    eprintln!();
    print_finding_summary(&finding);
}

// ── daemon ────────────────────────────────────────────────────────────────────

use queue::Artifact;

fn cmd_daemon(redis_url: &str, output: &Path) {
    let mut con = queue::connect(redis_url).unwrap_or_else(|e| {
        eprintln!("[analyzer] Cannot connect to Redis ({}): {}", redis_url, e);
        std::process::exit(1);
    });

    eprintln!("[analyzer] Daemon started. Consuming {}", queue::ARTIFACT_QUEUE);
    std::fs::create_dir_all(output).unwrap_or_else(|e| {
        eprintln!("[analyzer] Cannot create output dir: {}", e);
        std::process::exit(1);
    });

    let mut retry_counts: HashMap<String, u32> = HashMap::new();

    loop {
        let (raw_json, artifact) = match queue::pop_artifact(&mut con) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("[analyzer] Redis pop error: {}. Reconnecting.", e);
                con = loop {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    match queue::connect(redis_url) {
                        Ok(c) => break c,
                        Err(e) => eprintln!("[analyzer] Reconnect failed: {}", e),
                    }
                };
                continue;
            }
        };

        if artifact.schema_version != 1 {
            eprintln!(
                "[analyzer] Unsupported schema_version={} for {}@{} — dead-lettering.",
                artifact.schema_version, artifact.package, artifact.version
            );
            let _ = queue::push_dead_letter(
                &mut con,
                &raw_json,
                &format!("unsupported schema_version={}", artifact.schema_version),
            );
            continue;
        }

        let key = format!("{}@{}", artifact.package, artifact.version);
        eprintln!("[analyzer] Analysing {}", key);

        // Mark as queued before starting
        let _ = store::write_state(output, &artifact.package, &artifact.version, AnalysisState::Queued, None);

        match analyse_artifact(&artifact, output) {
            Ok(finding_json) => {
                retry_counts.remove(&key);
                if let Err(e) = queue::push_finding(&mut con, &finding_json) {
                    eprintln!("[analyzer] Failed to push finding to Redis: {}", e);
                }
                let _ = store::write_state(
                    output,
                    &artifact.package,
                    &artifact.version,
                    AnalysisState::Analyzed,
                    None,
                );
            }
            Err(e) => {
                eprintln!("[analyzer] Failed {}: {}", key, e);
                let count = retry_counts.entry(key.clone()).or_insert(0);
                *count += 1;
                if *count > queue::MAX_RETRIES {
                    eprintln!("[analyzer] Max retries exceeded for {} — dead-lettering.", key);
                    let _ = queue::push_dead_letter(&mut con, &raw_json, &e);
                    let _ = store::write_state(
                        output,
                        &artifact.package,
                        &artifact.version,
                        AnalysisState::Failed,
                        Some(e),
                    );
                    retry_counts.remove(&key);
                } else {
                    let _ = redis::cmd("LPUSH")
                        .arg(queue::ARTIFACT_QUEUE)
                        .arg(&raw_json)
                        .query::<i64>(&mut con);
                    eprintln!(
                        "[analyzer] Requeued {} (attempt {}/{})",
                        key, count, queue::MAX_RETRIES
                    );
                }
            }
        }
    }
}

fn analyse_artifact(artifact: &Artifact, output: &Path) -> Result<String, String> {
    let dir = Path::new(&artifact.artifact_path);
    if !dir.is_dir() {
        return Err(format!("artifact_path is not a directory: {}", artifact.artifact_path));
    }

    let pkg = vk_npm::from_extracted_dir(dir, &artifact.package, &artifact.version, &artifact.sha256)
        .map_err(|e| e.to_string())?;

    let (ir_graph, behavior_graph, finding) = vk_core::analyse(&pkg);

    // Write per-package artifacts to <output>/<package>/<version>/
    let pkg_out = output
        .join(artifact.package.replace('/', "_"))
        .join(&artifact.version);
    std::fs::create_dir_all(&pkg_out).map_err(|e| e.to_string())?;

    write_json(&pkg_out.join("ir_graph.json"),       &ir_graph);
    write_json(&pkg_out.join("behavior_graph.json"), &behavior_graph);
    write_json(&pkg_out.join("finding.json"),        &finding);

    // Append compact summary to the shared findings log
    let summary = FindingSummary {
        package: finding.package.clone(),
        version: finding.version.clone(),
        risk_score: finding.risk_score,
        signals: finding.signals.clone(),
        ts: store::now_secs(),
    };
    let _ = store::append_finding(output, &summary);

    eprintln!(
        "[analyzer] {} risk={:.2} signals={}",
        format!("{}@{}", artifact.package, artifact.version),
        finding.risk_score,
        finding.signals.len()
    );

    serde_json::to_string(&finding).map_err(|e| e.to_string())
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_list(min_risk: f32, output: &Path) {
    let mut findings = store::read_findings(output);
    findings.retain(|f| f.risk_score >= min_risk);
    // Sort by risk desc, then package name asc for stable ordering
    findings.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.package.cmp(&b.package))
    });

    if findings.is_empty() {
        eprintln!("No findings with risk_score >= {:.2} in {}.", min_risk, output.display());
        return;
    }

    println!("{}", risk_band_header(min_risk));
    for f in &findings {
        println!(
            "  {:<40}  risk: {:.2}  [{}]  {}",
            format!("{}@{}", f.package, f.version),
            f.risk_score,
            risk_label(f.risk_score),
            f.signals
                .iter()
                .map(|s| format!("{:?}", s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

// ── triage ────────────────────────────────────────────────────────────────────

fn cmd_triage(top: usize, output: &Path) {
    let mut findings = store::read_findings(output);
    findings.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings.truncate(top);

    if findings.is_empty() {
        eprintln!("No findings found in {}.", output.display());
        return;
    }

    println!("TOP {} BY RISK SCORE", findings.len());
    println!("{}", "─".repeat(72));

    let mut current_band = "";
    for f in &findings {
        let band = risk_band(f.risk_score);
        if band != current_band {
            println!();
            println!("  {} RISK ({:.1}–{:.1})", band, band_low(band), band_high(band));
            current_band = band;
        }
        println!(
            "  {:<40}  {:.2}  {}",
            format!("{}@{}", f.package, f.version),
            f.risk_score,
            f.signals
                .iter()
                .map(|s| format!("{:?}", s))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!();
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn risk_label(score: f32) -> &'static str {
    if score >= 0.8 { "HIGH" } else if score >= 0.4 { "MED" } else { "LOW" }
}

fn risk_band(score: f32) -> &'static str {
    if score >= 0.8 { "HIGH" } else if score >= 0.4 { "MED" } else { "LOW" }
}

fn risk_band_header(min_risk: f32) -> String {
    format!(
        "FINDINGS  min_risk={:.2}  (HIGH≥0.8 / MED≥0.4 / LOW<0.4)",
        min_risk
    )
}

fn band_low(band: &str) -> f32 {
    match band { "HIGH" => 0.8, "MED" => 0.4, _ => 0.0 }
}

fn band_high(band: &str) -> f32 {
    match band { "HIGH" => 1.0, "MED" => 0.8, _ => 0.4 }
}

fn print_finding_summary(finding: &vk_core::Finding) {
    eprintln!("  Package : {}@{}", finding.package, finding.version);
    eprintln!("  Hash    : {}", finding.integrity_hash);
    eprintln!("  Risk    : {:.2}  [{}]", finding.risk_score, risk_label(finding.risk_score));
    eprintln!("  Signals : {}", finding.signals.len());
    for sig in &finding.signals {
        eprintln!("            - {:?}", sig);
    }
    eprintln!("  Chains  : {}", finding.execution_chains.len());
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
    let json = serde_json::to_string_pretty(value).expect("serialization failed");
    std::fs::write(path, json).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", path.display(), e);
    });
}
