//! Calibration tests — run the full pipeline against a small corpus of
//! representative package shapes and assert the score lands in the expected
//! band.
//!
//! These are the guardrails that prevent the regression the refactor was
//! designed to fix: build-tools and CLIs must not score in the high band,
//! and obvious malware stubs must not score in the low band.

use std::path::PathBuf;

use serde_json::json;
use vk_core::{analyse, package_type::PackageClass, Signal};
use vk_ir::{DataSource, IrNode, IrNodeKind, SourceLocation};
use vk_npm::{EntryPoint, PackageGraph};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn corpus_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(name)
}

fn read_manifest(dir: &PathBuf) -> serde_json::Value {
    let raw = std::fs::read_to_string(dir.join("package.json"))
        .expect("read corpus package.json");
    serde_json::from_str(&raw).expect("parse corpus package.json")
}

fn collect_js_files(dir: &PathBuf) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read corpus dir")
        .filter_map(|e| {
            let e = e.ok()?;
            let p = e.path();
            match p.extension()?.to_str()? {
                "js" | "ts" | "jsx" | "tsx" => {
                    Some(p.file_name()?.to_string_lossy().into_owned())
                }
                _ => None,
            }
        })
        .collect()
}

fn build_graph(corpus: &str) -> PackageGraph {
    let dir = corpus_dir(corpus);
    let manifest = read_manifest(&dir);
    let files = collect_js_files(&dir);

    let mut entry_points: Vec<EntryPoint> = Vec::new();

    // bin / main
    if let Some(bin) = manifest["bin"].as_object() {
        for (_, v) in bin {
            if let Some(s) = v.as_str() {
                entry_points.push(EntryPoint::File {
                    path: s.trim_start_matches("./").to_string(),
                });
            }
        }
    }
    if let Some(main) = manifest["main"].as_str() {
        entry_points.push(EntryPoint::File {
            path: main.trim_start_matches("./").to_string(),
        });
    }

    // Lifecycle scripts
    if let Some(scripts) = manifest["scripts"].as_object() {
        for name in ["preinstall", "install", "postinstall"] {
            if let Some(cmd) = scripts.get(name).and_then(|v| v.as_str()) {
                entry_points.push(EntryPoint::InstallScript {
                    script: name.to_string(),
                    command: cmd.to_string(),
                });
            }
        }
    }

    PackageGraph {
        package: corpus.to_string(),
        version: "0.0.0-calibration".to_string(),
        integrity_hash: "0".repeat(64),
        files,
        entry_points,
        manifest,
        extracted_dir: dir,
    }
}

// ── Calibration thresholds ────────────────────────────────────────────────────

// Each corpus package has an expected score band and classification.
// Numbers are deliberately ranges, not exact — the scorer's internal
// weighting can be retuned without breaking these tests so long as the
// qualitative bucket is preserved.
struct Expected {
    /// Inclusive upper bound on the risk score.
    max_score: f32,
    /// Inclusive lower bound on the risk score (for malware cases).
    min_score: f32,
    class: PackageClass,
    /// Signals that MUST appear.
    must_have: &'static [Signal],
    /// Signals that MUST NOT appear.
    must_not_have: &'static [Signal],
}

#[test]
fn build_tool_scores_in_low_band() {
    let g = build_graph("build_tool");
    let (_, _, finding) = analyse(&g);

    let e = Expected {
        max_score: 0.35,
        min_score: 0.0,
        class: PackageClass::DevTool,
        must_have: &[],
        must_not_have: &[Signal::RemoteCodeExecution, Signal::RemoteExecChain],
    };
    assert_expected("build_tool", &finding, &e);

    // We should also detect the benign patterns.
    assert!(
        finding.benign_matches.iter().any(|m| m.category == "native_rebuild"),
        "expected native_rebuild benign match, got {:?}",
        finding.benign_matches
    );
}

#[test]
fn cli_scores_in_low_band() {
    let g = build_graph("cli");
    let (_, _, finding) = analyse(&g);

    let e = Expected {
        max_score: 0.45,
        min_score: 0.0,
        class: PackageClass::Cli,
        must_have: &[],
        must_not_have: &[Signal::RemoteCodeExecution, Signal::RemoteExecChain],
    };
    assert_expected("cli", &finding, &e);
}

#[test]
fn runtime_lib_scores_very_low() {
    let g = build_graph("runtime_lib");
    let (_, _, finding) = analyse(&g);

    let e = Expected {
        max_score: 0.20,
        min_score: 0.0,
        class: PackageClass::RuntimeLib,
        must_have: &[],
        must_not_have: &[
            Signal::ShellChainExecution,
            Signal::RemoteCodeExecution,
            Signal::RemoteExecChain,
            Signal::DynamicCodeEval,
        ],
    };
    assert_expected("runtime_lib", &finding, &e);
}

#[test]
fn malware_scores_in_high_band() {
    let g = build_graph("malware");
    let (_, _, finding) = analyse(&g);

    let e = Expected {
        max_score: 1.01, // effectively unbounded
        min_score: 0.65,
        class: PackageClass::Unknown, // scripts.postinstall without other priors
        must_have: &[
            Signal::DynamicCodeEval,
            Signal::EncodedPayloadDecode,
        ],
        must_not_have: &[],
    };
    // Don't assert exact class for malware fixture; any class is acceptable
    // as long as the score is high — the test exists to prove the gate
    // doesn't suppress real signals.
    assert!(
        finding.risk_score >= e.min_score,
        "malware score too low: {} (breakdown: {:?})",
        finding.risk_score, finding.score_breakdown
    );
    for s in e.must_have {
        assert!(
            finding.signals.contains(s),
            "malware missing signal {:?}; got {:?}",
            s, finding.signals
        );
    }
    // Attacker control must be non-trivial.
    assert!(
        finding.attacker_control.score > 0.5,
        "malware attacker_control too low: {}",
        finding.attacker_control.score
    );
}

// ── Property test ─────────────────────────────────────────────────────────────

#[test]
fn property_literal_args_devtool_bounded() {
    // For any IR where every sink's arg_source is `Literal` and the package
    // is classified as DevTool, risk_score must be <= 0.35 — this is the
    // exact regression-guard the plan calls out.
    use vk_core::{
        attacker_control::compute_attacker_control,
        benign_patterns::collect_benign_matches,
        flow::BehaviorGraph,
        package_type::classify_package,
        scoring::{build_feature_vector, compute_risk_score, ScoreInputs},
        signals::derive_signals,
    };

    // Synthesize a stress-test IR: many capability signals, all literal args.
    let mut nodes: Vec<IrNode> = Vec::new();
    for (i, cmd) in [
        "node-gyp rebuild",
        "prebuild-install",
        "npm rebuild",
        "tsc --declaration",
    ]
    .iter()
    .enumerate()
    {
        nodes.push(IrNode::new(
            IrNodeKind::ProcessExec {
                command: Some((*cmd).to_string()),
                arg_source: DataSource::Literal { value: (*cmd).to_string() },
            },
            SourceLocation { file: "x.js".into(), line: (i + 1) as u32, col: 1 },
        ));
    }
    // Plus a file write to build/
    nodes.push(IrNode::new(
        IrNodeKind::FileWrite {
            path: Some("build/Release/addon.node".into()),
            arg_source: DataSource::Literal {
                value: "build/Release/addon.node".into(),
            },
        },
        SourceLocation { file: "x.js".into(), line: 10, col: 1 },
    ));

    let bg = BehaviorGraph {
        schema_version: "1.0".into(),
        execution_chains: vec![],
        edges: vec![],
    };

    let manifest = json!({
        "name": "devtool",
        "version": "1.0.0",
        "scripts": { "postinstall": "node-gyp rebuild" },
        "dependencies": { "node-gyp": "*" }
    });
    let classification = classify_package(Some(&manifest), &nodes);
    assert_eq!(classification.class, PackageClass::DevTool);

    let signals = derive_signals(&nodes, &bg);
    let ac = compute_attacker_control(&nodes, &bg);
    let benign = collect_benign_matches(&nodes);
    let features = build_feature_vector(&nodes, &bg.execution_chains);

    let score = compute_risk_score(&ScoreInputs {
        signals: &signals,
        chains: &bg.execution_chains,
        nodes: &nodes,
        attacker_control: ac.score,
        package_class: &classification.class,
        benign_matches: &benign,
    });

    // Literal + DevTool must keep the final score in the low band.
    assert!(
        score.final_score <= 0.35,
        "DevTool with literal args scored {} (breakdown: {:?})",
        score.final_score, score
    );

    let _ = features; // not asserted, but built
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn assert_expected(name: &str, finding: &vk_core::Finding, e: &Expected) {
    assert!(
        finding.risk_score <= e.max_score,
        "{}: risk_score {} exceeded max {}. Breakdown: {:?}",
        name, finding.risk_score, e.max_score, finding.score_breakdown
    );
    assert!(
        finding.risk_score >= e.min_score,
        "{}: risk_score {} below min {}. Breakdown: {:?}",
        name, finding.risk_score, e.min_score, finding.score_breakdown
    );
    assert_eq!(
        finding.classification.class, e.class,
        "{}: expected class {:?}, got {:?}. Evidence: {:?}",
        name, e.class, finding.classification.class, finding.classification.evidence
    );
    for s in e.must_have {
        assert!(
            finding.signals.contains(s),
            "{}: missing signal {:?}; got {:?}",
            name, s, finding.signals
        );
    }
    for s in e.must_not_have {
        assert!(
            !finding.signals.contains(s),
            "{}: unexpected signal {:?}; got {:?}",
            name, s, finding.signals
        );
    }
}
