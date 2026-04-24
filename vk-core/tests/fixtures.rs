/// Integration tests — run the full analysis pipeline against JS fixture files.
///
/// Fixtures live in `vk-lang-js/tests/fixtures/<category>/<name>/index.js`.
/// Each test constructs a synthetic `PackageGraph` pointing at a fixture directory
/// so the full pipeline (IR → flow → signals) can exercise the real code path.
use std::path::PathBuf;

use vk_core::{analyse, Signal};
use vk_npm::{EntryPoint, PackageGraph};

// ── Helper ────────────────────────────────────────────────────────────────────

/// Build a synthetic `PackageGraph` pointing at a fixture directory.
///
/// `fixture` is a path relative to `vk-lang-js/tests/fixtures/`, e.g.
/// `"malicious/exec_chain"`.
///
/// `install_scripts` adds synthetic install-script entry points so the
/// behaviour graph can form chains anchored at a lifecycle hook.
fn make_fixture_graph(fixture: &str, install_scripts: &[(&str, &str)]) -> PackageGraph {
    // Fixtures live alongside the vk-lang-js crate; navigate from the manifest
    // directory of vk-core (CARGO_MANIFEST_DIR) to the sibling crate.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_root = manifest_dir
        .parent()
        .expect("workspace root")
        .join("vk-lang-js")
        .join("tests")
        .join("fixtures");

    let dir = fixtures_root.join(fixture);
    assert!(dir.exists(), "Fixture directory not found: {}", dir.display());

    let files: Vec<String> = std::fs::read_dir(&dir)
        .expect("read fixture dir")
        .filter_map(|e| {
            let e = e.ok()?;
            let p = e.path();
            if matches!(p.extension()?.to_str()?, "js" | "ts" | "jsx" | "tsx") {
                Some(e.file_name().to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .collect();

    let mut entry_points: Vec<EntryPoint> = files
        .iter()
        .map(|f| EntryPoint::File { path: f.clone() })
        .collect();

    for (script, command) in install_scripts {
        entry_points.push(EntryPoint::InstallScript {
            script: script.to_string(),
            command: command.to_string(),
        });
    }

    PackageGraph {
        package: fixture.replace('/', "-"),
        version: "0.0.0-test".to_string(),
        integrity_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        files,
        entry_points,
        extracted_dir: dir,
    }
}

fn run_fixture(fixture: &str) -> Vec<Signal> {
    run_fixture_with_install(fixture, &[])
}

fn run_fixture_with_install(fixture: &str, install_scripts: &[(&str, &str)]) -> Vec<Signal> {
    let graph = make_fixture_graph(fixture, install_scripts);
    let (_ir, _bg, finding) = analyse(&graph);
    finding.signals
}

// ── Malicious fixtures ────────────────────────────────────────────────────────

#[test]
fn exec_chain_triggers_shell_signals() {
    let sigs = run_fixture_with_install(
        "malicious/exec_chain",
        &[("postinstall", "node index.js")],
    );
    assert!(
        sigs.contains(&Signal::ShellChainExecution),
        "expected ShellChainExecution, got: {:?}", sigs
    );
    assert!(
        sigs.contains(&Signal::PostinstallExecution),
        "expected PostinstallExecution, got: {:?}", sigs
    );
    assert!(
        sigs.contains(&Signal::RemotePayloadFetch),
        "expected RemotePayloadFetch (https.get), got: {:?}", sigs
    );
    // Both NetworkRequest and ProcessExec in the same file → RemoteExecChain
    assert!(
        sigs.contains(&Signal::RemoteExecChain),
        "expected RemoteExecChain (exec + https in same chain), got: {:?}", sigs
    );
}

#[test]
fn decode_eval_triggers_encoded_and_dynamic_eval() {
    let sigs = run_fixture("malicious/decode_eval");
    assert!(
        sigs.contains(&Signal::EncodedPayloadDecode),
        "expected EncodedPayloadDecode, got: {:?}", sigs
    );
    assert!(
        sigs.contains(&Signal::DynamicCodeEval),
        "expected DynamicCodeEval, got: {:?}", sigs
    );
}

#[test]
fn remote_fetch_eval_triggers_rce_signal() {
    let sigs = run_fixture("malicious/remote_fetch");
    assert!(
        sigs.contains(&Signal::RemotePayloadFetch),
        "expected RemotePayloadFetch, got: {:?}", sigs
    );
    assert!(
        sigs.contains(&Signal::DynamicCodeEval),
        "expected DynamicCodeEval, got: {:?}", sigs
    );
    // RemoteCodeExecution requires NetworkRequest → Eval in the same chain,
    // which the DFS tracer should connect in the remote_fetch fixture.
    assert!(
        sigs.contains(&Signal::RemoteCodeExecution),
        "expected RemoteCodeExecution, got: {:?}", sigs
    );
}

// ── Suspicious fixtures ───────────────────────────────────────────────────────

#[test]
fn dynamic_require_triggers_obfuscated_loader() {
    let sigs = run_fixture("suspicious/dynamic_require");
    assert!(
        sigs.contains(&Signal::ObfuscatedLoader),
        "expected ObfuscatedLoader, got: {:?}", sigs
    );
}

#[test]
fn obfuscated_load_fixture_emits_signals() {
    let sigs = run_fixture("suspicious/obfuscated_load");
    // Bracket access on a known binding should be detected as obfuscated
    // or at minimum not panic; we accept either ObfuscatedLoader or ShellChainExecution
    let has_any_signal = sigs.contains(&Signal::ObfuscatedLoader)
        || sigs.contains(&Signal::ShellChainExecution);
    assert!(has_any_signal, "expected at least one suspicious signal, got: {:?}", sigs);
}

// ── Benign fixture ────────────────────────────────────────────────────────────

#[test]
fn benign_module_produces_no_dangerous_signals() {
    let sigs = run_fixture("benign/simple_module");
    let dangerous = [
        Signal::ShellChainExecution,
        Signal::RemotePayloadFetch,
        Signal::DynamicCodeEval,
        Signal::RemoteCodeExecution,
        Signal::RemoteExecChain,
        Signal::DynamicLoaderPattern,
    ];
    for sig in &dangerous {
        assert!(
            !sigs.contains(sig),
            "benign fixture should NOT produce {:?}, but got: {:?}", sig, sigs
        );
    }
}

// ── Schema version propagation ────────────────────────────────────────────────

#[test]
fn finding_carries_schema_version() {
    let graph = make_fixture_graph("benign/simple_module", &[]);
    let (_ir, _bg, finding) = analyse(&graph);
    assert_eq!(finding.schema_version, "1.0");
}

#[test]
fn ir_graph_carries_schema_version() {
    let graph = make_fixture_graph("benign/simple_module", &[]);
    let (ir, _bg, _finding) = analyse(&graph);
    assert_eq!(ir.schema_version, "1.0");
}

#[test]
fn behavior_graph_carries_schema_version() {
    let graph = make_fixture_graph("benign/simple_module", &[]);
    let (_ir, bg, _finding) = analyse(&graph);
    assert_eq!(bg.schema_version, "1.0");
}
