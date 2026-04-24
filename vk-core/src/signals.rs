use serde::{Deserialize, Serialize};
use vk_ir::{IrNode, IrNodeKind, NodeTag};

use crate::flow::{BehaviorGraph, ExecutionChain};

// ── Signal taxonomy ───────────────────────────────────────────────────────────

/// A semantic signal derived from IR facts.
///
/// Signals represent *what the code means*, not *what syntax it contains*.
/// They are derived after IR is complete, so the IR stays stable while
/// signal rules can be recalibrated independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Signal {
    /// A lifecycle hook (postinstall/preinstall/install) triggers code.
    PostinstallExecution,
    /// Code fetches a remote resource (HTTP/HTTPS).
    RemotePayloadFetch,
    /// Code executes a shell command.
    ShellChainExecution,
    /// Code calls eval() or new Function() with dynamic content.
    DynamicCodeEval,
    /// Code decodes an encoded payload (base64/hex) before use.
    EncodedPayloadDecode,
    /// Code uses dynamic require() or obfuscated property access.
    ObfuscatedLoader,
    /// Code writes to the filesystem.
    FilesystemWrite,
    /// Code reads from the filesystem.
    FilesystemRead,
    /// A network request is followed by eval in the same chain.
    RemoteCodeExecution,
    /// A ProcessExec and NetworkRequest appear in the same execution chain.
    RemoteExecChain,
    /// A DynamicImport and ObfuscatedFlow appear in the same execution chain.
    DynamicLoaderPattern,
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

/// Severity weight for a single signal in [0.0, 1.0].
///
/// Weights are calibrated so that the worst-case composite
/// (RemoteCodeExecution + high-confidence chain) reaches 1.0.
pub fn signal_weight(s: &Signal) -> f32 {
    match s {
        Signal::RemoteCodeExecution   => 1.00,
        Signal::RemoteExecChain       => 0.95,
        Signal::DynamicLoaderPattern  => 0.75,
        Signal::ShellChainExecution   => 0.70,
        Signal::DynamicCodeEval       => 0.65,
        Signal::PostinstallExecution  => 0.60,
        Signal::EncodedPayloadDecode  => 0.60,
        Signal::ObfuscatedLoader      => 0.55,
        Signal::RemotePayloadFetch    => 0.50,
        Signal::FilesystemWrite       => 0.30,
        Signal::FilesystemRead        => 0.20,
    }
}

/// Compute a composite risk score in [0.0, 1.0].
///
/// Formula: `min(1.0, max_signal_weight + chain_confidence_boost * 0.15)`
///
/// The confidence boost is intentionally small; signals are the primary
/// driver so that a confident-but-benign package doesn't score high.
pub fn compute_risk_score(signals: &[Signal], max_chain_confidence: f32) -> f32 {
    let base = signals
        .iter()
        .map(signal_weight)
        .fold(0.0f32, f32::max);
    let boost = max_chain_confidence * 0.15;
    (base + boost).min(1.0)
}

// ── Derivation ────────────────────────────────────────────────────────────────

/// Derive the set of signals present in this package's IR and behaviour graph.
pub fn derive_signals(ir_nodes: &[IrNode], graph: &BehaviorGraph) -> Vec<Signal> {
    let mut signals = std::collections::HashSet::new();

    // IR-level signals (presence of node types)
    for node in ir_nodes {
        match &node.kind {
            IrNodeKind::EntryPoint { script: Some(_) } => {
                signals.insert(Signal::PostinstallExecution);
            }
            IrNodeKind::ProcessExec { .. } => {
                signals.insert(Signal::ShellChainExecution);
            }
            IrNodeKind::NetworkRequest { .. } => {
                signals.insert(Signal::RemotePayloadFetch);
            }
            IrNodeKind::Eval { .. } | IrNodeKind::FunctionConstructor { .. } => {
                signals.insert(Signal::DynamicCodeEval);
            }
            IrNodeKind::EncodedString { .. } => {
                signals.insert(Signal::EncodedPayloadDecode);
            }
            IrNodeKind::ObfuscatedFlow => {
                signals.insert(Signal::ObfuscatedLoader);
            }
            IrNodeKind::FileWrite { .. } => {
                signals.insert(Signal::FilesystemWrite);
            }
            IrNodeKind::FileRead { .. } => {
                signals.insert(Signal::FilesystemRead);
            }
            _ => {}
        }
    }

    // Build a node lookup for chain-level analysis that needs full node data
    let node_map: std::collections::HashMap<&str, &IrNode> =
        ir_nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    // Chain-level signals (compositional patterns across execution chains)
    for chain in &graph.execution_chains {
        derive_chain_signals(chain, &node_map, &mut signals);
    }

    let mut out: Vec<Signal> = signals.into_iter().collect();
    // Stable ordering for deterministic output
    out.sort_by_key(|s| format!("{:?}", s));
    out
}

fn derive_chain_signals(
    chain: &ExecutionChain,
    node_map: &std::collections::HashMap<&str, &IrNode>,
    signals: &mut std::collections::HashSet<Signal>,
) {
    let types: Vec<&str> = chain.chain.iter().map(|s| s.kind.as_str()).collect();

    let has_network       = types.iter().any(|&t| t == "NetworkRequest");
    let has_eval          = types.iter().any(|&t| matches!(t, "Eval" | "FunctionConstructor"));
    let has_encoded       = types.iter().any(|&t| t == "EncodedString");
    let has_exec          = types.iter().any(|&t| t == "ProcessExec");
    let has_dynamic_import = types.iter().any(|&t| t == "DynamicImport");
    let has_obfuscated    = types.iter().any(|&t| t == "ObfuscatedFlow");

    // NetworkRequest → Eval in the same chain = remote code execution
    if has_network && has_eval {
        signals.insert(Signal::RemoteCodeExecution);
    }

    // EncodedString → Eval in the same chain
    if has_encoded && has_eval {
        // Check if any encoded string node has high-entropy tag for stronger confidence
        let has_high_entropy = chain.chain.iter().any(|step| {
            node_map
                .get(step.node_id.as_str())
                .map(|n| n.tags.contains(&NodeTag::HighEntropyString))
                .unwrap_or(false)
        });
        signals.insert(Signal::EncodedPayloadDecode);
        signals.insert(Signal::DynamicCodeEval);
        let _ = has_high_entropy; // available for confidence weighting
    }

    // PostinstallExecution + ShellChainExecution
    if chain.entry_point.script.is_some() && has_exec {
        signals.insert(Signal::PostinstallExecution);
        signals.insert(Signal::ShellChainExecution);
    }

    // ProcessExec + NetworkRequest in same chain → RemoteExecChain
    if has_exec && has_network {
        signals.insert(Signal::RemoteExecChain);
    }

    // DynamicImport + ObfuscatedFlow in same chain → DynamicLoaderPattern
    if has_dynamic_import && has_obfuscated {
        signals.insert(Signal::DynamicLoaderPattern);
    }
}
