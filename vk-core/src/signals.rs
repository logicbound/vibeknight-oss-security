use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use vk_ir::{IrNode, IrNodeKind};

use crate::flow::{BehaviorGraph, ExecutionChain};

// ── Signal taxonomy ───────────────────────────────────────────────────────────

/// A semantic signal derived from IR facts.
///
/// Signals represent *what the code means*, not *what syntax it contains*.
/// They are derived after IR is complete, so the IR stays stable while
/// signal rules can be recalibrated independently.
///
/// Signals split into two tiers:
///
/// * **Capability** signals fire on the mere presence of an IR fact (eg a
///   `ProcessExec` node exists). They are cheap and have low specificity —
///   they say "this code *can* do X", not "this code *does* X maliciously".
/// * **Composite / taint** signals fire only when argument provenance
///   (`DataSource`) demonstrates attacker-controllable influence on a sink.
///   These are the high-specificity signals.
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
    /// An `eval` or `Function` whose argument *transitively derives from* a
    /// network response or a decoded payload. High specificity.
    RemoteCodeExecution,
    /// A `ProcessExec` whose argument *transitively derives from* a network
    /// response or a decoded payload. High specificity.
    RemoteExecChain,
    /// A `DynamicImport` whose specifier is not fully literal.
    DynamicLoaderPattern,
}

// ── Risk scoring (legacy helper kept for backward compat) ────────────────────
//
// The real composite scorer lives in `crate::scoring::compute_risk_score`
// (see the Scoring module). This `signal_weight` remains as a bucketed
// severity used by that scorer's positive-term calculation.

/// Severity weight for a single signal in [0.0, 1.0].
///
/// These weights feed the *positive* term of the composite score only. They
/// are **not** the final score — the composite formula adds negative
/// dampeners, a package-type adjustment, and an attacker-control gate.
pub fn signal_weight(s: &Signal) -> f32 {
    match s {
        Signal::RemoteCodeExecution   => 1.00,
        Signal::RemoteExecChain       => 0.95,
        Signal::DynamicLoaderPattern  => 0.75,
        Signal::ShellChainExecution   => 0.40, // capability only
        Signal::DynamicCodeEval       => 0.55,
        Signal::PostinstallExecution  => 0.35, // capability only
        Signal::EncodedPayloadDecode  => 0.60,
        Signal::ObfuscatedLoader      => 0.55,
        Signal::RemotePayloadFetch    => 0.25, // capability only
        Signal::FilesystemWrite       => 0.15, // capability only
        Signal::FilesystemRead        => 0.10, // capability only
    }
}

// ── Derivation ────────────────────────────────────────────────────────────────

/// Derive the set of signals present in this package's IR and behaviour graph.
pub fn derive_signals(ir_nodes: &[IrNode], graph: &BehaviorGraph) -> Vec<Signal> {
    let mut signals: HashSet<Signal> = HashSet::new();

    // IR-level capability signals (presence of node types)
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
                // Raw presence of an encoded string is a weak signal; we only
                // fire EncodedPayloadDecode when it is *chained into* an eval
                // (see derive_chain_signals). Keep the IR-level derivation
                // quiet here to avoid capability-only false positives.
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

    // Build a node lookup for chain-level analysis that needs full node data.
    let node_map: HashMap<&str, &IrNode> =
        ir_nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    // Chain-level signals (taint-aware, compositional patterns).
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
    node_map: &HashMap<&str, &IrNode>,
    signals: &mut HashSet<Signal>,
) {
    // Resolve chain steps to their underlying IrNodes for arg_source inspection.
    let nodes: Vec<&IrNode> = chain
        .chain
        .iter()
        .filter_map(|step| node_map.get(step.node_id.as_str()).copied())
        .collect();

    // High-specificity rule: sink's arg_source transitively proves the
    // value came from a network response or a decoded payload.
    let has_eval_with_remote = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::Eval { .. } | IrNodeKind::FunctionConstructor { .. })
            && n.kind
                .arg_source()
                .map(|ds| ds.derives_from_network() || ds.derives_from_decoded())
                .unwrap_or(false)
    });

    let has_eval_with_decoded = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::Eval { .. } | IrNodeKind::FunctionConstructor { .. })
            && n.kind
                .arg_source()
                .map(|ds| ds.derives_from_decoded())
                .unwrap_or(false)
    });

    let has_exec_with_remote = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::ProcessExec { .. })
            && n.kind
                .arg_source()
                .map(|ds| ds.derives_from_network() || ds.derives_from_decoded())
                .unwrap_or(false)
    });

    let has_exec_with_attacker_controlled = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::ProcessExec { .. })
            && n.kind
                .arg_source()
                .map(|ds| ds.is_attacker_controllable())
                .unwrap_or(false)
    });

    let has_dynamic_import_tainted = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::DynamicImport { .. })
            && n.kind
                .arg_source()
                .map(|ds| !ds.is_fully_literal())
                .unwrap_or(false)
    });

    // Weaker (but chain-scoped) rule: the new chain builder only co-locates
    // nodes that share a Function ancestor (or are at module scope in the
    // same file). So if a chain contains *both* a NetworkRequest and an
    // Eval, they already satisfy "shared ancestor Function" from the plan
    // — a reasonable proxy for event-driven data flow that 1-hop taint
    // can't see (e.g. `res.on('data', d => body += d); eval(body);`).
    //
    // This fallback is deliberately *only* applied per-chain, never
    // across the whole package, so it cannot re-introduce the old
    // cross-file co-occurrence false positives.
    let has_any_eval = nodes.iter().any(|n| {
        matches!(&n.kind, IrNodeKind::Eval { .. } | IrNodeKind::FunctionConstructor { .. })
    });
    let has_any_network = nodes
        .iter()
        .any(|n| matches!(&n.kind, IrNodeKind::NetworkRequest { .. }));
    let has_any_exec = nodes
        .iter()
        .any(|n| matches!(&n.kind, IrNodeKind::ProcessExec { .. }));

    if has_eval_with_remote || (has_any_eval && has_any_network) {
        signals.insert(Signal::RemoteCodeExecution);
        signals.insert(Signal::DynamicCodeEval);
    }

    if has_eval_with_decoded {
        signals.insert(Signal::EncodedPayloadDecode);
        signals.insert(Signal::DynamicCodeEval);
    }

    if has_exec_with_remote || (has_any_exec && has_any_network) {
        signals.insert(Signal::RemoteExecChain);
    }

    // Lifecycle-triggered shell exec with attacker-controllable args is the
    // classic malware pattern (postinstall that runs curl | sh equivalents).
    if chain.entry_point.script.is_some() && has_exec_with_attacker_controlled {
        signals.insert(Signal::RemoteExecChain);
    }

    if has_dynamic_import_tainted {
        signals.insert(Signal::DynamicLoaderPattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_exec_does_not_trigger_remote_exec_chain() {
        use vk_ir::{DataSource, IrNodeKind, SourceLocation};

        // Fabricate a ProcessExec with a literal arg — classic build tool pattern.
        let node = IrNode::new(
            IrNodeKind::ProcessExec {
                command: Some("node-gyp rebuild".into()),
                arg_source: DataSource::Literal { value: "node-gyp rebuild".into() },
            },
            SourceLocation { file: "x.js".into(), line: 1, col: 1 },
        );
        let chain = ExecutionChain {
            entry_point: crate::flow::EntryPointRef {
                kind: "install_script".into(),
                script: Some("postinstall".into()),
                path: Some("package.json".into()),
            },
            chain: vec![crate::flow::ChainStep {
                node_id: node.id.clone(),
                kind: "ProcessExec".into(),
                name: None,
                detail: Some("node-gyp rebuild".into()),
                file: "x.js".into(),
                line: 1,
                edge: crate::flow::ExecutionEdge::LifecycleTrigger,
            }],
            confidence: 1.0,
        };

        let mut map = HashMap::new();
        map.insert(node.id.as_str(), &node);

        let mut out = HashSet::new();
        derive_chain_signals(&chain, &map, &mut out);

        assert!(!out.contains(&Signal::RemoteExecChain));
        assert!(!out.contains(&Signal::RemoteCodeExecution));
    }

    #[test]
    fn network_to_eval_triggers_remote_code_execution() {
        use vk_ir::{DataSource, IrNodeKind, SourceLocation};

        let eval_node = IrNode::new(
            IrNodeKind::Eval {
                raw_arg: None,
                arg_source: DataSource::NetworkResponse { origin_node_id: None },
            },
            SourceLocation { file: "x.js".into(), line: 3, col: 1 },
        );
        let chain = ExecutionChain {
            entry_point: crate::flow::EntryPointRef {
                kind: "file".into(),
                script: None,
                path: Some("x.js".into()),
            },
            chain: vec![crate::flow::ChainStep {
                node_id: eval_node.id.clone(),
                kind: "Eval".into(),
                name: None,
                detail: None,
                file: "x.js".into(),
                line: 3,
                edge: crate::flow::ExecutionEdge::Direct,
            }],
            confidence: 1.0,
        };

        let mut map = HashMap::new();
        map.insert(eval_node.id.as_str(), &eval_node);

        let mut out = HashSet::new();
        derive_chain_signals(&chain, &map, &mut out);

        assert!(out.contains(&Signal::RemoteCodeExecution));
        assert!(out.contains(&Signal::DynamicCodeEval));
    }
}
