//! Composite risk scoring.
//!
//! Replaces the previous `max(signal_weight) + chain_conf*0.15` formula,
//! which produced ~0.85 scores for any build-tool package and was the
//! root cause of the high-risk false-positive problem.
//!
//! The new formula:
//!
//! ```text
//! positive     = sum(signal_weights, clamped to 1.5)
//! negative     = sum(benign-pattern dampeners)
//!              + static-args reward
//!              + no-network reward
//!              + no-obfuscation reward
//! type_adjust  = DevTool:  -0.30
//!                Cli:      -0.15
//!                RuntimeLib: 0.00
//!                Unknown:    0.00
//!
//! raw          = clamp(positive - negative + type_adjust, 0, 1)
//! final        = raw * (0.25 + 0.75 * attacker_control)  // GATE
//! ```
//!
//! The **gate** is the critical part: a package with zero external-influence
//! signals caps at 25% of its raw capability score. `node-gyp rebuild` style
//! packages — which typically produce zero attacker-controllable sinks —
//! therefore land near 0.15–0.25 even with the full capability stack.

use serde::{Deserialize, Serialize};
use vk_ir::{DataSource, IrNode, IrNodeKind};

use crate::benign_patterns::BenignMatch;
use crate::flow::ExecutionChain;
use crate::package_type::PackageClass;
use crate::signals::{signal_weight, Signal};

// ── Feature vector ────────────────────────────────────────────────────────────

/// Raw feature counts emitted alongside the score for the downstream AI layer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureVector {
    /// Counts per sink kind: {"ProcessExec": 2, "NetworkRequest": 0, ...}
    pub sink_counts: std::collections::BTreeMap<String, u32>,
    /// Counts per `DataSource` kind across all sinks.
    pub data_source_counts: std::collections::BTreeMap<String, u32>,
    /// Number of sinks with fully-literal provenance.
    pub literal_sink_count: u32,
    /// Number of sinks with attacker-controllable provenance.
    pub attacker_controllable_sink_count: u32,
    /// Number of chains whose entry is an install lifecycle script.
    pub install_chain_count: u32,
    /// Number of chains whose entry is a file-level (non-lifecycle) entry.
    pub file_chain_count: u32,
}

pub fn build_feature_vector(nodes: &[IrNode], chains: &[ExecutionChain]) -> FeatureVector {
    let mut fv = FeatureVector::default();

    for node in nodes {
        let sink_kind = match &node.kind {
            IrNodeKind::ProcessExec { .. }         => Some("ProcessExec"),
            IrNodeKind::NetworkRequest { .. }      => Some("NetworkRequest"),
            IrNodeKind::FileRead { .. }            => Some("FileRead"),
            IrNodeKind::FileWrite { .. }           => Some("FileWrite"),
            IrNodeKind::Eval { .. }                => Some("Eval"),
            IrNodeKind::DynamicImport { .. }       => Some("DynamicImport"),
            IrNodeKind::FunctionConstructor { .. } => Some("FunctionConstructor"),
            IrNodeKind::EncodedString { .. }       => Some("EncodedString"),
            _ => None,
        };
        if let Some(k) = sink_kind {
            *fv.sink_counts.entry(k.to_string()).or_insert(0) += 1;
        }

        if let Some(ds) = node.kind.arg_source() {
            *fv.data_source_counts
                .entry(ds.kind_str().to_string())
                .or_insert(0) += 1;
            if ds.is_fully_literal() {
                fv.literal_sink_count += 1;
            } else if ds.is_attacker_controllable() {
                fv.attacker_controllable_sink_count += 1;
            }
        }
    }

    for chain in chains {
        if chain.entry_point.script.is_some() {
            fv.install_chain_count += 1;
        } else {
            fv.file_chain_count += 1;
        }
    }

    fv
}

// ── Composite score ───────────────────────────────────────────────────────────

/// Inputs the composite scorer reads. Grouped to keep the public signature
/// readable and stable as additional features are added.
#[derive(Debug, Clone)]
pub struct ScoreInputs<'a> {
    pub signals: &'a [Signal],
    pub chains: &'a [ExecutionChain],
    pub nodes: &'a [IrNode],
    pub attacker_control: f32,
    pub package_class: &'a PackageClass,
    pub benign_matches: &'a [BenignMatch],
}

/// A score + breakdown for debuggability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub positive: f32,
    pub negative: f32,
    pub type_adjust: f32,
    pub raw: f32,
    pub gate_multiplier: f32,
    pub final_score: f32,
}

/// Compute the composite risk score in [0, 1].
///
/// Returns both the score and a structured breakdown so the downstream AI
/// layer (and humans) can see every contribution.
pub fn compute_risk_score(inputs: &ScoreInputs<'_>) -> ScoreBreakdown {
    // ── Positive term — signal severity (capped) ────────────────────────────
    let positive: f32 = inputs
        .signals
        .iter()
        .map(signal_weight)
        .sum::<f32>()
        .min(1.5);

    // ── Negative term — dampeners ───────────────────────────────────────────
    let benign_dampener = (inputs.benign_matches.len() as f32 * 0.15).min(0.60);
    let literal_args_bonus = if all_exec_args_literal(inputs.nodes) { 0.25 } else { 0.0 };
    let no_network_bonus = if no_network_signal(inputs.signals) { 0.20 } else { 0.0 };
    let no_obfuscation_bonus = if no_obfuscation(inputs.signals, inputs.nodes) { 0.15 } else { 0.0 };

    let negative = benign_dampener + literal_args_bonus + no_network_bonus + no_obfuscation_bonus;

    // ── Package-type adjustment ─────────────────────────────────────────────
    let type_adjust = match inputs.package_class {
        PackageClass::DevTool    => -0.30,
        PackageClass::Cli        => -0.15,
        PackageClass::RuntimeLib =>  0.00,
        PackageClass::Unknown    =>  0.00,
    };

    let raw = (positive - negative + type_adjust).clamp(0.0, 1.0);

    // ── Attacker-control gate ───────────────────────────────────────────────
    // With zero attacker-control, score caps at 25% of raw — this is the fix
    // for the "postinstall+exec+fs=0.85" problem.
    let gate = 0.25 + 0.75 * inputs.attacker_control.clamp(0.0, 1.0);
    let final_score = (raw * gate).clamp(0.0, 1.0);

    ScoreBreakdown {
        positive,
        negative,
        type_adjust,
        raw,
        gate_multiplier: gate,
        final_score,
    }
}

// ── Helpers for the negative term ─────────────────────────────────────────────

/// True if every `ProcessExec` in the package has a fully-literal argument.
fn all_exec_args_literal(nodes: &[IrNode]) -> bool {
    let mut saw_exec = false;
    for n in nodes {
        if let IrNodeKind::ProcessExec { arg_source, .. } = &n.kind {
            saw_exec = true;
            if !arg_source.is_fully_literal() {
                return false;
            }
        }
    }
    saw_exec // only award bonus if there is at least one exec to vouch for
}

fn no_network_signal(signals: &[Signal]) -> bool {
    !signals.iter().any(|s| matches!(
        s,
        Signal::RemotePayloadFetch
            | Signal::RemoteCodeExecution
            | Signal::RemoteExecChain,
    ))
}

fn no_obfuscation(signals: &[Signal], nodes: &[IrNode]) -> bool {
    if signals.iter().any(|s| matches!(s, Signal::ObfuscatedLoader | Signal::DynamicLoaderPattern)) {
        return false;
    }
    let has_decoded = nodes.iter().any(|n| match &n.kind {
        IrNodeKind::EncodedString { .. } => true,
        _ => matches!(
            n.kind.arg_source(),
            Some(DataSource::Decoded { .. })
        ) || n
            .kind
            .arg_source()
            .map(|ds| ds.derives_from_decoded())
            .unwrap_or(false),
    });
    !has_decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_ir::SourceLocation;

    fn mk_exec(ds: DataSource) -> IrNode {
        IrNode::new(
            IrNodeKind::ProcessExec {
                command: None,
                arg_source: ds,
            },
            SourceLocation { file: "a.js".into(), line: 1, col: 1 },
        )
    }

    #[test]
    fn devtool_with_literal_args_scores_low() {
        let nodes = vec![mk_exec(DataSource::Literal { value: "node-gyp rebuild".into() })];
        let chains = vec![];
        let signals = vec![
            Signal::PostinstallExecution,
            Signal::ShellChainExecution,
            Signal::FilesystemWrite,
        ];
        let benign = vec![BenignMatch {
            node_id: nodes[0].id.clone(),
            category: "native_rebuild".into(),
            description: "node-gyp".into(),
            matched_command: "node-gyp rebuild".into(),
            file: "a.js".into(),
            line: 1,
        }];
        let inputs = ScoreInputs {
            signals: &signals,
            chains: &chains,
            nodes: &nodes,
            attacker_control: 0.0,
            package_class: &PackageClass::DevTool,
            benign_matches: &benign,
        };
        let b = compute_risk_score(&inputs);
        assert!(b.final_score <= 0.35, "expected <= 0.35, got {}", b.final_score);
    }

    #[test]
    fn runtime_malware_scores_high() {
        let nodes = vec![
            IrNode::new(
                IrNodeKind::Eval {
                    raw_arg: None,
                    arg_source: DataSource::Decoded {
                        origin_node_id: None,
                        encoding: "base64".into(),
                    },
                },
                SourceLocation { file: "a.js".into(), line: 1, col: 1 },
            ),
            IrNode::new(
                IrNodeKind::NetworkRequest {
                    url: Some("https://evil".into()),
                    arg_source: DataSource::Literal { value: "https://evil".into() },
                },
                SourceLocation { file: "a.js".into(), line: 2, col: 1 },
            ),
        ];
        let signals = vec![
            Signal::RemoteCodeExecution,
            Signal::EncodedPayloadDecode,
            Signal::DynamicCodeEval,
            Signal::RemotePayloadFetch,
        ];
        let inputs = ScoreInputs {
            signals: &signals,
            chains: &[],
            nodes: &nodes,
            attacker_control: 0.85,
            package_class: &PackageClass::RuntimeLib,
            benign_matches: &[],
        };
        let b = compute_risk_score(&inputs);
        assert!(b.final_score >= 0.75, "expected >= 0.75, got {}", b.final_score);
    }
}
