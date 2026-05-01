//! Attacker-control feature.
//!
//! Answers the single question the old scorer refused to ask:
//!
//! > *"Can an outsider influence the arguments this package hands to its
//! > sinks?"*
//!
//! If the answer is **no** (all sink arguments are literal, hardcoded paths,
//! or purely local constants), the composite scorer caps final risk *way*
//! below the high band — even for packages with `postinstall + exec + fs
//! write` capability stacks. This is what stops `node-gyp`-style rebuild
//! packages from lighting up at 0.85.
//!
//! The feature is a score in `[0.0, 1.0]` plus a structured evidence list
//! so downstream consumers (and the AI layer) can understand *why* it
//! scored the way it did.

use serde::{Deserialize, Serialize};
use vk_ir::{DataSource, IrNode, IrNodeKind};

use crate::flow::BehaviorGraph;

/// Aggregate attacker-control report for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerControlReport {
    /// Score in [0, 1] — the weight applied by the composite scorer's gate.
    pub score: f32,
    /// Human/ML-readable evidence for each contribution.
    pub evidence: Vec<AttackerControlEvidence>,
}

/// A single contribution to the attacker-control score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerControlEvidence {
    /// The node id responsible (sink with tainted argument).
    pub node_id: String,
    /// The sink kind ("ProcessExec", "Eval", ...).
    pub sink_kind: String,
    /// Why it contributes — a short category tag.
    pub reason: AttackerControlReason,
    /// The DataSource kind that triggered the contribution.
    pub data_source_kind: String,
    /// Contribution to the score.
    pub contribution: f32,
    pub file: String,
    pub line: u32,
}

/// Discrete categories used to explain a score contribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttackerControlReason {
    /// A sink reads a value that came directly from a `NetworkResponse`.
    NetworkInputToSink,
    /// A sink reads a value that came through a `Decoded` step (base64, hex).
    DecodedPayloadToSink,
    /// A sink reads a value that came from `process.env.X`.
    EnvVarInputToSink,
    /// A sink reads a value that came from `process.argv`.
    ArgvInputToSink,
    /// A sink reads a value that is a concatenation mixing literal + tainted.
    MixedConcatenationToSink,
    /// A `DynamicImport` whose specifier is not a static literal.
    DynamicImportTaintedSpecifier,
    /// A sink reads a value whose provenance is unresolved (`Unknown`).
    UnknownProvenanceToSink,
}

/// Compute the attacker-control feature for a whole package.
///
/// The algorithm is intentionally monotonic: each tainted sink contributes a
/// *capped* positive amount and contributions are combined as `1 - Π(1 - c_i)`
/// so more independent tainted sinks raise the score toward 1.0 without any
/// single one being able to exceed its ceiling.
pub fn compute_attacker_control(
    nodes: &[IrNode],
    _graph: &BehaviorGraph,
) -> AttackerControlReport {
    let mut evidence: Vec<AttackerControlEvidence> = Vec::new();

    for node in nodes {
        let Some(ds) = node.kind.arg_source() else { continue };
        let sink_kind = sink_kind_str(&node.kind);

        let contributions = analyse_source(ds, &node.kind);
        for (reason, data_source_kind, contribution) in contributions {
            evidence.push(AttackerControlEvidence {
                node_id: node.id.clone(),
                sink_kind: sink_kind.to_string(),
                reason,
                data_source_kind,
                contribution,
                file: node.location.file.clone(),
                line: node.location.line,
            });
        }
    }

    // Aggregate via independent-probabilities combination so multiple
    // moderate contributions lift the score without a single one dominating.
    let score = combine_independent(
        evidence.iter().map(|e| e.contribution.clamp(0.0, 1.0)).collect(),
    );

    // Stable evidence order
    evidence.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.node_id.cmp(&b.node_id))
    });

    AttackerControlReport { score, evidence }
}

/// Per-sink analysis: a tainted sink may contribute one or more rows.
fn analyse_source(
    ds: &DataSource,
    sink: &IrNodeKind,
) -> Vec<(AttackerControlReason, String, f32)> {
    let mut out = Vec::new();
    let is_exec_like = matches!(
        sink,
        IrNodeKind::ProcessExec { .. }
            | IrNodeKind::Eval { .. }
            | IrNodeKind::FunctionConstructor { .. }
    );
    let is_dynamic_import = matches!(sink, IrNodeKind::DynamicImport { .. });

    // Fully literal sources contribute nothing.
    if ds.is_fully_literal() {
        return out;
    }

    // Direct network/decoded taint is the strongest signal.
    if ds.derives_from_network() {
        out.push((
            AttackerControlReason::NetworkInputToSink,
            ds.kind_str().to_string(),
            if is_exec_like { 0.85 } else { 0.60 },
        ));
    }
    if ds.derives_from_decoded() {
        out.push((
            AttackerControlReason::DecodedPayloadToSink,
            "decoded".to_string(),
            if is_exec_like { 0.80 } else { 0.55 },
        ));
    }

    // Primary-variant classification for the rest.
    match ds {
        DataSource::EnvVar { name } => {
            // Env vars are moderate influence. A non-literal name (computed)
            // is a stronger signal because the attacker picks which env key.
            let base: f32 = if is_exec_like { 0.45 } else { 0.25 };
            let boost: f32 = if name.is_none() { 0.10 } else { 0.0 };
            out.push((
                AttackerControlReason::EnvVarInputToSink,
                "env_var".to_string(),
                (base + boost).min(1.0),
            ));
        }
        DataSource::ProcessArgv => {
            let contribution = if is_exec_like { 0.40 } else { 0.20 };
            out.push((
                AttackerControlReason::ArgvInputToSink,
                "process_argv".to_string(),
                contribution,
            ));
        }
        DataSource::Concatenation { sources } => {
            // Mixed concat (some literal, some tainted) is common in shell
            // commands built up with env vars — worth flagging.
            let has_tainted = sources.iter().any(|s| !s.is_fully_literal());
            let has_literal = sources.iter().any(|s| s.is_fully_literal());
            if has_tainted && has_literal {
                out.push((
                    AttackerControlReason::MixedConcatenationToSink,
                    "concatenation".to_string(),
                    if is_exec_like { 0.30 } else { 0.15 },
                ));
            }
        }
        DataSource::Unknown => {
            // Unknown provenance on an exec-like sink is worrying; on a
            // filesystem/network sink it's milder.
            let contribution = if is_exec_like { 0.25 } else { 0.10 };
            out.push((
                AttackerControlReason::UnknownProvenanceToSink,
                "unknown".to_string(),
                contribution,
            ));
        }
        DataSource::FunctionArg { .. } => {
            // Parameter — caller-dependent. Treat as low unknown.
            let contribution = if is_exec_like { 0.20 } else { 0.10 };
            out.push((
                AttackerControlReason::UnknownProvenanceToSink,
                "function_arg".to_string(),
                contribution,
            ));
        }
        DataSource::FileReadResult { .. } => {
            // Contents of a file on disk — marginally attacker-controllable
            // (depends on install context); worth flagging on exec sinks.
            let contribution = if is_exec_like { 0.30 } else { 0.15 };
            out.push((
                AttackerControlReason::UnknownProvenanceToSink,
                "file_read_result".to_string(),
                contribution,
            ));
        }
        DataSource::Literal { .. } | DataSource::TemplateOnly { .. } => {
            // No contribution — fully literal.
        }
        DataSource::NetworkResponse { .. } | DataSource::Decoded { .. } => {
            // Already accounted for by the top-level derives_from_* checks.
        }
    }

    // DynamicImport adds a small additional contribution if tainted.
    if is_dynamic_import && !ds.is_fully_literal() {
        out.push((
            AttackerControlReason::DynamicImportTaintedSpecifier,
            ds.kind_str().to_string(),
            0.25,
        ));
    }

    out
}

fn sink_kind_str(kind: &IrNodeKind) -> &'static str {
    match kind {
        IrNodeKind::ProcessExec { .. }         => "ProcessExec",
        IrNodeKind::NetworkRequest { .. }      => "NetworkRequest",
        IrNodeKind::FileRead { .. }            => "FileRead",
        IrNodeKind::FileWrite { .. }           => "FileWrite",
        IrNodeKind::Eval { .. }                => "Eval",
        IrNodeKind::DynamicImport { .. }       => "DynamicImport",
        IrNodeKind::FunctionConstructor { .. } => "FunctionConstructor",
        _ => "Other",
    }
}

/// Combine independent probability-like contributions: `1 - Π(1 - c_i)`.
fn combine_independent(contributions: Vec<f32>) -> f32 {
    let mut surviving = 1.0f32;
    for c in contributions {
        surviving *= 1.0 - c.clamp(0.0, 1.0);
    }
    (1.0 - surviving).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_ir::{IrNode, IrNodeKind, SourceLocation, SCHEMA_VERSION};

    fn mk_graph() -> BehaviorGraph {
        BehaviorGraph {
            schema_version: SCHEMA_VERSION.to_string(),
            execution_chains: vec![],
            edges: vec![],
        }
    }

    #[test]
    fn literal_exec_yields_zero() {
        let node = IrNode::new(
            IrNodeKind::ProcessExec {
                command: Some("node-gyp rebuild".into()),
                arg_source: DataSource::Literal {
                    value: "node-gyp rebuild".into(),
                },
            },
            SourceLocation {
                file: "a.js".into(),
                line: 1,
                col: 1,
            },
        );
        let g = mk_graph();
        let r = compute_attacker_control(&[node], &g);
        assert_eq!(r.score, 0.0);
        assert!(r.evidence.is_empty());
    }

    #[test]
    fn decoded_to_exec_lifts_score() {
        let node = IrNode::new(
            IrNodeKind::ProcessExec {
                command: None,
                arg_source: DataSource::Decoded {
                    origin_node_id: None,
                    encoding: "base64".into(),
                },
            },
            SourceLocation {
                file: "a.js".into(),
                line: 1,
                col: 1,
            },
        );
        let g = mk_graph();
        let r = compute_attacker_control(&[node], &g);
        assert!(r.score > 0.7, "expected > 0.7, got {}", r.score);
    }

    #[test]
    fn env_var_to_exec_is_moderate() {
        let node = IrNode::new(
            IrNodeKind::ProcessExec {
                command: None,
                arg_source: DataSource::EnvVar {
                    name: Some("PAYLOAD".into()),
                },
            },
            SourceLocation {
                file: "a.js".into(),
                line: 1,
                col: 1,
            },
        );
        let g = mk_graph();
        let r = compute_attacker_control(&[node], &g);
        assert!(r.score > 0.3 && r.score < 0.6, "score={}", r.score);
    }
}
