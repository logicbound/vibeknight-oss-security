pub mod attacker_control;
pub mod benign_patterns;
pub mod callgraph;
pub mod finding;
pub mod flow;
pub mod package_type;
pub mod scoring;
pub mod signals;

use std::collections::HashSet;

use vk_ir::{ExecutionContext, ExecutionPhase, IrNode, IrNodeKind, SourceLocation, SCHEMA_VERSION};
use vk_lang_js::analyse_file;
use vk_npm::PackageGraph;

pub use finding::{build_finding, Evidence, Finding};
pub use flow::BehaviorGraph;
pub use signals::Signal;

// ── Output artifacts ──────────────────────────────────────────────────────────

/// The `ir_graph.json` artifact — all IR nodes across all files.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IrGraph {
    pub schema_version: String,
    pub nodes: Vec<IrNode>,
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Run the full analysis pipeline on an already-ingested package.
///
/// Steps:
/// 1. Analyse each JS/TS file in the package → emit IR nodes
/// 2. Inject EntryPoint nodes from the package graph
/// 3. Build call graph
/// 4. Build behaviour graph (execution chains)
/// 5. Post-pass: propagate ExecutionContext.phase for install-script entry points
/// 6. Derive signals
/// 7. Classify package (DevTool / CLI / RuntimeLib)
/// 8. Compute attacker-control feature
/// 9. Collect benign-pattern matches
/// 10. Build feature vector
/// 11. Compose composite risk score
/// 12. Assemble Finding
pub fn analyse(package: &PackageGraph) -> (IrGraph, BehaviorGraph, Finding) {
    // ── Stage 1+2: AST → IR ───────────────────────────────────────────────────
    let mut all_nodes: Vec<IrNode> = Vec::new();

    for file_rel in &package.files {
        let abs = package.extracted_dir.join(file_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        let Ok(source) = std::fs::read_to_string(&abs) else { continue };
        let file_ir = analyse_file(&source, file_rel);
        all_nodes.extend(file_ir.nodes);
    }

    // Inject EntryPoint nodes from the package manifest
    for ep in &package.entry_points {
        match ep {
            vk_npm::EntryPoint::InstallScript { script, command: _ } => {
                let loc = SourceLocation {
                    file: "package.json".to_string(),
                    line: 0,
                    col: 0,
                };
                all_nodes.push(IrNode::new(
                    IrNodeKind::EntryPoint { script: Some(script.clone()) },
                    loc,
                ));
            }
            vk_npm::EntryPoint::File { path } => {
                let loc = SourceLocation {
                    file: path.clone(),
                    line: 1,
                    col: 0,
                };
                all_nodes.push(IrNode::new(
                    IrNodeKind::EntryPoint { script: None },
                    loc,
                ));
            }
        }
    }

    // ── Stage 3: Call graph ───────────────────────────────────────────────────
    let call_graph = callgraph::CallGraph::build(&all_nodes);

    // ── Stage 4: Flow linking ─────────────────────────────────────────────────
    let behavior_graph = flow::build_behavior_graph(&all_nodes, &call_graph);

    // ── Stage 5: ExecutionContext propagation ─────────────────────────────────
    let install_node_ids = collect_install_node_ids(&behavior_graph);
    for node in &mut all_nodes {
        if let Some((phase, entry_point)) = install_node_ids.get(&node.id) {
            node.context = ExecutionContext {
                phase: phase.clone(),
                entry_point: Some(entry_point.clone()),
            };
        }
    }

    // ── Stage 6: Output normalisation ─────────────────────────────────────────
    all_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let ir_graph = IrGraph {
        schema_version: SCHEMA_VERSION.to_string(),
        nodes: all_nodes.clone(),
    };

    // ── Stage 7: Signal derivation ────────────────────────────────────────────
    let signals_vec = signals::derive_signals(&all_nodes, &behavior_graph);

    // ── Stage 8: Package classification ───────────────────────────────────────
    let manifest_for_class = if package.manifest.is_null() {
        None
    } else {
        Some(&package.manifest)
    };
    let classification = package_type::classify_package(manifest_for_class, &all_nodes);

    // ── Stage 9: Attacker-control feature ─────────────────────────────────────
    let attacker_control = attacker_control::compute_attacker_control(&all_nodes, &behavior_graph);

    // ── Stage 10: Benign-pattern matches ──────────────────────────────────────
    let benign_matches = benign_patterns::collect_benign_matches(&all_nodes);

    // ── Stage 11: Feature vector ──────────────────────────────────────────────
    let features = scoring::build_feature_vector(&all_nodes, &behavior_graph.execution_chains);

    // ── Stage 12: Composite score ─────────────────────────────────────────────
    let score = scoring::compute_risk_score(&scoring::ScoreInputs {
        signals: &signals_vec,
        chains: &behavior_graph.execution_chains,
        nodes: &all_nodes,
        attacker_control: attacker_control.score,
        package_class: &classification.class,
        benign_matches: &benign_matches,
    });

    // ── Stage 13: Evidence extraction ─────────────────────────────────────────
    let evidence: Vec<Evidence> = all_nodes
        .iter()
        .filter(|n| is_evidence_node(n))
        .map(|n| Evidence {
            kind: kind_tag_str(&n.kind).to_string(),
            detail: extract_detail(&n.kind),
            file: n.location.file.clone(),
            line: n.location.line,
        })
        .collect();

    let finding = build_finding(
        package.package.clone(),
        package.version.clone(),
        package.integrity_hash.clone(),
        signals_vec,
        behavior_graph.execution_chains.clone(),
        evidence,
        classification,
        attacker_control,
        benign_matches,
        features,
        score,
    );

    (ir_graph, behavior_graph, finding)
}

// ── ExecutionContext propagation ──────────────────────────────────────────────

/// Collect the IDs of all nodes that appear in chains rooted at install-script
/// entry points. Returns a map: node_id → (ExecutionPhase, script_name).
fn collect_install_node_ids(
    behavior_graph: &flow::BehaviorGraph,
) -> std::collections::HashMap<String, (ExecutionPhase, String)> {
    let mut result = std::collections::HashMap::new();

    for chain in &behavior_graph.execution_chains {
        let Some(script_name) = &chain.entry_point.script else { continue };
        for step in &chain.chain {
            result.entry(step.node_id.clone()).or_insert_with(|| {
                (ExecutionPhase::Install, script_name.clone())
            });
        }
    }

    result
}

// ── Collect node IDs reachable from entry points ──────────────────────────────

/// Collect all node IDs that appear across all chains (for graph walking).
#[allow(dead_code)]
fn collect_reachable_ids(behavior_graph: &flow::BehaviorGraph) -> HashSet<String> {
    behavior_graph
        .execution_chains
        .iter()
        .flat_map(|c| c.chain.iter().map(|s| s.node_id.clone()))
        .collect()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn is_evidence_node(node: &IrNode) -> bool {
    matches!(
        &node.kind,
        IrNodeKind::ProcessExec { .. }
            | IrNodeKind::NetworkRequest { .. }
            | IrNodeKind::Eval { .. }
            | IrNodeKind::FunctionConstructor { .. }
            | IrNodeKind::EncodedString { .. }
            | IrNodeKind::ObfuscatedFlow
    )
}

fn kind_tag_str(kind: &IrNodeKind) -> &'static str {
    match kind {
        IrNodeKind::EntryPoint { .. }          => "EntryPoint",
        IrNodeKind::Function { .. }            => "Function",
        IrNodeKind::Call { .. }                => "Call",
        IrNodeKind::ProcessExec { .. }         => "ProcessExec",
        IrNodeKind::FileRead { .. }            => "FileRead",
        IrNodeKind::FileWrite { .. }           => "FileWrite",
        IrNodeKind::NetworkRequest { .. }      => "NetworkRequest",
        IrNodeKind::Eval { .. }                => "Eval",
        IrNodeKind::DynamicImport { .. }       => "DynamicImport",
        IrNodeKind::FunctionConstructor { .. } => "FunctionConstructor",
        IrNodeKind::EncodedString { .. }       => "EncodedString",
        IrNodeKind::ObfuscatedFlow             => "ObfuscatedFlow",
    }
}

fn extract_detail(kind: &IrNodeKind) -> Option<String> {
    match kind {
        IrNodeKind::ProcessExec { command, .. }       => command.clone(),
        IrNodeKind::NetworkRequest { url, .. }        => url.clone(),
        IrNodeKind::Eval { raw_arg, .. }              => raw_arg.clone(),
        IrNodeKind::FunctionConstructor { body, .. } => body.clone(),
        IrNodeKind::EncodedString { value, .. }       => Some(value.clone()),
        _ => None,
    }
}
