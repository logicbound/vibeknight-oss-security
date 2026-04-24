use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use vk_ir::{IrNode, IrNodeKind, NodeTag, SCHEMA_VERSION};

use crate::callgraph::CallGraph;

// ── Execution edge semantics ──────────────────────────────────────────────────

/// The nature of a connection between two nodes in an execution chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEdge {
    /// A synchronous, direct function call.
    Direct,
    /// Inside a conditional branch (if/switch/ternary).
    Conditional,
    /// Deferred execution (setTimeout, setInterval, Promise.then/catch).
    Deferred,
    /// Event-driven execution (process.on, EventEmitter.on, addEventListener).
    EventDriven,
}

// ── Graph edges ───────────────────────────────────────────────────────────────

/// An explicit directed edge in the behavior graph — suitable for downstream
/// graph consumers (ML, visualization, rule engines).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub edge_type: ExecutionEdge,
}

// ── Behaviour graph ───────────────────────────────────────────────────────────

/// A single step in an execution chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub node_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub file: String,
    pub line: u32,
    pub edge: ExecutionEdge,
}

/// One execution chain rooted at an entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionChain {
    pub entry_point: EntryPointRef,
    pub chain: Vec<ChainStep>,
    /// Confidence score in [0.0, 1.0] — product of per-node factors.
    /// Degraded by obfuscation, dynamic arguments, and dynamic imports.
    pub confidence: f32,
}

/// Lightweight reference to the entry point that anchors a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointRef {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// The `behavior_graph.json` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorGraph {
    pub schema_version: String,
    pub execution_chains: Vec<ExecutionChain>,
    /// Explicit edge list for downstream graph consumers.
    pub edges: Vec<GraphEdge>,
}

// ── Builder ───────────────────────────────────────────────────────────────────

pub fn build_behavior_graph(nodes: &[IrNode], call_graph: &CallGraph) -> BehaviorGraph {
    // Index nodes by id for fast lookup
    let by_id: HashMap<&str, &IrNode> = nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let entry_points: Vec<&IrNode> = nodes
        .iter()
        .filter(|n| matches!(&n.kind, IrNodeKind::EntryPoint { .. }))
        .collect();

    let mut chains = Vec::new();
    let mut all_edges: Vec<GraphEdge> = Vec::new();

    for ep in entry_points {
        let ep_ref = entry_point_ref(ep);
        let mut visited = HashSet::new();
        let mut chain_steps = Vec::new();

        // Emit the entry point itself
        chain_steps.push(node_to_step(ep, ExecutionEdge::Direct));

        trace_from(
            ep,
            nodes,
            call_graph,
            &by_id,
            &mut chain_steps,
            &mut all_edges,
            &mut visited,
            0,
        );

        if chain_steps.len() > 1 {
            let confidence = compute_confidence(&chain_steps, nodes);
            chains.push(ExecutionChain {
                entry_point: ep_ref,
                chain: chain_steps,
                confidence,
            });
        }
    }

    // If there are no explicit EntryPoint nodes but there are interesting sinks,
    // produce a single "implicit" chain from the first function node.
    if chains.is_empty() {
        let first_fn = nodes.iter().find(|n| matches!(&n.kind, IrNodeKind::Function { .. }));
        if let Some(fn_node) = first_fn {
            let ep_ref = EntryPointRef {
                kind: "implicit".to_string(),
                script: None,
                path: Some(fn_node.location.file.clone()),
            };
            let mut visited = HashSet::new();
            let mut steps = Vec::new();
            trace_from(fn_node, nodes, call_graph, &by_id, &mut steps, &mut all_edges, &mut visited, 0);
            if !steps.is_empty() {
                let confidence = compute_confidence(&steps, nodes);
                chains.push(ExecutionChain {
                    entry_point: ep_ref,
                    chain: steps,
                    confidence,
                });
            }
        }
    }

    // Normalise output — stable ordering for deterministic diffs
    chains.sort_by(|a, b| {
        let pa = a.entry_point.path.as_deref().unwrap_or("");
        let pb = b.entry_point.path.as_deref().unwrap_or("");
        pa.cmp(pb)
            .then(a.entry_point.script.as_deref().unwrap_or("").cmp(
                b.entry_point.script.as_deref().unwrap_or(""),
            ))
    });
    all_edges.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));

    BehaviorGraph {
        schema_version: SCHEMA_VERSION.to_string(),
        execution_chains: chains,
        edges: all_edges,
    }
}

// ── DFS tracer ────────────────────────────────────────────────────────────────

const MAX_DEPTH: usize = 20;

fn trace_from<'a>(
    node: &'a IrNode,
    all_nodes: &'a [IrNode],
    call_graph: &CallGraph,
    by_id: &HashMap<&str, &'a IrNode>,
    steps: &mut Vec<ChainStep>,
    edges: &mut Vec<GraphEdge>,
    visited: &mut HashSet<String>,
    depth: usize,
) {
    if depth > MAX_DEPTH || visited.contains(&node.id) {
        return;
    }
    visited.insert(node.id.clone());

    let file = &node.location.file;
    let start_line = node.location.line;
    let prev_id = node.id.clone();

    for candidate in all_nodes {
        if &candidate.location.file != file { continue; }
        if candidate.location.line <= start_line { continue; }
        if visited.contains(&candidate.id) { continue; }

        let edge_type = classify_edge(candidate);
        if is_interesting(&candidate.kind) {
            steps.push(node_to_step(candidate, edge_type.clone()));
            edges.push(GraphEdge {
                from: prev_id.clone(),
                to: candidate.id.clone(),
                edge_type,
            });
            visited.insert(candidate.id.clone());
        }

        // Follow calls into called functions
        if let IrNodeKind::Call { callee } = &candidate.kind {
            let callees_of = call_graph.callees_of(callee);
            for callee_name in callees_of {
                if let Some(&callee_node) = by_id.get(callee_name.as_str()) {
                    trace_from(callee_node, all_nodes, call_graph, by_id, steps, edges, visited, depth + 1);
                }
            }
        }
    }
}

fn is_interesting(kind: &IrNodeKind) -> bool {
    matches!(
        kind,
        IrNodeKind::ProcessExec { .. }
            | IrNodeKind::NetworkRequest { .. }
            | IrNodeKind::FileRead { .. }
            | IrNodeKind::FileWrite { .. }
            | IrNodeKind::Eval { .. }
            | IrNodeKind::DynamicImport { .. }
            | IrNodeKind::FunctionConstructor { .. }
            | IrNodeKind::EncodedString { .. }
            | IrNodeKind::ObfuscatedFlow
    )
}

fn classify_edge(node: &IrNode) -> ExecutionEdge {
    // Check node tags for deferred/event-driven patterns
    // (future: derive from surrounding context; for now Direct is the safe default)
    let _ = node;
    ExecutionEdge::Direct
}

fn node_to_step(node: &IrNode, edge: ExecutionEdge) -> ChainStep {
    let (kind_str, name, detail) = describe_node(node);
    ChainStep {
        node_id: node.id.clone(),
        kind: kind_str,
        name,
        detail,
        file: node.location.file.clone(),
        line: node.location.line,
        edge,
    }
}

fn describe_node(node: &IrNode) -> (String, Option<String>, Option<String>) {
    match &node.kind {
        IrNodeKind::EntryPoint { script }     => ("EntryPoint".into(), script.clone(), None),
        IrNodeKind::Function { name }         => ("Function".into(), name.clone(), None),
        IrNodeKind::Call { callee }           => ("Call".into(), Some(callee.clone()), None),
        IrNodeKind::ProcessExec { command }   => ("ProcessExec".into(), None, command.clone()),
        IrNodeKind::FileRead { path }         => ("FileRead".into(), None, path.clone()),
        IrNodeKind::FileWrite { path }        => ("FileWrite".into(), None, path.clone()),
        IrNodeKind::NetworkRequest { url }    => ("NetworkRequest".into(), None, url.clone()),
        IrNodeKind::Eval { raw_arg }          => ("Eval".into(), None, raw_arg.clone()),
        IrNodeKind::DynamicImport { specifier } => ("DynamicImport".into(), None, specifier.clone()),
        IrNodeKind::FunctionConstructor { body } => ("FunctionConstructor".into(), None, body.clone()),
        IrNodeKind::EncodedString { encoding, value } => (
            "EncodedString".into(),
            Some(encoding.clone()),
            Some(value.clone()),
        ),
        IrNodeKind::ObfuscatedFlow => ("ObfuscatedFlow".into(), None, None),
    }
}

fn entry_point_ref(node: &IrNode) -> EntryPointRef {
    match &node.kind {
        IrNodeKind::EntryPoint { script } => EntryPointRef {
            kind: "install_script".to_string(),
            script: script.clone(),
            path: Some(node.location.file.clone()),
        },
        _ => EntryPointRef {
            kind: "file".to_string(),
            script: None,
            path: Some(node.location.file.clone()),
        },
    }
}

// ── Confidence scoring ────────────────────────────────────────────────────────

/// Compute chain confidence as a product of per-node degradation factors.
///
/// | Condition                          | Factor |
/// |------------------------------------|--------|
/// | `ObfuscatedFlow` node              |  ×0.70 |
/// | `DynamicArg` tag on a sink node    |  ×0.85 |
/// | `DynamicImport` node               |  ×0.80 |
/// | `ObfuscatedContext` tag            |  ×0.75 |
/// | Minimum clamp                      |   0.10 |
fn compute_confidence(steps: &[ChainStep], all_nodes: &[IrNode]) -> f32 {
    // Build a quick lookup for node by id
    let by_id: HashMap<&str, &IrNode> = all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut confidence: f32 = 1.0;

    for step in steps {
        let Some(node) = by_id.get(step.node_id.as_str()) else { continue };

        match &node.kind {
            IrNodeKind::ObfuscatedFlow => {
                confidence *= 0.70;
            }
            IrNodeKind::DynamicImport { .. } => {
                confidence *= 0.80;
            }
            _ => {}
        }

        for tag in &node.tags {
            match tag {
                NodeTag::DynamicArg => {
                    // Only degrade on "sink" nodes, not on every dynamic arg
                    if is_interesting(&node.kind) {
                        confidence *= 0.85;
                    }
                }
                NodeTag::ObfuscatedContext => {
                    confidence *= 0.75;
                }
                _ => {}
            }
        }
    }

    confidence.max(0.10)
}
