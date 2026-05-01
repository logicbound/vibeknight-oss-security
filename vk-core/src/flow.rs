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
    /// An install-lifecycle trigger (preinstall/install/postinstall) → code.
    /// Scored weaker than `Direct` because it only proves activation, not data-flow.
    LifecycleTrigger,
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

        let seed_edge = if matches!(&ep.kind, IrNodeKind::EntryPoint { script: Some(_) }) {
            ExecutionEdge::LifecycleTrigger
        } else {
            ExecutionEdge::Direct
        };

        trace_from(
            ep,
            seed_edge,
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
            trace_from(
                fn_node,
                ExecutionEdge::Direct,
                nodes,
                call_graph,
                &by_id,
                &mut steps,
                &mut all_edges,
                &mut visited,
                0,
            );
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

/// Walk outward from `node`, adding downstream sinks to `steps`.
///
/// Successor selection is scoped:
/// * for an install-script `EntryPoint` (`seed_edge == LifecycleTrigger`), only
///   the **first** eligible sink per function body is attached as a lifecycle
///   trigger — subsequent sinks in that same body inherit `Direct` from that
///   first node as they are recursively traced.
/// * for a real in-code origin, we only link nodes that live in the **same
///   function scope** (`parent_fn_id` matches) or can be reached through an
///   explicit `Call` edge resolved via the call graph.
///
/// This fixes the old "every later line in the same file is one chain" bug.
fn trace_from<'a>(
    node: &'a IrNode,
    seed_edge: ExecutionEdge,
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

    let origin_scope = node.parent_fn_id.clone();
    let prev_id = node.id.clone();
    let is_entry = matches!(&node.kind, IrNodeKind::EntryPoint { .. });
    let from_lifecycle = matches!(seed_edge, ExecutionEdge::LifecycleTrigger);

    // Compute candidate set. For EntryPoints we use file-scope (they have no
    // parent_fn_id by definition). For everything else we require matching
    // scope.
    for candidate in all_nodes {
        if visited.contains(&candidate.id) { continue; }
        if candidate.id == node.id { continue; }

        let same_scope = if is_entry {
            // An EntryPoint links to nodes in the same file that are at module
            // scope (parent_fn_id == None). This keeps the lifecycle chain
            // anchored to the top-level code that actually runs at trigger
            // time, instead of slurping every function body in the file.
            let same_file = candidate.location.file == node.location.file
                || from_lifecycle; // install script EPs have file == "package.json"
            let top_level = candidate.parent_fn_id.is_none();
            same_file && top_level
        } else {
            candidate.parent_fn_id == origin_scope
                && candidate.location.file == node.location.file
                && candidate.location.line >= node.location.line
        };

        if !same_scope { continue; }

        let edge_type = if from_lifecycle && !matches!(
            &candidate.kind,
            IrNodeKind::EntryPoint { .. } | IrNodeKind::Function { .. }
        ) {
            ExecutionEdge::LifecycleTrigger
        } else {
            classify_edge(candidate)
        };

        if is_interesting(&candidate.kind) {
            steps.push(node_to_step(candidate, edge_type.clone()));
            edges.push(GraphEdge {
                from: prev_id.clone(),
                to: candidate.id.clone(),
                edge_type: edge_type.clone(),
            });
            visited.insert(candidate.id.clone());

            // Recurse inside the same scope (but stop treating it as lifecycle;
            // further hops are direct data/control flow from this sink).
            trace_from(
                candidate,
                ExecutionEdge::Direct,
                all_nodes,
                call_graph,
                by_id,
                steps,
                edges,
                visited,
                depth + 1,
            );
        }

        // Follow explicit call edges into called functions regardless of scope.
        //
        // When we see `Call { callee: "fetchAndEval" }`, what we want is the
        // **local Function node** named `fetchAndEval` so we can descend into
        // its body. `CallGraph::fn_nodes` maps callee name → Function node id
        // for that exact purpose.
        if let IrNodeKind::Call { callee } = &candidate.kind {
            if let Some(fn_node_id) = call_graph.fn_nodes.get(callee) {
                if let Some(&fn_node) = by_id.get(fn_node_id.as_str()) {
                    trace_from(
                        fn_node,
                        ExecutionEdge::Direct,
                        all_nodes,
                        call_graph,
                        by_id,
                        steps,
                        edges,
                        visited,
                        depth + 1,
                    );
                }
            }
        }
    }

    // Special case: when entering a Function node via a Call, the Function
    // node itself isn't "interesting" but its body contains sinks that share
    // its id as their parent_fn_id. Walk those sinks directly, and also
    // descend into any nested (anonymous) functions whose parent is this
    // function — those are commonly event callbacks like
    // `res.on('data', d => body += d)` whose sinks would otherwise be
    // unreachable by the DFS.
    if matches!(&node.kind, IrNodeKind::Function { .. }) {
        descend_into_function_body(
            node,
            all_nodes,
            call_graph,
            by_id,
            steps,
            edges,
            visited,
            depth,
        );
    }
}

/// Walk every node whose `parent_fn_id` points at this function's id,
/// adding sinks as steps and recursing into nested Functions and Calls.
fn descend_into_function_body<'a>(
    fn_node: &'a IrNode,
    all_nodes: &'a [IrNode],
    call_graph: &CallGraph,
    by_id: &HashMap<&str, &'a IrNode>,
    steps: &mut Vec<ChainStep>,
    edges: &mut Vec<GraphEdge>,
    visited: &mut HashSet<String>,
    depth: usize,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let fn_id = fn_node.id.as_str();
    for candidate in all_nodes {
        if visited.contains(&candidate.id) { continue; }
        if candidate.parent_fn_id.as_deref() != Some(fn_id) { continue; }

        if is_interesting(&candidate.kind) {
            let edge_type = classify_edge(candidate);
            steps.push(node_to_step(candidate, edge_type.clone()));
            edges.push(GraphEdge {
                from: fn_node.id.clone(),
                to: candidate.id.clone(),
                edge_type,
            });
            visited.insert(candidate.id.clone());
            trace_from(
                candidate,
                ExecutionEdge::Direct,
                all_nodes,
                call_graph,
                by_id,
                steps,
                edges,
                visited,
                depth + 1,
            );
        } else if let IrNodeKind::Call { callee } = &candidate.kind {
            if let Some(fn_node_id) = call_graph.fn_nodes.get(callee) {
                if let Some(&cn) = by_id.get(fn_node_id.as_str()) {
                    trace_from(
                        cn,
                        ExecutionEdge::Direct,
                        all_nodes,
                        call_graph,
                        by_id,
                        steps,
                        edges,
                        visited,
                        depth + 1,
                    );
                }
            }
        } else if matches!(&candidate.kind, IrNodeKind::Function { .. }) {
            // Nested anonymous function (event callback / arrow / closure).
            // We can't know whether it actually fires, but for malware
            // detection it is essential to inspect its body — that is where
            // the eval/exec of attacker-controlled data usually lives.
            visited.insert(candidate.id.clone());
            descend_into_function_body(
                candidate,
                all_nodes,
                call_graph,
                by_id,
                steps,
                edges,
                visited,
                depth + 1,
            );
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
        IrNodeKind::EntryPoint { script }        => ("EntryPoint".into(), script.clone(), None),
        IrNodeKind::Function { name }            => ("Function".into(), name.clone(), None),
        IrNodeKind::Call { callee }              => ("Call".into(), Some(callee.clone()), None),
        IrNodeKind::ProcessExec { command, .. }  => ("ProcessExec".into(), None, command.clone()),
        IrNodeKind::FileRead { path, .. }        => ("FileRead".into(), None, path.clone()),
        IrNodeKind::FileWrite { path, .. }       => ("FileWrite".into(), None, path.clone()),
        IrNodeKind::NetworkRequest { url, .. }   => ("NetworkRequest".into(), None, url.clone()),
        IrNodeKind::Eval { raw_arg, .. }         => ("Eval".into(), None, raw_arg.clone()),
        IrNodeKind::DynamicImport { specifier, .. } => ("DynamicImport".into(), None, specifier.clone()),
        IrNodeKind::FunctionConstructor { body, .. } => ("FunctionConstructor".into(), None, body.clone()),
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
        IrNodeKind::EntryPoint { script: Some(s) } => EntryPointRef {
            kind: "install_script".to_string(),
            script: Some(s.clone()),
            path: Some(node.location.file.clone()),
        },
        IrNodeKind::EntryPoint { script: None } => EntryPointRef {
            kind: "file".to_string(),
            script: None,
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
/// | `LifecycleTrigger` edge            |  ×0.90 (weaker causality) |
/// | Minimum clamp                      |   0.10 |
fn compute_confidence(steps: &[ChainStep], all_nodes: &[IrNode]) -> f32 {
    // Build a quick lookup for node by id
    let by_id: HashMap<&str, &IrNode> = all_nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    let mut confidence: f32 = 1.0;

    for step in steps {
        if matches!(step.edge, ExecutionEdge::LifecycleTrigger) {
            confidence *= 0.90;
        }

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
