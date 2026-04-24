use std::collections::HashMap;
use vk_ir::{IrNode, IrNodeKind};

use crate::flow::ExecutionEdge;

// ── Typed call edge ───────────────────────────────────────────────────────────

/// A directed call edge with its execution-edge type.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The callee identity (e.g. "child_process.exec" or a function name).
    pub callee: String,
    /// The semantic type of the call edge.
    pub edge_type: ExecutionEdge,
}

// ── Call graph ────────────────────────────────────────────────────────────────

/// A directed call graph built from a flat list of IR nodes.
///
/// Edges represent: caller function name → typed call edges.
/// `fn_nodes` maps callee identity → node id of the matching Function node.
#[derive(Debug, Default)]
pub struct CallGraph {
    /// function name → list of typed edges leaving it
    pub edges: HashMap<String, Vec<CallEdge>>,
    /// callee identity → node id of the matching Function node (if present)
    pub fn_nodes: HashMap<String, String>,
}

impl CallGraph {
    pub fn build(nodes: &[IrNode]) -> Self {
        let mut graph = CallGraph::default();
        let mut current_fn: Option<String> = None;

        for node in nodes {
            match &node.kind {
                IrNodeKind::Function { name } => {
                    if let Some(n) = name {
                        graph.fn_nodes.insert(n.clone(), node.id.clone());
                        current_fn = Some(n.clone());
                    }
                }
                IrNodeKind::Call { callee } => {
                    if let Some(fn_name) = &current_fn {
                        let edge_type = classify_call_edge(callee, node);
                        graph
                            .edges
                            .entry(fn_name.clone())
                            .or_default()
                            .push(CallEdge {
                                callee: callee.clone(),
                                edge_type,
                            });
                    }
                }
                _ => {}
            }
        }

        graph
    }

    /// Return the direct callees of a function as plain strings (for backward compat).
    pub fn callees_of(&self, fn_name: &str) -> Vec<String> {
        self.edges
            .get(fn_name)
            .map(|edges| edges.iter().map(|e| e.callee.clone()).collect())
            .unwrap_or_default()
    }

    /// Return the typed call edges leaving a function.
    pub fn typed_edges_of(&self, fn_name: &str) -> &[CallEdge] {
        self.edges.get(fn_name).map(Vec::as_slice).unwrap_or(&[])
    }
}

// ── Edge classification ───────────────────────────────────────────────────────

fn classify_call_edge(callee: &str, node: &IrNode) -> ExecutionEdge {
    // setTimeout / setInterval / Promise callbacks → Deferred
    if matches!(callee, "setTimeout" | "setInterval" | "Promise.then" | "Promise.catch" | "Promise.finally") {
        return ExecutionEdge::Deferred;
    }

    // Event-listener patterns → EventDriven
    if matches!(callee,
        "process.on" | "process.once" |
        "EventEmitter.on" | "EventEmitter.once" |
        "emitter.on" | "emitter.once" |
        "ee.on" | "ee.once"
    ) {
        return ExecutionEdge::EventDriven;
    }

    // A call with ObfuscatedContext tag → still Direct (tag carries the signal for scoring)
    if node.tags.iter().any(|t| matches!(t, vk_ir::NodeTag::ObfuscatedContext)) {
        return ExecutionEdge::Direct;
    }

    ExecutionEdge::Direct
}
