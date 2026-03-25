//! Forward taint propagation engine
//! 
//! Propagates taint from sources through the dataflow graph to sinks,
//! tracking sanitization along the way.

use vk_ir::{
    Function, Instruction, Expr, SymbolId, TaintState, TaintKind,
    AExpr, AInstruction,
};
use crate::taint::graph::DataflowGraph;
use crate::taint::model::{SourceDef, SinkDef, SanitizerDef};
use std::collections::HashMap;
use macros::dbg_eprintln;

/// Taint propagation engine
pub struct TaintPropagator {
    sources: SourceDef,
    sinks: SinkDef,
    sanitizers: SanitizerDef,
}

impl TaintPropagator {
    pub fn new() -> Self {
        Self {
            sources: SourceDef::default(),
            sinks: SinkDef::default(),
            sanitizers: SanitizerDef::default(),
        }
    }
    
    pub fn with_definitions(sources: SourceDef, sinks: SinkDef, sanitizers: SanitizerDef) -> Self {
        Self {
            sources,
            sinks,
            sanitizers,
        }
    }
    
    /// Propagate taint through a function
    /// 
    /// Returns a map from symbol IDs to their taint states after propagation
    pub fn propagate(&self, function: &Function, graph: &DataflowGraph) -> HashMap<SymbolId, TaintState> {
        let mut taint_map: HashMap<SymbolId, TaintState> = HashMap::new();
        
        // Step 0: Mark function parameters that are known sources
        // First, check the explicit params list
        for param in &function.params {
            let is_source = param.name == "req" || 
                           param.name == "request" ||
                           param.name == "process" ||
                           param.name == "document" ||
                           param.name == "window" ||
                           param.name == "fetch";
            
            if is_source {
                dbg_eprintln!("[DEBUG] Marking parameter '{}' (SymbolId({})) as source", param.name, param.symbol_id.0);
                taint_map.insert(param.symbol_id, TaintState::tainted(TaintKind::UserInput));
            }
        }
        
        // Step 1: Identify sources in the function
        for block in &function.blocks {
            for instruction in &block.instructions {
                self.mark_sources(&instruction, &mut taint_map);
            }
        }
        
        // Step 2: Propagate taint through dataflow edges
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100; // Prevent infinite loops
        
        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;
            
            for edge in graph.edges() {
                let from_taint = self.get_taint_for_node(&edge.from, &taint_map, function);
                let to_taint = self.get_taint_for_node(&edge.to, &taint_map, function);
                
                // Merge taint states
                let new_taint = from_taint.merge(&to_taint);
                
                if new_taint != to_taint {
                    if let Some(symbol_id) = self.get_symbol_from_node(&edge.to) {
                        taint_map.insert(symbol_id, new_taint.clone());
                        changed = true;
                    }
                }
            }
        }
        
        // Step 3: Apply sanitization
        for block in &function.blocks {
            for instruction in &block.instructions {
                self.apply_sanitization(&instruction, &mut taint_map);
            }
        }
        
        taint_map
    }
    
    fn mark_sources(&self, instruction: &AInstruction, taint_map: &mut HashMap<SymbolId, TaintState>) {
        match &instruction.node {
            Instruction::Assign { dst, src } => {
                // Check if source expression is a taint source
                if let Some(source) = self.find_source_in_expr(src) {
                    taint_map.insert(*dst, TaintState::tainted(source.kind));
                }
            }
            Instruction::Call { callee, args: _ } => {
                // Check if the call itself is a source
                if self.find_source_in_expr(callee).is_some() {
                    // Mark call result as tainted (simplified - would need proper tracking)
                }
            }
            _ => {}
        }
    }
    
    fn find_source_in_expr(&self, expr: &AExpr) -> Option<&crate::taint::model::Source> {
        match &expr.node {
            Expr::Identifier(_) => {
                self.sources.find_source(&expr.node)
            }
            Expr::Member { obj: _, prop: _ } => {
                self.sources.find_source(&expr.node)
            }
            Expr::Call { callee, .. } => {
                self.sources.find_source(&callee.node)
            }
            _ => None,
        }
    }
    
    fn apply_sanitization(&self, instruction: &AInstruction, taint_map: &mut HashMap<SymbolId, TaintState>) {
        match &instruction.node {
            Instruction::Call { callee, args } => {
                // Check if this is a sanitizer
                if self.sanitizers.find_sanitizer(&callee.node).is_some() {
                    // Sanitize all arguments
                    for arg in args {
                        if let Some(symbol_id) = self.extract_symbol_from_expr(arg) {
                            if let Some(taint) = taint_map.get(&symbol_id) {
                                let sanitized = match taint {
                                    TaintState::Tainted { kinds } => {
                                        TaintState::Sanitized {
                                            original_kinds: kinds.clone(),
                                            sanitizer: "sanitizer".to_string(), // Would get actual name
                                        }
                                    }
                                    _ => taint.clone(),
                                };
                                taint_map.insert(symbol_id, sanitized);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    fn get_taint_for_node(
        &self,
        node: &crate::taint::graph::DataflowNode,
        taint_map: &HashMap<SymbolId, TaintState>,
        _function: &Function,
    ) -> TaintState {
        match node {
            crate::taint::graph::DataflowNode::Variable(symbol_id) |
            crate::taint::graph::DataflowNode::Parameter(symbol_id) => {
                taint_map.get(symbol_id)
                    .cloned()
                    .unwrap_or_default()
            }
            _ => TaintState::default(),
        }
    }
    
    fn get_symbol_from_node(&self, node: &crate::taint::graph::DataflowNode) -> Option<SymbolId> {
        match node {
            crate::taint::graph::DataflowNode::Variable(symbol_id) |
            crate::taint::graph::DataflowNode::Parameter(symbol_id) => {
                Some(*symbol_id)
            }
            _ => None,
        }
    }
    
    fn extract_symbol_from_expr(&self, expr: &AExpr) -> Option<SymbolId> {
        match &expr.node {
            Expr::Identifier(_) => {
                expr.meta.symbol
            }
            _ => None,
        }
    }
    
    /// Check if tainted data reaches a sink
    pub fn check_sink_reachability(
        &self,
        function: &Function,
        taint_map: &HashMap<SymbolId, TaintState>,
    ) -> Vec<SinkFinding> {
        let mut findings = Vec::new();
        
        for block in &function.blocks {
            for instruction in &block.instructions {
                if let Instruction::Call { callee, args } = &instruction.node {
                    if let Some(sink) = self.sinks.find_sink(&callee.node) {
                        // Check if any sensitive arguments are tainted
                        let sensitive_indices = sink.sensitive_args.as_ref()
                            .map(|v| v.as_slice())
                            .unwrap_or(&[]);
                        
                        for (arg_idx, arg) in args.iter().enumerate() {
                            if sensitive_indices.is_empty() || sensitive_indices.contains(&arg_idx) {
                                if let Some(symbol_id) = self.extract_symbol_from_expr(arg) {
                                    if let Some(taint) = taint_map.get(&symbol_id) {
                                        if taint.is_tainted() && !taint.is_sanitized() {
                                            findings.push(SinkFinding {
                                                sink: sink.clone(),
                                                taint: taint.clone(),
                                                argument_index: arg_idx,
                                                instruction_location: instruction.meta.source.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
}

/// Finding when tainted data reaches a sink
#[derive(Debug, Clone)]
pub struct SinkFinding {
    pub sink: crate::taint::model::Sink,
    pub taint: TaintState,
    pub argument_index: usize,
    pub instruction_location: Option<vk_ir::SourceLocation>,
}

impl Default for TaintPropagator {
    fn default() -> Self {
        Self::new()
    }
}

