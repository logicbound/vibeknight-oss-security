//! Inter-procedural taint analysis
//! 
//! Handles taint propagation across function boundaries using
//! summary-based analysis.

use vk_ir::{Function, SymbolId, TaintState, TaintKind};
use std::collections::HashMap;

/// Function summary for inter-procedural analysis
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Function name
    pub name: String,
    /// Which parameters can be tainted (parameter index -> taint kinds)
    pub tainted_params: HashMap<usize, Vec<TaintKind>>,
    /// Whether the return value can be tainted
    pub tainted_return: bool,
    /// Which taint kinds can flow to the return value
    pub return_taint_kinds: Vec<TaintKind>,
}

/// Inter-procedural analyzer
pub struct InterProceduralAnalyzer {
    /// Cache of function summaries
    summaries: HashMap<String, FunctionSummary>,
}

impl InterProceduralAnalyzer {
    pub fn new() -> Self {
        Self {
            summaries: HashMap::new(),
        }
    }
    
    /// Compute summary for a function
    pub fn compute_summary(&mut self, function: &Function, intra_taint: &HashMap<SymbolId, TaintState>) -> FunctionSummary {
        let mut summary = FunctionSummary {
            name: function.name.clone(),
            tainted_params: HashMap::new(),
            tainted_return: false,
            return_taint_kinds: Vec::new(),
        };
        
        // Check which parameters are tainted
        for (param_idx, param) in function.params.iter().enumerate() {
            if let Some(taint) = intra_taint.get(&param.symbol_id) {
                if taint.is_tainted() {
                    summary.tainted_params.insert(param_idx, taint.kinds());
                }
            }
        }
        
        // Check return value (simplified - would need proper return tracking)
        // For now, if any parameter is tainted, assume return can be tainted
        if !summary.tainted_params.is_empty() {
            summary.tainted_return = true;
            // Collect all taint kinds from parameters
            for kinds in summary.tainted_params.values() {
                summary.return_taint_kinds.extend(kinds.clone());
            }
            summary.return_taint_kinds.sort_by_key(|k| k.as_str());
            summary.return_taint_kinds.dedup();
        }
        
        // Cache the summary
        self.summaries.insert(function.name.clone(), summary.clone());
        
        summary
    }
    
    /// Get cached summary for a function
    pub fn get_summary(&self, function_name: &str) -> Option<&FunctionSummary> {
        self.summaries.get(function_name)
    }
    
    /// Apply function summary at a call site
    /// 
    /// Returns taint state for the call result based on argument taint
    pub fn apply_summary(
        &self,
        summary: &FunctionSummary,
        arg_taints: &[TaintState],
    ) -> TaintState {
        if !summary.tainted_return {
            return TaintState::default();
        }
        
        // Collect taint kinds from arguments that correspond to tainted parameters
        let mut result_kinds = Vec::new();
        
        for (param_idx, _param_kinds) in &summary.tainted_params {
            if let Some(arg_taint) = arg_taints.get(*param_idx) {
                if arg_taint.is_tainted() {
                    result_kinds.extend(arg_taint.kinds());
                }
            }
        }
        
        if result_kinds.is_empty() {
            TaintState::default()
        } else {
            result_kinds.sort_by_key(|k| k.as_str());
            result_kinds.dedup();
            TaintState::tainted_multi(result_kinds)
        }
    }
}

impl Default for InterProceduralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

