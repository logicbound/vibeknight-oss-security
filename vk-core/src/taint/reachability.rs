//! Reachability analysis
//! 
//! Determines if sinks are reachable from function entry points,
//! ensuring we only flag flows that are actually executable.

use vk_ir::{Function, BlockId, Instruction};
use std::collections::{HashMap, HashSet, VecDeque};

/// Reachability analyzer
pub struct ReachabilityAnalyzer {
    /// Map from block ID to reachable blocks
    reachability: HashMap<BlockId, HashSet<BlockId>>,
}

impl ReachabilityAnalyzer {
    pub fn new() -> Self {
        Self {
            reachability: HashMap::new(),
        }
    }
    
    /// Compute reachability for a function
    /// 
    /// Returns a set of all blocks reachable from the entry block
    pub fn compute_reachability(&mut self, function: &Function) -> HashSet<BlockId> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        
        // Start from entry block
        queue.push_back(function.entry_block);
        reachable.insert(function.entry_block);
        
        // Build control flow graph
        let cfg = self.build_cfg(function);
        
        // BFS to find all reachable blocks
        while let Some(block_id) = queue.pop_front() {
            if let Some(successors) = cfg.get(&block_id) {
                for &successor in successors {
                    if reachable.insert(successor) {
                        queue.push_back(successor);
                    }
                }
            }
        }
        
        self.reachability.insert(function.entry_block, reachable.clone());
        reachable
    }
    
    /// Build control flow graph
    fn build_cfg(&self, function: &Function) -> HashMap<BlockId, Vec<BlockId>> {
        let mut cfg = HashMap::new();
        
        // Block map not needed for current implementation
        
        for block in &function.blocks {
            let mut successors = Vec::new();
            
            // Check last instruction in block for control flow
            if let Some(last_instr) = block.instructions.last() {
                match &last_instr.node {
                    Instruction::Branch { then_block, else_block, .. } => {
                        successors.push(*then_block);
                        successors.push(*else_block);
                    }
                    Instruction::Jump { target } => {
                        successors.push(*target);
                    }
                    Instruction::Return { .. } => {
                        // No successors
                    }
                    _ => {
                        // Fall through to next block (simplified - would need proper block ordering)
                        // For now, assume sequential execution
                    }
                }
            }
            
            cfg.insert(block.id, successors);
        }
        
        cfg
    }
    
    /// Check if a block is reachable from the entry
    pub fn is_reachable(&self, function: &Function, block_id: BlockId) -> bool {
        if let Some(reachable) = self.reachability.get(&function.entry_block) {
            reachable.contains(&block_id)
        } else {
            // Compute if not cached
            let mut analyzer = Self::new();
            let reachable = analyzer.compute_reachability(function);
            reachable.contains(&block_id)
        }
    }
    
    /// Get all reachable blocks for a function
    pub fn get_reachable_blocks(&self, function: &Function) -> Option<&HashSet<BlockId>> {
        self.reachability.get(&function.entry_block)
    }
}

impl Default for ReachabilityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

