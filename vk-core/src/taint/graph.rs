//! Dataflow graph construction
//! 
//! Builds intra-procedural dataflow graphs from IR to track how data flows
//! through variable assignments, function calls, and returns.

use vk_ir::{
    Function, BasicBlock, Instruction, Expr, SymbolId, BlockId,
    AExpr, SymbolTable,
};
use std::collections::{HashMap, HashSet};

/// Dataflow graph node
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataflowNode {
    /// A variable/symbol
    Variable(SymbolId),
    /// A function parameter
    Parameter(SymbolId),
    /// A function return value
    ReturnValue(SymbolId),
    /// A function call argument
    CallArgument { call_id: usize, arg_index: usize },
    /// A function call result
    CallResult { call_id: usize },
    /// An object property access
    Property { obj: SymbolId, prop: String },
}

/// Edge in the dataflow graph representing data flow
#[derive(Debug, Clone, PartialEq)]
pub struct DataflowEdge {
    pub from: DataflowNode,
    pub to: DataflowNode,
    /// The instruction that causes this flow
    pub instruction: usize, // Index in the instruction list
    /// The block where this flow occurs
    pub block: BlockId,
}

/// Dataflow graph for a function
pub struct DataflowGraph {
    /// Nodes in the graph
    nodes: HashSet<DataflowNode>,
    /// Edges representing data flow
    edges: Vec<DataflowEdge>,
    /// Map from symbol to nodes
    symbol_to_nodes: HashMap<SymbolId, Vec<DataflowNode>>,
    /// Map from call site to call ID
    call_sites: HashMap<usize, usize>, // instruction index -> call_id
    next_call_id: usize,
    /// Symbol table for name resolution (optional)
    symbol_table: Option<SymbolTable>,
}

impl DataflowGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            edges: Vec::new(),
            symbol_to_nodes: HashMap::new(),
            call_sites: HashMap::new(),
            next_call_id: 0,
            symbol_table: None,
        }
    }
    
    /// Build dataflow graph for a function
    pub fn build_for_function(function: &Function) -> Self {
        Self::build_for_function_with_symbols(function, None)
    }
    
    /// Build a dataflow graph for a function with symbol table for name resolution
    pub fn build_for_function_with_symbols(function: &Function, symbol_table: Option<&SymbolTable>) -> Self {
        let mut graph = Self::new();
        graph.symbol_table = symbol_table.cloned();
        
        // Add parameter nodes
        for param in &function.params {
            let node = DataflowNode::Parameter(param.symbol_id);
            graph.add_node(node.clone());
            graph.symbol_to_nodes.entry(param.symbol_id)
                .or_insert_with(Vec::new)
                .push(node);
        }
        
        // Process each block
        for block in &function.blocks {
            graph.build_block(block, function);
        }
        
        graph
    }
    
    fn build_block(&mut self, block: &BasicBlock, _function: &Function) {
        for (instr_idx, instruction) in block.instructions.iter().enumerate() {
            match &instruction.node {
                Instruction::Assign { dst, src } => {
                    // Variable assignment: src -> dst
                    let dst_node = self.get_or_create_variable(*dst);
                    let src_nodes = self.extract_nodes_from_expr(src);
                    
                    for src_node in src_nodes {
                        self.add_edge(DataflowEdge {
                            from: src_node,
                            to: dst_node.clone(),
                            instruction: instr_idx,
                            block: block.id,
                        });
                    }
                }
                Instruction::Call { callee: _, args } => {
                    // Function call: arguments -> parameters, return -> result
                    let call_id = self.next_call_id;
                    self.next_call_id += 1;
                    self.call_sites.insert(instr_idx, call_id);
                    
                    // Create call result node
                    let result_node = DataflowNode::CallResult { call_id };
                    self.add_node(result_node.clone());
                    
                    // Process arguments
                    for (arg_idx, arg) in args.iter().enumerate() {
                        let arg_node = DataflowNode::CallArgument {
                            call_id,
                            arg_index: arg_idx,
                        };
                        self.add_node(arg_node.clone());
                        
                        // Flow from argument expression to call argument node
                        let arg_expr_nodes = self.extract_nodes_from_expr(arg);
                        for expr_node in arg_expr_nodes {
                            self.add_edge(DataflowEdge {
                                from: expr_node,
                                to: arg_node.clone(),
                                instruction: instr_idx,
                                block: block.id,
                            });
                        }
                    }
                }
                Instruction::Return { value } => {
                    if let Some(ret_expr) = value {
                        // Return value flow
                        let ret_nodes = self.extract_nodes_from_expr(ret_expr);
                        for ret_node in ret_nodes {
                            // Create return value node for the function
                            // In a real implementation, we'd track which function this is
                            let return_node = DataflowNode::ReturnValue(SymbolId(0)); // Placeholder
                            self.add_node(return_node.clone());
                            
                            self.add_edge(DataflowEdge {
                                from: ret_node,
                                to: return_node,
                                instruction: instr_idx,
                                block: block.id,
                            });
                        }
                    }
                }
                _ => {
                    // Other instructions don't create dataflow edges
                }
            }
        }
    }
    
    fn extract_nodes_from_expr(&mut self, expr: &AExpr) -> Vec<DataflowNode> {
        match &expr.node {
            Expr::Identifier(name) => {
                // If expression has a symbol, create node for it
                if let Some(symbol_id) = expr.meta.symbol {
                    vec![self.get_or_create_variable(symbol_id)]
                } else if let Some(ref symbol_table) = self.symbol_table {
                    // Try to look up symbol by name
                    let symbol_ids = symbol_table.find_symbol_ids(name);
                    if let Some(symbol_id) = symbol_ids.first() {
                        vec![self.get_or_create_variable(*symbol_id)]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            }
            Expr::Member { obj, prop: _ } => {
                // Object property access - extract from object
                self.extract_nodes_from_expr(obj)
            }
            Expr::Call { callee: _, args } => {
                // Call arguments contribute to the call
                let mut nodes = Vec::new();
                for arg in args {
                    nodes.extend(self.extract_nodes_from_expr(arg));
                }
                nodes
            }
            Expr::Binary { left, right, .. } => {
                let mut nodes = Vec::new();
                nodes.extend(self.extract_nodes_from_expr(left));
                nodes.extend(self.extract_nodes_from_expr(right));
                nodes
            }
            Expr::Literal(_) => {
                // Literals don't create dataflow nodes
                Vec::new()
            }
        }
    }
    
    fn get_or_create_variable(&mut self, symbol_id: SymbolId) -> DataflowNode {
        let node = DataflowNode::Variable(symbol_id);
        if !self.nodes.contains(&node) {
            self.add_node(node.clone());
            self.symbol_to_nodes.entry(symbol_id)
                .or_insert_with(Vec::new)
                .push(node.clone());
        }
        node
    }
    
    fn add_node(&mut self, node: DataflowNode) {
        self.nodes.insert(node);
    }
    
    fn add_edge(&mut self, edge: DataflowEdge) {
        self.edges.push(edge);
    }
    
    /// Get all edges
    pub fn edges(&self) -> &[DataflowEdge] {
        &self.edges
    }
    
    /// Get all nodes
    pub fn nodes(&self) -> &HashSet<DataflowNode> {
        &self.nodes
    }
    
    /// Get nodes for a symbol
    pub fn get_nodes_for_symbol(&self, symbol_id: SymbolId) -> Vec<&DataflowNode> {
        self.symbol_to_nodes.get(&symbol_id)
            .map(|nodes| nodes.iter().collect())
            .unwrap_or_default()
    }
    
    /// Find all nodes that flow to the given node
    pub fn find_predecessors(&self, node: &DataflowNode) -> Vec<&DataflowNode> {
        self.edges.iter()
            .filter(|e| &e.to == node)
            .map(|e| &e.from)
            .collect()
    }
    
    /// Find all nodes that flow from the given node
    pub fn find_successors(&self, node: &DataflowNode) -> Vec<&DataflowNode> {
        self.edges.iter()
            .filter(|e| &e.from == node)
            .map(|e| &e.to)
            .collect()
    }
}

impl Default for DataflowGraph {
    fn default() -> Self {
        Self::new()
    }
}

