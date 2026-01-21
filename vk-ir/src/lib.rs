// Intermediate Representation (IR) for Vibe Knight
// Language-agnostic IR that serves as the boundary between parsing and analysis

use std::collections::HashMap;

/// Top-level program representation
pub struct Program {
    pub modules: Vec<Module>,
    pub module_graph: ModuleGraph,
}

/// Represents a module/file
pub struct Module {
    pub path: String,
    pub functions: Vec<Function>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub symbols: SymbolTable,
}


/// Annotated expression
pub type AExpr = Annotated<Expr>;
pub type AInstruction = Annotated<Instruction>;

/// Normalized expression tree (does not expose parser internals)
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Call {
        callee: Box<AExpr>,
        args: Vec<AExpr>,
    },
    Member {
        obj: Box<AExpr>,
        prop: String,
    },
    Binary {
        op: BinaryOp,
        left: Box<AExpr>,
        right: Box<AExpr>,
    },
    Identifier(String),
    Literal(Value),
}




/// Binary operations
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    // Comparison
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    // Logical
    And,
    Or,
    // String operations
    Concat, // String concatenation
}

/// Literal values
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    Undefined,
}

/// Function representation
pub struct Function {
    pub name: String,
    pub params: Vec<Parameter>,
    pub blocks: Vec<BasicBlock>,
    pub entry_block: BlockId,
    pub scope_id: ScopeId,
}

/// Function parameter
pub struct Parameter {
    pub name: String,
    pub symbol_id: SymbolId,
}

/// Basic block identifier (opaque)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

/// Basic block in control flow
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<Annotated<Instruction>>,
}

/// Instruction in a basic block
pub enum Instruction {
    Assign { dst: SymbolId, src: AExpr },
    Call { callee: AExpr, args: Vec<AExpr> },
    Branch {
        condition: AExpr,
        then_block: BlockId,
        else_block: BlockId,
    },
    Jump {
        target: BlockId,
    },
    Return { value: Option<AExpr> },
}

/// Source location for Instructions
#[derive(Debug, Clone, PartialEq)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Metadata for Instructions
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    pub source: Option<SourceLocation>,
    pub symbol: Option<SymbolId>,
    pub taint: TaintState,
    pub tags: HashMap<String, String>,
}


/// Taint state for Instructions
#[derive(Debug, Clone, PartialEq)]
pub enum TaintState {
    Untainted,
    Tainted,
    Unknown,
}

/// Annotated node with metadata
#[derive(Debug, Clone, PartialEq)]
pub struct Annotated<T> {
    pub node: T,
    pub meta: Metadata,
}



/// Import statement
pub struct Import {
    pub specifiers: Vec<ImportSpecifier>,
    pub source: String,
}

/// Import specifier (default, named, namespace)
pub enum ImportSpecifier {
    Default { local: String },
    Named { local: String, imported: String },
    Namespace { local: String },
}

/// Export statement
pub struct Export {
    pub specifiers: Vec<ExportSpecifier>,
    pub source: Option<String>, // None for local exports, Some for re-exports
}

/// Export specifier
pub enum ExportSpecifier {
    Default { local: String },
    Named { local: String, exported: Option<String> },
}

/// Symbol identifier (opaque)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolId(pub u32);

/// Scope identifier (opaque)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeId(pub u32);

/// Symbol table for a module
pub struct SymbolTable {
    symbols: HashMap<SymbolId, Symbol>,
    by_name: HashMap<String, Vec<SymbolId>>,
    next_id: u32,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            by_name: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add_symbol(&mut self, name: String, kind: SymbolKind, scope_id: ScopeId) -> SymbolId {
        let id = SymbolId(self.next_id);
        self.next_id += 1;
        
        let symbol = Symbol {
            name,
            scope_id,
            kind,
        };
        
        self.symbols.insert(id, symbol.clone());
        self.by_name.entry(symbol.name.clone())
            .or_insert_with(Vec::new)
            .push(id);
        
        id
    }

    pub fn get_symbol(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(&id)
    }

    pub fn find_symbols(&self, name: &str) -> Vec<&Symbol> {
        self.by_name.get(name)
            .map(|ids| ids.iter().filter_map(|id| self.symbols.get(id)).collect())
            .unwrap_or_default()
    }
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub scope_id: ScopeId,
    pub kind: SymbolKind,
}

/// Kind of symbol
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolKind {
    Import,
    Local,
    Parameter,
    Closure,
    Function,
    Variable,
}

/// Module dependency graph
pub struct ModuleGraph {
    modules: HashMap<String, ModuleNode>,
}

/// Node in module graph
struct ModuleNode {
    dependencies: Vec<String>,
    dependents: Vec<String>,
}

impl ModuleGraph {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn add_module(&mut self, path: String) {
        if !self.modules.contains_key(&path) {
            self.modules.insert(path, ModuleNode {
                dependencies: Vec::new(),
                dependents: Vec::new(),
            });
        }
    }

    pub fn add_dependency(&mut self, from: &str, to: &str) {
        self.add_module(from.to_string());
        self.add_module(to.to_string());
        
        if let Some(node) = self.modules.get_mut(from) {
            if !node.dependencies.contains(&to.to_string()) {
                node.dependencies.push(to.to_string());
            }
        }
        
        if let Some(node) = self.modules.get_mut(to) {
            if !node.dependents.contains(&from.to_string()) {
                node.dependents.push(from.to_string());
            }
        }
    }

    pub fn get_dependencies(&self, path: &str) -> &[String] {
        self.modules.get(path)
            .map(|n| n.dependencies.as_slice())
            .unwrap_or(&[])
    }

    pub fn get_dependents(&self, path: &str) -> &[String] {
        self.modules.get(path)
            .map(|n| n.dependents.as_slice())
            .unwrap_or(&[])
    }
}

