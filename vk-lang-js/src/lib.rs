use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::{SourceType, Span, GetSpan};
use oxc_ast::ast::*;
use std::path::Path;
use vk_ir::{
    Program, Module, Function, BasicBlock, Instruction, Expr, Value, BinaryOp,
    Import, ImportSpecifier, Export, ExportSpecifier,
    SymbolTable, ScopeId, SymbolKind, Parameter,
    ModuleGraph, BlockId, Annotated, AExpr, AInstruction, Metadata, TaintState, SourceLocation,
};
use macros::dbg_eprintln;

pub mod patterns;

/// Convert OXC span to SourceLocation
fn span_to_location(span: Span, file_path: &str, source: &str) -> SourceLocation {
    // OXC spans are byte offsets, we need to convert to line/column
    let start = span.start as usize;
    let mut line = 1;
    let mut column = 1;
    
    // Count lines and find column
    for (idx, ch) in source.char_indices() {
        if idx >= start {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    
    SourceLocation {
        file: file_path.to_string(),
        line: line as u32,
        column: column as u32,
    }
}

/// Helper to create annotated expression with source location
fn annotate_expr_with_location(expr: Expr, span: Option<Span>, file_path: &str, source: &str) -> AExpr {
    let source_loc = span.map(|s| span_to_location(s, file_path, source));
    Annotated {
        node: expr,
        meta: Metadata {
            source: source_loc,
            symbol: None,
            taint: TaintState::Unknown,
            tags: std::collections::HashMap::new(),
        },
    }
}

/// Helper to create annotated instruction with source location
fn annotate_instr_with_location(instr: Instruction, span: Option<Span>, file_path: &str, source: &str) -> AInstruction {
    let source_loc = span.map(|s| span_to_location(s, file_path, source));
    Annotated {
        node: instr,
        meta: Metadata {
            source: source_loc,
            symbol: None,
            taint: TaintState::Unknown,
            tags: std::collections::HashMap::new(),
        },
    }
}

/// Parse JavaScript source and lower it to IR with symbol resolution
pub fn lower_to_ir(source: &str) -> Program {
    lower_to_ir_with_path(source, "")
}

/// Parse JavaScript source and lower it to IR with symbol resolution
/// `file_path` is used for module graph resolution
pub fn lower_to_ir_with_path(source: &str, file_path: &str) -> Program {
    let allocator = Allocator::default();
    
    // Detect TypeScript based on file extension
    let source_type = if file_path.ends_with(".ts") || file_path.ends_with(".tsx") {
        // TypeScript mode
        let mut st = SourceType::default();
        st = st.with_typescript(true);
        st = st.with_jsx(file_path.ends_with(".tsx"));
        st = st.with_module(true);
        st
    } else {
        // JavaScript mode
        let mut st = SourceType::default();
        st = st.with_jsx(file_path.ends_with(".jsx"));
        st = st.with_module(true);
        st
    };
    
    dbg_eprintln!("[DEBUG] lower_to_ir_with_path: File={}, is_ts={}, is_jsx={}", 
        file_path, 
        file_path.ends_with(".ts") || file_path.ends_with(".tsx"),
        file_path.ends_with(".jsx") || file_path.ends_with(".tsx")
    );
    
    let parser = Parser::new(&allocator, source, source_type);
    let program = parser.parse().program;

    dbg_eprintln!("[DEBUG] lower_to_ir_with_path: File={}, program.body.len()={}", file_path, program.body.len());
    for (idx, stmt) in program.body.iter().enumerate() {
        dbg_eprintln!("[DEBUG]   Statement {}: {:?}", idx, std::mem::discriminant(stmt));
    }

    let mut symbol_table = SymbolTable::new();
    let mut module_graph = ModuleGraph::new();
    let mut scope_stack = vec![ScopeId(0)]; // Global scope
    let mut next_scope_id = 1u32;

    // Process imports and exports first
    let (imports, exports) = extract_imports_exports(&program.body, &mut symbol_table, scope_stack[0]);
    
    // Build module graph from imports
    for import in &imports {
        let resolved_path = resolve_import_path(&import.source, file_path);
        module_graph.add_module(file_path.to_string());
        module_graph.add_module(resolved_path.clone());
        module_graph.add_dependency(file_path, &resolved_path);
    }

    // Process functions with symbol resolution
    let functions = lower_functions(
        &program.body,
        &mut symbol_table,
        &mut scope_stack,
        &mut next_scope_id,
        source,
        file_path,
    );

    let module = Module {
        path: file_path.to_string(),
        functions,
        imports,
        exports,
        symbols: symbol_table,
    };

    Program {
        modules: vec![module],
        module_graph,
    }
}

/// Extract import and export statements
fn extract_imports_exports(
    body: &oxc_allocator::Vec<'_, Statement<'_>>,
    symbol_table: &mut SymbolTable,
    scope_id: ScopeId,
) -> (Vec<Import>, Vec<Export>) {
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    for stmt in body {
        match stmt {
            Statement::ModuleDeclaration(module_decl) => {
                match &**module_decl {
                    ModuleDeclaration::ImportDeclaration(import_decl) => {
                        let specifiers: Vec<ImportSpecifier> = if let Some(specs) = &import_decl.specifiers {
                            specs.iter()
                                .map(|spec| {
                                    match spec {
                                        ImportDeclarationSpecifier::ImportSpecifier(import_spec) => {
                                            let local = import_spec.local.name.to_string();
                                            
                                            // Add to symbol table
                                            symbol_table.add_symbol(
                                                local.clone(),
                                                SymbolKind::Import,
                                                scope_id,
                                            );
                                            
                                            let imported = match &import_spec.imported {
                                                ModuleExportName::Identifier(ident) => ident.name.to_string(),
                                                ModuleExportName::StringLiteral(lit) => lit.value.to_string(),
                                            };
                                            
                                            ImportSpecifier::Named {
                                                local,
                                                imported,
                                            }
                                        }
                                        ImportDeclarationSpecifier::ImportDefaultSpecifier(default_spec) => {
                                            let local = default_spec.local.name.to_string();
                                            symbol_table.add_symbol(local.clone(), SymbolKind::Import, scope_id);
                                            ImportSpecifier::Default { local }
                                        }
                                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace_spec) => {
                                            let local = namespace_spec.local.name.to_string();
                                            symbol_table.add_symbol(local.clone(), SymbolKind::Import, scope_id);
                                            ImportSpecifier::Namespace { local }
                                        }
                                    }
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };

                        imports.push(Import {
                            specifiers,
                            source: import_decl.source.value.to_string(),
                        });
                    }
                    ModuleDeclaration::ExportNamedDeclaration(export_decl) => {
                        let specifiers: Vec<ExportSpecifier> = export_decl.specifiers
                            .iter()
                            .map(|spec| {
                                let local = spec.local.name().to_string();
                                let exported = match &spec.exported {
                                    ModuleExportName::Identifier(ident) => Some(ident.name.to_string()),
                                    ModuleExportName::StringLiteral(lit) => Some(lit.value.to_string()),
                                };
                                ExportSpecifier::Named {
                                    local,
                                    exported,
                                }
                            })
                            .collect();

                        exports.push(Export {
                            specifiers,
                            source: export_decl.source.as_ref().map(|s| s.value.to_string()),
                        });
                    }
                    ModuleDeclaration::ExportDefaultDeclaration(_) => {
                        // Handle default exports - simplified for now
                        exports.push(Export {
                            specifiers: vec![ExportSpecifier::Default { local: "default".to_string() }],
                            source: None,
                        });
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    (imports, exports)
}

/// Process arrow functions from variable declarations
fn process_variable_declaration_arrow_functions(
    var_decl: &VariableDeclaration<'_>,
    symbol_table: &mut SymbolTable,
    scope_stack: &mut Vec<ScopeId>,
    next_scope_id: &mut u32,
    source: &str,
    file_path: &str,
) -> Vec<Function> {
    let mut functions = Vec::new();
    
    for declarator in &var_decl.declarations {
        if let Some(init) = &declarator.init {
            if let Expression::ArrowFunctionExpression(arrow_func) = init {
                let function_name = match &declarator.id.kind {
                    BindingPatternKind::BindingIdentifier(ident) => {
                        ident.name.to_string()
                    }
                    _ => continue,
                };
                
                // Create function scope
                let function_scope = ScopeId(*next_scope_id);
                *next_scope_id += 1;
                scope_stack.push(function_scope);
                
                // Add function to symbol table
                let _func_symbol_id = symbol_table.add_symbol(
                    function_name.clone(),
                    SymbolKind::Function,
                    scope_stack[scope_stack.len() - 2],
                );
                
                // Process parameters
                let params = arrow_func.params.items.iter()
                    .filter_map(|param| {
                        match &param.pattern.kind {
                            BindingPatternKind::BindingIdentifier(ident) => {
                                let param_name = ident.name.to_string();
                                let symbol_id = symbol_table.add_symbol(
                                    param_name.clone(),
                                    SymbolKind::Parameter,
                                    function_scope,
                                );
                                Some(Parameter {
                                    name: param_name,
                                    symbol_id,
                                })
                            }
                            _ => None,
                        }
                    })
                    .collect();
                
                // Lower arrow function body
                let mut blocks = Vec::new();
                let mut instructions: Vec<AInstruction> = Vec::new();

                //@TODO: Make next_block_id mutable once we have multiple blocks
                let next_block_id = 0u32;
                let entry_block_id = BlockId(next_block_id);
                // @TODO: Only increment when you actually create another block
                //next_block_id += 1;

                
                // Arrow function body handling
                lower_statements(
                    &arrow_func.body.statements,
                    &mut instructions,
                    symbol_table,
                    scope_stack,
                    next_scope_id,
                    source,
                    file_path,
                );
                
                
                
                blocks.push(BasicBlock {
                    id: entry_block_id,
                    instructions,
                });
                
                
                functions.push(Function {
                    name: function_name,
                    params,
                    blocks,
                    entry_block: entry_block_id,
                    scope_id: function_scope,
                });
                
                
                scope_stack.pop();
            }
        }
    }
    
    functions
}

/// Lower function declarations to IR with symbol resolution
fn lower_functions(
    body: &oxc_allocator::Vec<'_, Statement<'_>>,
    symbol_table: &mut SymbolTable,
    scope_stack: &mut Vec<ScopeId>,
    next_scope_id: &mut u32,
    source: &str,
    file_path: &str,
) -> Vec<Function> {
    let mut functions = Vec::new();

    dbg_eprintln!("[DEBUG] lower_functions: Processing {} statements", body.len());
    for stmt in body {
        dbg_eprintln!("[DEBUG] lower_functions: Statement type = {:?}", std::mem::discriminant(stmt));
        match stmt {
            // Handle exported functions: export function foo() { ... }
            Statement::ModuleDeclaration(module_decl) => {
                match &**module_decl {
                    ModuleDeclaration::ExportNamedDeclaration(export_decl) => {
                        if let Some(Declaration::FunctionDeclaration(func_decl)) = &export_decl.declaration {
                            dbg_eprintln!("[DEBUG] Found exported FunctionDeclaration");
                            if let Some(binding_identifier) = &func_decl.id {
                                let function_name = binding_identifier.name.to_string();
                                
                                // Create function scope
                                let function_scope = ScopeId(*next_scope_id);
                                *next_scope_id += 1;
                                scope_stack.push(function_scope);
                                
                                // Add function to symbol table
                                let _func_symbol_id = symbol_table.add_symbol(
                                    function_name.clone(),
                                    SymbolKind::Function,
                                    scope_stack[scope_stack.len() - 2],
                                );
                                
                                // Process parameters
                                let params: Vec<Parameter> = func_decl.params.items.iter()
                                    .filter_map(|param| {
                                        match &param.pattern.kind {
                                            BindingPatternKind::BindingIdentifier(ident) => {
                                                let param_name = ident.name.to_string();
                                                let symbol_id = symbol_table.add_symbol(
                                                    param_name.clone(),
                                                    SymbolKind::Parameter,
                                                    function_scope,
                                                );
                                                dbg_eprintln!("[DEBUG] Exported function param: {} (SymbolId({}))", param_name, symbol_id.0);
                                                Some(Parameter {
                                                    name: param_name,
                                                    symbol_id,
                                                })
                                            }
                                            _ => None,
                                        }
                                    })
                                    .collect();
                                dbg_eprintln!("[DEBUG] Exported function '{}' has {} params", function_name, params.len());
                                
                                // Lower function body
                                let mut blocks = Vec::new();
                                let mut instructions: Vec<AInstruction> = Vec::new();

                                let next_block_id = 0u32;
                                let entry_block_id = BlockId(next_block_id);
                                
                                if let Some(body) = &func_decl.body {
                                    dbg_eprintln!("[DEBUG] Exported function body has {} statements", body.statements.len());
                                    
                                    // First, scan for arrow functions in return statements and extract them
                                    for stmt in &body.statements {
                                        if let Statement::ReturnStatement(ret_stmt) = stmt {
                                            if let Some(Expression::ArrowFunctionExpression(arrow_fn)) = &ret_stmt.argument {
                                                if !arrow_fn.body.statements.is_empty() {
                                                    dbg_eprintln!("[DEBUG] Extracting arrow function from return statement");
                                                    
                                                    // Create function scope for arrow function
                                                    let arrow_scope = ScopeId(*next_scope_id);
                                                    *next_scope_id += 1;
                                                    
                                                    // Extract parameters
                                                    let arrow_params: Vec<Parameter> = arrow_fn.params.items.iter()
                                                        .filter_map(|param| {
                                                            match &param.pattern.kind {
                                                                BindingPatternKind::BindingIdentifier(ident) => {
                                                                    let param_name = ident.name.to_string();
                                                                    let symbol_id = symbol_table.add_symbol(
                                                                        param_name.clone(),
                                                                        SymbolKind::Parameter,
                                                                        arrow_scope,
                                                                    );
                                                                    Some(Parameter {
                                                                        name: param_name,
                                                                        symbol_id,
                                                                    })
                                                                }
                                                                _ => None,
                                                            }
                                                        })
                                                        .collect();
                                                    
                                                    // Process arrow function body
                                                    let mut arrow_instructions: Vec<AInstruction> = Vec::new();
                                                    scope_stack.push(arrow_scope);
                                                    lower_statements(
                                                        &arrow_fn.body.statements,
                                                        &mut arrow_instructions,
                                                        symbol_table,
                                                        scope_stack,
                                                        next_scope_id,
                                                        source,
                                                        file_path,
                                                    );
                                                    scope_stack.pop();
                                                    
                                                    // Create arrow function and add to functions list
                                                    let arrow_entry_block = BlockId(0);
                                                    let mut arrow_blocks = Vec::new();
                                                    arrow_blocks.push(BasicBlock {
                                                        id: arrow_entry_block,
                                                        instructions: arrow_instructions,
                                                    });
                                                    
                                                    // Use the parent function name as the base for the arrow function
                                                    let arrow_fn_name = format!("{}_return_arrow", function_name);
                                                    functions.push(Function {
                                                        name: arrow_fn_name,
                                                        params: arrow_params,
                                                        blocks: arrow_blocks,
                                                        entry_block: arrow_entry_block,
                                                        scope_id: arrow_scope,
                                                    });
                                                    dbg_eprintln!("[DEBUG] Added extracted arrow function to functions list");
                                                }
                                            }
                                        }
                                    }
                                    
                                    // Now process the parent function normally
                                    lower_statements(
                                        &body.statements,
                                        &mut instructions,
                                        symbol_table,
                                        scope_stack,
                                        next_scope_id,
                                        source,
                                        file_path,
                                    );
                                } else {
                                    dbg_eprintln!("[DEBUG] Exported function body is None");
                                }
                                
                                blocks.push(BasicBlock {
                                    id: entry_block_id,
                                    instructions,
                                });
                                
                                functions.push(Function {
                                    name: function_name,
                                    params,
                                    blocks,
                                    entry_block: entry_block_id,
                                    scope_id: function_scope,
                                });
                                
                                scope_stack.pop();
                            }
                        }
                    }
                    _ => {}
                }
            }
            Statement::Declaration(Declaration::FunctionDeclaration(func_decl)) => {
                dbg_eprintln!("[DEBUG] Found FunctionDeclaration");
                if let Some(binding_identifier) = &func_decl.id {
                    let function_name = binding_identifier.name.to_string();
                    
                    // Create function scope
                    let function_scope = ScopeId(*next_scope_id);
                    *next_scope_id += 1;
                    scope_stack.push(function_scope);
                    
                    // Add function to symbol table
                    let _func_symbol_id = symbol_table.add_symbol(
                        function_name.clone(),
                        SymbolKind::Function,
                        scope_stack[scope_stack.len() - 2], // Parent scope
                    );
                    
                    // Process parameters
                    let params = func_decl.params.items.iter()
                        .filter_map(|param| {
                            match &param.pattern.kind {
                                BindingPatternKind::BindingIdentifier(ident) => {
                                    let param_name = ident.name.to_string();
                                    let symbol_id = symbol_table.add_symbol(
                                        param_name.clone(),
                                        SymbolKind::Parameter,
                                        function_scope,
                                    );
                                    Some(Parameter {
                                        name: param_name,
                                        symbol_id,
                                    })
                                }
                                _ => None,
                            }
                        })
                        .collect();
                    
                    // Lower function body
                    let mut blocks = Vec::new();
                    let mut instructions: Vec<AInstruction> = Vec::new();

                    //@TODO: Make next_block_id mutable once we have multiple blocks
                    let next_block_id = 0u32;
                    let entry_block_id = BlockId(next_block_id);
                    // @TODO: Only increment when you actually create another block
                    //next_block_id += 1;

                    
                    if let Some(body) = &func_decl.body {
                        lower_statements(
                            &body.statements,
                            &mut instructions,
                            symbol_table,
                            scope_stack,
                            next_scope_id,
                            source,
                            file_path,
                        );
                    }
                    
                    blocks.push(BasicBlock {
                        id: entry_block_id,
                        instructions,
                    });
                    
                    
                    functions.push(Function {
                        name: function_name,
                        params,
                        blocks,
                        entry_block: entry_block_id,
                        scope_id: function_scope,
                    });
                    
                    
                    scope_stack.pop();
                }
            }
            Statement::Declaration(Declaration::VariableDeclaration(var_decl)) => {
                // Handle arrow functions in variable declarations
                functions.extend(process_variable_declaration_arrow_functions(
                    var_decl,
                    symbol_table,
                    scope_stack,
                    next_scope_id,
                    source,
                    file_path,
                ));
            }
            Statement::ModuleDeclaration(module_decl) => {
                match &**module_decl {
                    ModuleDeclaration::ExportNamedDeclaration(export_decl) => {
                        // Handle exported variable declarations with arrow functions
                        // e.g., export const register = async (req, res) => { ... }
                        if let Some(declaration) = &export_decl.declaration {
                            match declaration {
                                Declaration::VariableDeclaration(var_decl) => {
                                    functions.extend(process_variable_declaration_arrow_functions(
                                        var_decl,
                                        symbol_table,
                                        scope_stack,
                                        next_scope_id,
                                        source,
                                        file_path,
                                    ));
                                }
                                Declaration::FunctionDeclaration(func_decl) => {
                                    // Handle exported function declarations
                                    if let Some(binding_identifier) = &func_decl.id {
                                        let function_name = binding_identifier.name.to_string();
                                        
                                        // Create function scope
                                        let function_scope = ScopeId(*next_scope_id);
                                        *next_scope_id += 1;
                                        scope_stack.push(function_scope);
                                        
                                        // Add function to symbol table
                                        let _func_symbol_id = symbol_table.add_symbol(
                                            function_name.clone(),
                                            SymbolKind::Function,
                                            scope_stack[scope_stack.len() - 2],
                                        );
                                        
                                        // Process parameters
                                        let params = func_decl.params.items.iter()
                                            .filter_map(|param| {
                                                match &param.pattern.kind {
                                                    BindingPatternKind::BindingIdentifier(ident) => {
                                                        let param_name = ident.name.to_string();
                                                        let symbol_id = symbol_table.add_symbol(
                                                            param_name.clone(),
                                                            SymbolKind::Parameter,
                                                            function_scope,
                                                        );
                                                        Some(Parameter {
                                                            name: param_name,
                                                            symbol_id,
                                                        })
                                                    }
                                                    _ => None,
                                                }
                                            })
                                            .collect();
                                        
                                        // Lower function body
                                        let mut blocks = Vec::new();
                                        let mut instructions = Vec::new();

                                        //@TODO: Make next_block_id mutable once we have multiple blocks
                                        let next_block_id = 0u32;
                                        let entry_block_id = BlockId(next_block_id);
                                        // @TODO: Only increment when you actually create another block
                                        //next_block_id += 1;

                                        if let Some(body) = &func_decl.body {
                                            lower_statements(
                                                &body.statements,
                                                &mut instructions,
                                                symbol_table,
                                                scope_stack,
                                                next_scope_id,
                                                source,
                                                file_path,
                                            );
                                        }
                                        
                                        blocks.push(BasicBlock {
                                            id: entry_block_id,
                                            instructions,
                                        });
                                        
                                        
                                        functions.push(Function {
                                            name: function_name,
                                            params,
                                            blocks,
                                            entry_block: entry_block_id,
                                            scope_id: function_scope,
                                        });
                                        
                                        
                                        scope_stack.pop();
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    functions
}

/// Lower statements to instructions
fn lower_statements(
    statements: &oxc_allocator::Vec<'_, Statement<'_>>,
    instructions: &mut Vec<AInstruction>,
    symbol_table: &mut SymbolTable,
    scope_stack: &mut Vec<ScopeId>,
    _next_scope_id: &mut u32,
    source: &str,
    file_path: &str,
) {
    dbg_eprintln!("[DEBUG] lower_statements: processing {} statements", statements.len());
    for (idx, stmt) in statements.iter().enumerate() {
        dbg_eprintln!("[DEBUG]   Statement {}: type={:?}", idx, stmt);
        match stmt {
            Statement::Declaration(Declaration::VariableDeclaration(var_decl)) => {
                dbg_eprintln!("[DEBUG] Processing VariableDeclaration with {} declarators", var_decl.declarations.len());
                for declarator in &var_decl.declarations {
                    dbg_eprintln!("[DEBUG] Processing declarator: init={}", declarator.init.is_some());
                    dbg_eprintln!("[DEBUG] Declarator id kind: {:?}", &declarator.id.kind);
                    if let Some(init) = &declarator.init {
                        let dst_name = match &declarator.id.kind {
                            BindingPatternKind::BindingIdentifier(ident) => {
                                dbg_eprintln!("[DEBUG] Found BindingIdentifier: {}", ident.name);
                                ident.name.to_string()
                            }
                            _ => {
                                dbg_eprintln!("[DEBUG] Skipping non-BindingIdentifier pattern");
                                continue;
                            }
                        };
                        
                        dbg_eprintln!("[DEBUG] Creating assignment for variable: {}", dst_name);
                        
                        // Add variable to symbol table
                        let current_scope = *scope_stack.last().unwrap();
                        let symbol_id = symbol_table.add_symbol(
                            dst_name.clone(),
                            SymbolKind::Variable,
                            current_scope,
                        );
                        
                        let src = normalize_expression(init, symbol_table, scope_stack, source, file_path);
                        let span = declarator.id.span();
                        instructions.push(annotate_instr_with_location(Instruction::Assign {
                            dst: symbol_id,
                            src,
                        }, Some(span), file_path, source));
                    }
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                let normalized = normalize_expression(&expr_stmt.expression, symbol_table, scope_stack, source, file_path);
                let span = expr_stmt.expression.span();
                
                // If it's a call, emit as Call instruction
                if let Expr::Call { callee, args } = normalized.node {
                    instructions.push(annotate_instr_with_location(Instruction::Call {
                        callee: *callee,
                        args,
                    }, Some(span), file_path, source));
                } else {
                    // Other expressions are evaluated but result is discarded
                    // Could emit as side-effect instruction if needed
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                // Check if the return value is an arrow function with a body (not just expression)
                if let Some(expr) = &ret_stmt.argument {
                    if let Expression::ArrowFunctionExpression(arrow_fn) = expr {
                        // arrow_fn.body is a Box<FunctionBody>, not Option
                        let body = &arrow_fn.body;
                        if !body.statements.is_empty() {
                            dbg_eprintln!("[DEBUG] Found arrow function in return with {} body statements", body.statements.len());
                            // Create a new scope for the arrow function
                            let arrow_scope = ScopeId(*_next_scope_id);
                            *_next_scope_id += 1;
                            scope_stack.push(arrow_scope);
                            
                            // Add parameters to symbol table AND to the function's params
                            let mut arrow_params = Vec::new();
                            for param in &arrow_fn.params.items {
                                if let BindingPatternKind::BindingIdentifier(ident) = &param.pattern.kind {
                                    let param_name = ident.name.to_string();
                                    dbg_eprintln!("[DEBUG]   Arrow function parameter: {}", param_name);
                                    let symbol_id = symbol_table.add_symbol(
                                        param_name.clone(),
                                        SymbolKind::Parameter,
                                        arrow_scope,
                                    );
                                    // Also add to the function's params list
                                    arrow_params.push(vk_ir::Parameter {
                                        name: param_name,
                                        symbol_id,
                                    });
                                }
                            }
                            
                            // Process the body statements
                            lower_statements(&body.statements, instructions, symbol_table, scope_stack, _next_scope_id, source, file_path);
                            
                            scope_stack.pop();
                        }
                    }
                }
                
                let value = ret_stmt.argument.as_ref()
                    .map(|expr| normalize_expression(expr, symbol_table, scope_stack, source, file_path));
                let span = ret_stmt.span;
                instructions.push(annotate_instr_with_location(Instruction::Return { value }, Some(span), file_path, source));
            }
            Statement::IfStatement(if_stmt) => {
                dbg_eprintln!("[DEBUG]   Processing IfStatement");
                // Process the condition
                let _condition = normalize_expression(&if_stmt.test, symbol_table, scope_stack, source, file_path);
                
                // Process the consequent (then block)
                match &if_stmt.consequent {
                    Statement::BlockStatement(block) => {
                        dbg_eprintln!("[DEBUG]     Processing if-consequent block with {} statements", block.body.len());
                        lower_statements(&block.body, instructions, symbol_table, scope_stack, _next_scope_id, source, file_path);
                    }
                    _ => {
                        // Single statement in if
                        dbg_eprintln!("[DEBUG]     Processing if-consequent single statement");
                        match &if_stmt.consequent {
                            Statement::ExpressionStatement(expr_stmt) => {
                                let normalized = normalize_expression(&expr_stmt.expression, symbol_table, scope_stack, source, file_path);
                                let span = expr_stmt.expression.span();
                                if let Expr::Call { callee, args } = normalized.node {
                                    instructions.push(annotate_instr_with_location(Instruction::Call {
                                        callee: *callee,
                                        args,
                                    }, Some(span), file_path, source));
                                }
                            }
                            Statement::ReturnStatement(ret_stmt) => {
                                let value = ret_stmt.argument.as_ref()
                                    .map(|expr| normalize_expression(expr, symbol_table, scope_stack, source, file_path));
                                let span = ret_stmt.span;
                                instructions.push(annotate_instr_with_location(Instruction::Return { value }, Some(span), file_path, source));
                            }
                            _ => {}
                        }
                    }
                }
                
                // Process the alternate (else block) if present
                if let Some(alternate) = &if_stmt.alternate {
                    dbg_eprintln!("[DEBUG]     Processing if-alternate block");
                    match alternate {
                        Statement::BlockStatement(block) => {
                            dbg_eprintln!("[DEBUG]     Processing else-block with {} statements", block.body.len());
                            lower_statements(&block.body, instructions, symbol_table, scope_stack, _next_scope_id, source, file_path);
                        }
                        _ => {
                            // Single statement else
                        }
                    }
                }
            }
            Statement::BlockStatement(block_stmt) => {
                dbg_eprintln!("[DEBUG]   Processing BlockStatement with {} statements", block_stmt.body.len());
                lower_statements(&block_stmt.body, instructions, symbol_table, scope_stack, _next_scope_id, source, file_path);
            }
            _ => {
                dbg_eprintln!("[DEBUG]   Unhandled statement type: {:?}", std::mem::discriminant(stmt));
                // Other statements can be added later
            }
        }
    }
}

/// Normalize OXC AST expression to IR Expr (does not expose parser internals)
fn normalize_expression(
    expr: &Expression<'_>,
    symbol_table: &mut SymbolTable,
    scope_stack: &[ScopeId],
    source: &str,
    file_path: &str,
) -> AExpr {
    let span = expr.span();
    match expr {
        Expression::CallExpression(call_expr) => {
            let callee = Box::new(normalize_expression(&call_expr.callee, symbol_table, scope_stack, source, file_path));
            let args: Vec<AExpr> = call_expr.arguments.iter()
                .map(|arg| {
                    match arg {
                        Argument::Expression(expr) => normalize_expression(expr, symbol_table, scope_stack, source, file_path),
                        _ => annotate_expr_with_location(Expr::Literal(Value::Undefined), None, file_path, source),
                    }
                })
                .collect();
            
            annotate_expr_with_location(Expr::Call { callee, args }, Some(span), file_path, source)
        }
        Expression::MemberExpression(member_expr) => {
            match &**member_expr {
                MemberExpression::StaticMemberExpression(static_member) => {
                    let obj = Box::new(normalize_expression(&static_member.object, symbol_table, scope_stack, source, file_path));
                    let prop = static_member.property.name.to_string();
                    annotate_expr_with_location(Expr::Member { obj, prop }, Some(span), file_path, source)
                }
                MemberExpression::ComputedMemberExpression(computed_member) => {
                    // For computed members, we'll simplify to just the object
                    // Full support can be added later
                    normalize_expression(&computed_member.object, symbol_table, scope_stack, source, file_path)
                }
                MemberExpression::PrivateFieldExpression(_) => {
                    // Private field access - simplified for now
                    annotate_expr_with_location(Expr::Literal(Value::Undefined), Some(span), file_path, source)
                }
            }
        }
        Expression::Identifier(ident) => {
            let name = ident.name.to_string();
            let ident_span = ident.span;
            annotate_expr_with_location(Expr::Identifier(name), Some(ident_span), file_path, source)
        }
        Expression::StringLiteral(lit) => {
            annotate_expr_with_location(Expr::Literal(Value::String(lit.value.to_string())), Some(span), file_path, source)
        }
        Expression::NumericLiteral(lit) => {
            annotate_expr_with_location(Expr::Literal(Value::Number(lit.value)), Some(span), file_path, source)
        }
        Expression::BooleanLiteral(lit) => {
            annotate_expr_with_location(Expr::Literal(Value::Boolean(lit.value)), Some(span), file_path, source)
        }
        Expression::NullLiteral(_) => {
            annotate_expr_with_location(Expr::Literal(Value::Null), Some(span), file_path, source)
        }
        Expression::ObjectExpression(_obj_expr) => {
            // Object literals - simplified to just a literal for now
            annotate_expr_with_location(Expr::Literal(Value::Null), Some(span), file_path, source)
        }
        Expression::ArrayExpression(_) => {
            annotate_expr_with_location(Expr::Literal(Value::Null), Some(span), file_path, source)
        }
        Expression::BinaryExpression(bin_expr) => {
            // Normalize both sides recursively
            let left = Box::new(normalize_expression(
                &bin_expr.left,
                symbol_table,
                scope_stack,
                source,
                file_path,
            ));
            let right = Box::new(normalize_expression(
                &bin_expr.right,
                symbol_table,
                scope_stack,
                source,
                file_path,
            ));
        
            // Use Concat for all binary ops for now to track string concatenation in taint analysis
            let op = BinaryOp::Concat;
        
            // Annotate the binary node with location for full traceability
            let binary_node = Expr::Binary {
                op,
                left: left.clone(),
                right: right.clone(),
            };
        
            annotate_expr_with_location(binary_node, Some(span), file_path, source)
        }
        
        Expression::UnaryExpression(unary_expr) => {
            normalize_expression(&unary_expr.argument, symbol_table, scope_stack, source, file_path)
        }
        Expression::ConditionalExpression(cond_expr) => {
            // Ternary - return test expression for now
            normalize_expression(&cond_expr.test, symbol_table, scope_stack, source, file_path)
        }
        Expression::AssignmentExpression(assign_expr) => {
            // Assignment - normalize right side
            normalize_expression(&assign_expr.right, symbol_table, scope_stack, source, file_path)
        }
        Expression::NewExpression(new_expr) => {
            // New expression - treat as call
            let callee = Box::new(normalize_expression(&new_expr.callee, symbol_table, scope_stack, source, file_path));
            let args: Vec<AExpr> = new_expr.arguments.iter()
                .map(|arg| {
                    match arg {
                        Argument::Expression(expr) => normalize_expression(expr, symbol_table, scope_stack, source, file_path),
                        _ => annotate_expr_with_location(Expr::Literal(Value::Undefined), None, file_path, source),
                    }
                })
                .collect();
            annotate_expr_with_location(Expr::Call { callee, args }, Some(span), file_path, source)
        }
        Expression::TemplateLiteral(tpl) => {
            let mut parts: Vec<AExpr> = Vec::new();
        
            let quasis = &tpl.quasis;
            let exprs = &tpl.expressions;
        
            for i in 0..quasis.len() {
                // Add literal part
                if let Some(lit_value) = &quasis[i].value.cooked {
                    if !lit_value.is_empty() {
                        parts.push(annotate_expr_with_location(
                            Expr::Literal(Value::String(lit_value.to_string())),
                            Some(quasis[i].span),
                            file_path,
                            source,
                        ));
                    }
                }
        
                // Add interpolated expression if exists
                if i < exprs.len() {
                    let normalized_expr = normalize_expression(&exprs[i], symbol_table, scope_stack, source, file_path);
                    parts.push(normalized_expr);
                }
            }
        
            // Build Binary(Concat) chain
            if parts.is_empty() {
                annotate_expr_with_location(Expr::Literal(Value::String(String::new())), Some(span), file_path, source)
            } else if parts.len() == 1 {
                parts.into_iter().next().unwrap()
            } else {
                let mut result = Box::new(parts[0].clone());
                for part in &parts[1..] {
                    result = Box::new(annotate_expr_with_location(
                        Expr::Binary {
                            op: BinaryOp::Concat,
                            left: result,
                            right: Box::new(part.clone()),
                        },
                        Some(span),
                        file_path,
                        source,
                    ));
                }
                (*result).clone()
            }
        }
        
        
        Expression::LogicalExpression(logical_expr) => {
            // Logical expressions (||, &&) - normalize both sides for taint tracking
            // For taint analysis, we need to track both sides since either could be tainted
            let left = Box::new(normalize_expression(
                &logical_expr.left,
                symbol_table,
                scope_stack,
                source,
                file_path,
            ));
            let right = Box::new(normalize_expression(
                &logical_expr.right,
                symbol_table,
                scope_stack,
                source,
                file_path,
            ));
            
            // Use Binary with Concat to track taint from both sides
            // The taint_of_expr function will merge taint from both left and right
            // For || and &&, we need to track taint from both operands
            annotate_expr_with_location(
                Expr::Binary {
                    op: BinaryOp::Concat, // Use Concat for taint merging
                    left,
                    right,
                },
                Some(span),
                file_path,
                source,
            )
        }
        Expression::ArrowFunctionExpression(_) => {
            // Arrow functions in expressions - simplified
            annotate_expr_with_location(Expr::Literal(Value::Null), Some(span), file_path, source)
        }
        Expression::FunctionExpression(_) => {
            annotate_expr_with_location(Expr::Literal(Value::Null), Some(span), file_path, source)
        }
        _ => {
            // Unknown expression type - return undefined
            annotate_expr_with_location(Expr::Literal(Value::Undefined), Some(span), file_path, source)
        }
    }
}

/// Resolve import path (handles relative paths, path aliases, etc.)
fn resolve_import_path(import_source: &str, current_file: &str) -> String {
    // Handle relative imports
    if import_source.starts_with('.') {
        if current_file.is_empty() {
            return import_source.to_string();
        }
        
        // Simple relative path resolution
        let current_dir = Path::new(current_file)
            .parent()
            .unwrap_or(Path::new("."));
        
        let resolved = current_dir.join(import_source);
        resolved.to_string_lossy().to_string()
    } else {
        // Absolute or node_modules import
        import_source.to_string()
    }
}
