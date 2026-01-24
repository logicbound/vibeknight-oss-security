use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_ast::ast::*;
use std::path::Path;
use vk_ir::{
    Program, Module, Function, BasicBlock, Instruction, Expr, Value,
    Import, ImportSpecifier, Export, ExportSpecifier,
    SymbolTable, ScopeId, SymbolKind, Parameter,
    ModuleGraph, BlockId, Annotated, AExpr, AInstruction, Metadata, TaintState,
};

/// Helper to create annotated expression with default metadata
fn annotate_expr(expr: Expr) -> AExpr {
    Annotated {
        node: expr,
        meta: Metadata {
            source: None,
            symbol: None,
            taint: TaintState::Unknown,
            tags: std::collections::HashMap::new(),
        },
    }
}

/// Helper to create annotated instruction with default metadata
fn annotate_instr(instr: Instruction) -> AInstruction {
    Annotated {
        node: instr,
        meta: Metadata {
            source: None,
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
    let source_type = SourceType::default();
    let parser = Parser::new(&allocator, source, source_type);
    let program = parser.parse().program;

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
) -> Vec<Function> {
    let mut functions = Vec::new();

    for stmt in body {
        match stmt {
            Statement::Declaration(Declaration::FunctionDeclaration(func_decl)) => {
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
) {
    for stmt in statements {
        match stmt {
            Statement::Declaration(Declaration::VariableDeclaration(var_decl)) => {
                for declarator in &var_decl.declarations {
                    if let Some(init) = &declarator.init {
                        let dst_name = match &declarator.id.kind {
                            BindingPatternKind::BindingIdentifier(ident) => {
                                ident.name.to_string()
                            }
                            _ => continue,
                        };
                        
                        // Add variable to symbol table
                        let current_scope = *scope_stack.last().unwrap();
                        let symbol_id = symbol_table.add_symbol(
                            dst_name.clone(),
                            SymbolKind::Variable,
                            current_scope,
                        );
                        
                        let src = normalize_expression(init, symbol_table, scope_stack);
                        instructions.push(annotate_instr(Instruction::Assign {
                            dst: symbol_id,
                            src,
                        }));
                    }
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                let normalized = normalize_expression(&expr_stmt.expression, symbol_table, scope_stack);
                
                // If it's a call, emit as Call instruction
                if let Expr::Call { callee, args } = normalized.node {
                    instructions.push(annotate_instr(Instruction::Call {
                        callee: *callee,
                        args,
                    }));
                } else {
                    // Other expressions are evaluated but result is discarded
                    // Could emit as side-effect instruction if needed
                }
            }
            Statement::ReturnStatement(ret_stmt) => {
                let value = ret_stmt.argument.as_ref()
                    .map(|expr| normalize_expression(expr, symbol_table, scope_stack));
                instructions.push(annotate_instr(Instruction::Return { value }));
            }
            _ => {
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
) -> AExpr {
    match expr {
        Expression::CallExpression(call_expr) => {
            let callee = Box::new(normalize_expression(&call_expr.callee, symbol_table, scope_stack));
            let args: Vec<AExpr> = call_expr.arguments.iter()
                .map(|arg| {
                    match arg {
                        Argument::Expression(expr) => normalize_expression(expr, symbol_table, scope_stack),
                        _ => annotate_expr(Expr::Literal(Value::Undefined)),
                    }
                })
                .collect();
            
            annotate_expr(Expr::Call { callee, args })
        }
        Expression::MemberExpression(member_expr) => {
            match &**member_expr {
                MemberExpression::StaticMemberExpression(static_member) => {
                    let obj = Box::new(normalize_expression(&static_member.object, symbol_table, scope_stack));
                    let prop = static_member.property.name.to_string();
                    annotate_expr(Expr::Member { obj, prop })
                }
                MemberExpression::ComputedMemberExpression(computed_member) => {
                    // For computed members, we'll simplify to just the object
                    // Full support can be added later
                    normalize_expression(&computed_member.object, symbol_table, scope_stack)
                }
                MemberExpression::PrivateFieldExpression(_) => {
                    // Private field access - simplified for now
                    annotate_expr(Expr::Literal(Value::Undefined))
                }
            }
        }
        Expression::Identifier(ident) => {
            let name = ident.name.to_string();
            
            // Try to resolve symbol (for closure/scope tracking)
            // For now, we'll just use the identifier name
            // Full symbol resolution can be enhanced later
            annotate_expr(Expr::Identifier(name))
        }
        Expression::StringLiteral(lit) => {
            annotate_expr(Expr::Literal(Value::String(lit.value.to_string())))
        }
        Expression::NumericLiteral(lit) => {
            annotate_expr(Expr::Literal(Value::Number(lit.value)))
        }
        Expression::BooleanLiteral(lit) => {
            annotate_expr(Expr::Literal(Value::Boolean(lit.value)))
        }
        Expression::NullLiteral(_) => {
            annotate_expr(Expr::Literal(Value::Null))
        }
        Expression::ObjectExpression(_obj_expr) => {
            // Object literals - simplified to just a literal for now
            annotate_expr(Expr::Literal(Value::Null))
        }
        Expression::ArrayExpression(_) => {
            annotate_expr(Expr::Literal(Value::Null))
        }
        Expression::BinaryExpression(bin_expr) => {
            // Binary expressions - normalize both sides
            // For now, return left side (can be enhanced)
            normalize_expression(&bin_expr.left, symbol_table, scope_stack)
        }
        Expression::UnaryExpression(unary_expr) => {
            normalize_expression(&unary_expr.argument, symbol_table, scope_stack)
        }
        Expression::ConditionalExpression(cond_expr) => {
            // Ternary - return test expression for now
            normalize_expression(&cond_expr.test, symbol_table, scope_stack)
        }
        Expression::AssignmentExpression(assign_expr) => {
            // Assignment - normalize right side
            normalize_expression(&assign_expr.right, symbol_table, scope_stack)
        }
        Expression::NewExpression(new_expr) => {
            // New expression - treat as call
            let callee = Box::new(normalize_expression(&new_expr.callee, symbol_table, scope_stack));
            let args: Vec<AExpr> = new_expr.arguments.iter()
                .map(|arg| {
                    match arg {
                        Argument::Expression(expr) => normalize_expression(expr, symbol_table, scope_stack),
                        _ => annotate_expr(Expr::Literal(Value::Undefined)),
                    }
                })
                .collect();
            annotate_expr(Expr::Call { callee, args })
        }
        Expression::TemplateLiteral(_) => {
            annotate_expr(Expr::Literal(Value::String(String::new())))
        }
        Expression::ArrowFunctionExpression(_) => {
            // Arrow functions in expressions - simplified
            annotate_expr(Expr::Literal(Value::Null))
        }
        Expression::FunctionExpression(_) => {
            annotate_expr(Expr::Literal(Value::Null))
        }
        _ => {
            // Unknown expression type - return undefined
            annotate_expr(Expr::Literal(Value::Undefined))
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
