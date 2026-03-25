use vk_ir::{Instruction, Expr};
use crate::rule::{Rule, Severity};
use crate::finding::{Finding, DataFlowPath, FixSuggestion};
use crate::context::AnalysisContext;
use crate::taint::{
    TaintPropagator, DataflowGraph, SinkDef, SanitizerDef,
};
use crate::taint::model::{Sink, Sanitizer, SinkPattern, SanitizerPattern, SanitizerMethod};
use crate::finding::extract_code_snippet;
use macros::dbg_eprintln;

/// SQL Injection detection rule using taint analysis
/// 
/// Detects when tainted user input reaches SQL query execution without sanitization
pub struct SqlInjectionRule {
    /// SQL-specific sink definitions
    sql_sinks: SinkDef,
    /// SQL-specific sanitizer definitions (safe patterns)
    sql_sanitizers: SanitizerDef,
}

impl SqlInjectionRule {
    pub fn new() -> Self {
        // Note: Patterns are now provided by the language frontend via AnalysisContext
        // This rule instance doesn't need to store patterns anymore
        Self {
            sql_sinks: SinkDef::new(), // Will be populated from context
            sql_sanitizers: SanitizerDef::new(), // Will be populated from context
        }
    }
    
    
    /// Add SQL injection sink patterns (DEPRECATED - kept for reference)
    #[allow(dead_code)]
    fn add_sql_sinks(sinks: &mut SinkDef) {
        // db.query(), connection.query()
        sinks.add(Sink {
            description: "SQL query execution via db.query()".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "db".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]), // First argument is the query string
            vuln_type: "sql-injection".to_string(),
        });
        
        sinks.add(Sink {
            description: "SQL query execution via connection.query()".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "connection".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
        
        // execute() methods
        sinks.add(Sink {
            description: "SQL query execution via execute()".to_string(),
            pattern: SinkPattern::FunctionName("execute".to_string()),
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
        
        // ORM raw queries
        sinks.add(Sink {
            description: "ORM raw query execution".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "sequelize".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
        
        sinks.add(Sink {
            description: "TypeORM raw query".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "queryRunner".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
        
        // Generic query() function
        sinks.add(Sink {
            description: "Generic query() function".to_string(),
            pattern: SinkPattern::FunctionName("query".to_string()),
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
    }
    
    /// Add safe SQL patterns (sanitizers) (DEPRECATED - kept for reference)
    #[allow(dead_code)]
    fn add_sql_sanitizers(sanitizers: &mut SanitizerDef) {
        // ONLY TRUE PARAMETERIZED QUERIES ARE SAFE
        
        // Sequelize with parameterized queries (not raw with interpolation)
        sanitizers.add(Sanitizer {
            description: "Sequelize query builder (safe - parameterized)".to_string(),
            pattern: SanitizerPattern::MethodCall {
                object: "sequelize".to_string(),
                method: "findAll".to_string(),
            },
            method: SanitizerMethod::ParameterizedQuery,
        });
        
        sanitizers.add(Sanitizer {
            description: "Sequelize findOne (safe - parameterized)".to_string(),
            pattern: SanitizerPattern::MethodCall {
                object: "sequelize".to_string(),
                method: "findOne".to_string(),
            },
            method: SanitizerMethod::ParameterizedQuery,
        });
        
        // TypeORM with parameterized queries
        sanitizers.add(Sanitizer {
            description: "TypeORM repository find (safe - parameterized)".to_string(),
            pattern: SanitizerPattern::MethodCall {
                object: "repository".to_string(),
                method: "find".to_string(),
            },
            method: SanitizerMethod::ParameterizedQuery,
        });
        
        // Knex query builder
        sanitizers.add(Sanitizer {
            description: "Knex select (safe - query builder)".to_string(),
            pattern: SanitizerPattern::MethodCall {
                object: "knex".to_string(),
                method: "select".to_string(),
            },
            method: SanitizerMethod::ParameterizedQuery,
        });
        
        // Known SQL escape functions
        sanitizers.add(Sanitizer {
            description: "MySQL escape function".to_string(),
            pattern: SanitizerPattern::FunctionName("escape".to_string()),
            method: SanitizerMethod::ParameterizedQuery,  // Use ParameterizedQuery as the closest match
        });
        
        // NOTE: We explicitly do NOT add:
        // - .match() as a sanitizer (it just filters, doesn't sanitize)
        // - Generic hash functions as sanitizers (they're not SQL-specific)
        // - db.prepare() unless it's actually being used with parameters
    }
    
    /// Extract query string from expression (for finding details)
    fn extract_query_string(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(name) => Some(name.clone()),
            Expr::Literal(_) => Some("(literal)".to_string()),
            Expr::Call { .. } => Some("(function call)".to_string()),
            Expr::Member { obj: _, prop } => Some(format!("(object.{})", prop)),
            Expr::Binary { .. } => Some("(binary expression)".to_string()),
        }
    }
}

impl Rule for SqlInjectionRule {
    fn id(&self) -> &'static str {
        "sql-injection"
    }
    
    fn name(&self) -> &'static str {
        "SQL Injection"
    }
    
    fn severity(&self) -> Severity {
        Severity::High
    }
    
    fn description(&self) -> &'static str {
        "Detects SQL injection vulnerabilities when tainted input reaches SQL query execution without sanitization"
    }
    
    fn detect(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Get language-specific patterns from context
        let sql_sinks = ctx.pattern_provider.sql_sinks();
        let sql_sanitizers = ctx.pattern_provider.sql_sanitizers();
        let sources = ctx.pattern_provider.taint_sources();
        
        // Create taint propagator with language-specific sinks and sanitizers
        let propagator = TaintPropagator::with_definitions(
            sources,
            sql_sinks.clone(),
            sql_sanitizers.clone(),
        );
        
        for module in &ctx.program.modules {
            dbg_eprintln!("[DEBUG] SQL Rule: Processing module with {} functions", module.functions.len());
            for (func_idx, function) in module.functions.iter().enumerate() {
                dbg_eprintln!("[DEBUG]   Function {}: name={}, params={}", func_idx, function.name, function.params.len());
            }
            for function in &module.functions {
                // Build dataflow graph for this function with symbol table
                let graph = DataflowGraph::build_for_function_with_symbols(function, Some(&module.symbols));
                
                // Debug: Print graph edges
                dbg_eprintln!("[DEBUG] Function: {}, Graph edges: {}", function.name, graph.edges().len());
                for edge in graph.edges() {
                    dbg_eprintln!("[DEBUG]   Edge: {:?} -> {:?}", edge.from, edge.to);
                }
                
                // Propagate taint through the function
                let taint_map = propagator.propagate(function, &graph);
                
                // Debug: Print taint map
                dbg_eprintln!("[DEBUG] Function: {}, Taint map size: {}", function.name, taint_map.len());
                for (symbol_id, taint) in &taint_map {
                    dbg_eprintln!("[DEBUG]   Symbol {}: {:?}", symbol_id.0, taint);
                }
                
                // Check for SQL sinks with tainted input
                for block in &function.blocks {
                    for instruction in &block.instructions {
                        // Handle both direct Call instructions and Return with Call expressions
                        match &instruction.node {
                            Instruction::Call { callee, args } => {
                                dbg_eprintln!("[DEBUG] Checking call in {}: {:?}", function.name, callee.node);
                                
                                // Recursively search for SQL sinks in nested expressions
                                let sql_sinks = ctx.pattern_provider.sql_sinks();
                                self.check_for_sql_sinks_recursive(
                                    &callee.node, args, &instruction, &taint_map, &module, ctx, &sql_sinks, &mut findings
                                );
                            }
                            Instruction::Return { value } => {
                                // Check if return value is a call expression
                                if let Some(ret_value) = value {
                                    if let Expr::Call { callee, args } = &ret_value.node {
                                        dbg_eprintln!("[DEBUG] Checking return call in {}: {:?}", function.name, callee.node);
                                        
                                        // Check if this is a SQL sink (get from context)
                                        let sql_sinks = ctx.pattern_provider.sql_sinks();
                                        if let Some(sink) = sql_sinks.find_sink(&callee.node) {
                                            dbg_eprintln!("[DEBUG] Found SQL sink in {}: {}", function.name, sink.description);
                                            
                                            if sink.vuln_type == "sql-injection" {
                                                // Check sensitive arguments
                                                let sensitive_indices = sink.sensitive_args.as_ref()
                                                    .map(|v| v.as_slice())
                                                    .unwrap_or(&[]);
                                                
                                                for (arg_idx, arg) in args.iter().enumerate() {
                                                    if sensitive_indices.is_empty() || sensitive_indices.contains(&arg_idx) {
                                                        self.check_argument_for_taint(
                                                            arg, arg_idx, sink, &callee.node, &instruction,
                                                            &taint_map, &module, ctx, &mut findings
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        
        findings
    }
}

impl SqlInjectionRule {
    /// Recursively search for SQL sinks in nested Call/Member expressions
    fn check_for_sql_sinks_recursive(
        &self,
        expr: &vk_ir::Expr,
        args: &[vk_ir::AExpr],
        instruction: &vk_ir::AInstruction,
        taint_map: &std::collections::HashMap<vk_ir::SymbolId, vk_ir::TaintState>,
        module: &vk_ir::Module,
        ctx: &AnalysisContext,
        sql_sinks: &SinkDef,
        findings: &mut Vec<Finding>,
    ) {
        use vk_ir::Expr;
        
        // Check if this expression itself is a SQL sink
        if let Some(sink) = sql_sinks.find_sink(expr) {
            dbg_eprintln!("[DEBUG] Found SQL sink: {}", sink.description);
            
            if sink.vuln_type == "sql-injection" {
                // Check sensitive arguments
                let sensitive_indices = sink.sensitive_args.as_ref()
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                
                for (arg_idx, arg) in args.iter().enumerate() {
                    if sensitive_indices.is_empty() || sensitive_indices.contains(&arg_idx) {
                        self.check_argument_for_taint(
                            arg, arg_idx, sink, expr, instruction,
                            taint_map, module, ctx, findings
                        );
                    }
                }
            }
        }
        
        // Recursively check nested expressions
        match expr {
            Expr::Member { obj, .. } => {
                // Check if the object is a Call expression (e.g., models.sequelize.query().then)
                if let Expr::Call { callee, args: nested_args } = &obj.node {
                    self.check_for_sql_sinks_recursive(
                        &callee.node, nested_args, instruction, taint_map, module, ctx, sql_sinks, findings
                    );
                } else {
                    // Also check if the object itself (which might be a nested Member) is a SQL sink
                    // This handles cases like: Member { obj: Member { obj: ..., prop: "sequelize" }, prop: "query" }
                    self.check_for_sql_sinks_recursive(
                        &obj.node, &[], instruction, taint_map, module, ctx, sql_sinks, findings
                    );
                }
            }
            Expr::Call { callee, args: nested_args } => {
                // Recursively check the callee
                self.check_for_sql_sinks_recursive(
                    &callee.node, nested_args, instruction, taint_map, module, ctx, sql_sinks, findings
                );
            }
            _ => {}
        }
    }

    fn check_argument_for_taint(
        &self,
        expr: &vk_ir::AExpr,
        _arg_idx: usize,
        _sink: &Sink,
        callee: &Expr,
        instruction: &vk_ir::AInstruction,
        taint_map: &std::collections::HashMap<vk_ir::SymbolId, vk_ir::TaintState>,
        module: &vk_ir::Module,
        ctx: &AnalysisContext,
        findings: &mut Vec<Finding>,
    ) {
        // --- Compute taint for this expression recursively ---
        dbg_eprintln!("[DEBUG] check_argument_for_taint: Checking argument expression");
        let expr_taint = self.taint_of_expr(expr, taint_map, module);
        dbg_eprintln!("[DEBUG] check_argument_for_taint: Expression taint result: {:?}", expr_taint);

        if expr_taint.is_tainted() && !expr_taint.is_sanitized() {
            let query_string = Self::extract_query_string(&expr.node)
                .unwrap_or_else(|| "(unknown)".to_string());

            let taint_kinds = expr_taint
                .kinds()
                .iter()
                .map(|k| k.as_str().to_string())
                .collect::<Vec<_>>();
            let taint_source_str = taint_kinds.join(", ");

            let callee_name = match callee {
                Expr::Identifier(name) => name.clone(),
                Expr::Member { obj: _, prop } => prop.clone(),
                _ => "unknown".to_string(),
            };

            let sink_location = instruction.meta.source.clone()
                .unwrap_or_else(|| vk_ir::SourceLocation {
                    file: ctx.file_path.clone(),
                    line: 1,
                    column: 1,
                });
            let source_location = expr.meta.source.clone().unwrap_or_else(|| sink_location.clone());
            let code_snippet = extract_code_snippet(&ctx.file_path, sink_location.line as usize, 3);

            let data_flow = DataFlowPath::simple(
                source_location.clone(),
                query_string.clone(),
                sink_location.clone(),
                format!("{}({})", callee_name, query_string),
                taint_kinds.clone(),
            );

            let fix = Self::create_sql_fix_suggestion(&callee_name, &query_string);

            let finding = Finding::new(
                self.id().to_string(),
                self.severity(),
                "SQL Injection: Tainted input reaches SQL sink".to_string(),
                format!(
                    "Tainted input ({}) reaches SQL sink {}(). Query: {}. This may allow SQL injection attacks.",
                    taint_source_str,
                    callee_name,
                    query_string
                ),
                ctx.file_path.clone(),
                sink_location.line as usize,
                sink_location.column as usize,
                code_snippet,
            )
            .with_data_flow(data_flow)
            .with_fix(fix);

            findings.push(finding);
        }

        // --- Recurse manually into children to propagate taint ---
        match &expr.node {
            Expr::Binary { left, right, .. } => {
                self.check_argument_for_taint(left, _arg_idx, _sink, callee, instruction, taint_map, module, ctx, findings);
                self.check_argument_for_taint(right, _arg_idx, _sink, callee, instruction, taint_map, module, ctx, findings);
            }
            Expr::Member { obj, .. } => {
                self.check_argument_for_taint(obj, _arg_idx, _sink, callee, instruction, taint_map, module, ctx, findings);
            }
            Expr::Call { callee: call_callee, args } => {
                self.check_argument_for_taint(call_callee, _arg_idx, _sink, callee, instruction, taint_map, module, ctx, findings);
                for arg in args {
                    self.check_argument_for_taint(arg, _arg_idx, _sink, callee, instruction, taint_map, module, ctx, findings);
                }
            }
            _ => {}
        }
    }

    /// Compute combined taint for an expression, propagating through Binary(Concat)
    fn taint_of_expr(
        &self,
        expr: &vk_ir::AExpr,
        taint_map: &std::collections::HashMap<vk_ir::SymbolId, vk_ir::TaintState>,
        module: &vk_ir::Module,
    ) -> vk_ir::TaintState {
        use vk_ir::Expr;

        dbg_eprintln!("[DEBUG] taint_of_expr: Checking expression type: {:?}", std::mem::discriminant(&expr.node));
        
        match &expr.node {
            Expr::Identifier(name) => {
                // Try to find symbol ID - check metadata first, then symbol table
                let symbol_ids = if let Some(symbol_id) = expr.meta.symbol {
                    dbg_eprintln!("[DEBUG] taint_of_expr: Identifier '{}' has symbol in metadata: {:?}", name, symbol_id);
                    vec![symbol_id]
                } else {
                    let found_ids = module.symbols.find_symbol_ids(name);
                    dbg_eprintln!("[DEBUG] taint_of_expr: Identifier '{}' found {} symbol IDs in table: {:?}", name, found_ids.len(), found_ids.iter().map(|id| id.0).collect::<Vec<_>>());
                    found_ids
                };
                
                // Check all symbol IDs to see if any are tainted
                // (There might be multiple symbols with the same name in different scopes)
                let mut result = vk_ir::TaintState::default();
                for symbol_id in &symbol_ids {
                    if let Some(taint) = taint_map.get(symbol_id) {
                        dbg_eprintln!("[DEBUG] taint_of_expr: Symbol {:?} is tainted: {:?}", symbol_id.0, taint);
                        result = result.merge(taint);
                    } else {
                        dbg_eprintln!("[DEBUG] taint_of_expr: Symbol {:?} not found in taint_map (map has {} entries)", symbol_id.0, taint_map.len());
                    }
                }
                if symbol_ids.is_empty() {
                    dbg_eprintln!("[DEBUG] taint_of_expr: No symbol IDs found for '{}'", name);
                }
                result
            }
            Expr::Member { obj, .. } => {
                // Recursively check the object (e.g., req.body.email -> check req)
                dbg_eprintln!("[DEBUG] taint_of_expr: Member expression, recursing into object");
                self.taint_of_expr(obj, taint_map, module)
            }
            Expr::Call { callee, args } => {
                // Check callee and all arguments recursively
                let mut result = self.taint_of_expr(callee, taint_map, module);
                for arg in args {
                    result = result.merge(&self.taint_of_expr(arg, taint_map, module));
                }
                result
            }
            Expr::Binary { left, right, .. } => {
                // Combine taint recursively from both sides
                dbg_eprintln!("[DEBUG] taint_of_expr: Binary expression, checking left and right");
                let left_taint = self.taint_of_expr(left, taint_map, module);
                let right_taint = self.taint_of_expr(right, taint_map, module);
                let merged = left_taint.merge(&right_taint);
                dbg_eprintln!("[DEBUG] taint_of_expr: Binary merged taint: {:?}", merged);
                merged
            }
            _ => vk_ir::TaintState::default(),
        }
    }



    
    /// Extract symbol ID from expression if it's an identifier
    fn extract_symbol_id_from_expr(
        expr: &vk_ir::AExpr,
        symbol_table: &vk_ir::SymbolTable,
    ) -> Option<vk_ir::SymbolId> {
        // First check if metadata already has a symbol
        if let Some(symbol_id) = expr.meta.symbol {
            return Some(symbol_id);
        }
    
        match &expr.node {
            // Identifier: try to find symbol in the table
            Expr::Identifier(name) => {
                symbol_table.find_symbol_ids(name).first().copied()
            }
    
            // Binary expression: recursively check left, then right
            Expr::Binary { left, right, .. } => {
                Self::extract_symbol_id_from_expr(left, symbol_table)
                    .or_else(|| Self::extract_symbol_id_from_expr(right, symbol_table))
            }
    
            // Member expression: recursively check the object
            Expr::Member { obj, .. } => Self::extract_symbol_id_from_expr(obj, symbol_table),
    
            // Call expression: recursively check callee, then args
            Expr::Call { callee, args } => {
                Self::extract_symbol_id_from_expr(callee, symbol_table)
                    .or_else(|| args.iter().find_map(|arg| Self::extract_symbol_id_from_expr(arg, symbol_table)))
            }
    
            // For all other expressions, return None
            _ => None,
        }
    }
    
    
    /// Check if expression is a direct source (not through variable)
    fn is_direct_source(expr: &vk_ir::AExpr) -> bool {
        // Check if expression itself matches source patterns
        // This is a simplified check - full implementation would use SourceDef
        match &expr.node {
            Expr::Identifier(name) => {
                // Mark 'req' parameter as a source
                // Also mark other common sources: process, document, window, fetch, etc.
                name == "req" || 
                name == "request" ||
                name == "process" ||
                name == "document" ||
                name == "window" ||
                name == "fetch"
            }
            Expr::Member { obj: _, prop } => {
                prop == "body" || prop == "query" || prop == "params" || 
                prop == "cookies" || prop == "headers" || prop == "email"
            }
            Expr::Call { callee, .. } => {
                // Function calls like security.hash() are NOT sanitizers
                // Only specific, known-safe functions should be considered sanitizers
                // For now, assume all function calls pass taint through
                match &callee.node {
                    Expr::Member { .. } => {
                        // These are NOT sanitizers for SQL:
                        // - .hash() - password hashing, not SQL escaping
                        // - .match() - regex filtering, incomplete
                        // - .substring() - just string manipulation
                        // - .slice() - just string manipulation
                        // Only consider true SQL sanitizers safe
                        false  // By default, function calls don't sanitize for SQL
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
    
    /// Create a fix suggestion for SQL injection
    fn create_sql_fix_suggestion(callee_name: &str, query_string: &str) -> FixSuggestion {
        // Determine the appropriate fix based on the callee
        let (before, after, explanation) = if callee_name == "query" {
            (
                format!("db.query('SELECT * FROM users WHERE id = {}', userId);", query_string),
                format!("db.query('SELECT * FROM users WHERE id = ?', [userId]);"),
                "Use parameterized queries with placeholders (?) instead of string concatenation. This prevents SQL injection by separating SQL code from data.".to_string(),
            )
        } else {
            (
                format!("{}(`SELECT * FROM users WHERE id = ${{}}`, userId);", callee_name),
                format!("{}(`SELECT * FROM users WHERE id = ?`, [userId]);", callee_name),
                "Use parameterized queries or query builders instead of string interpolation. This prevents SQL injection by separating SQL code from data.".to_string(),
            )
        };
        
        FixSuggestion::with_explanation(
            "Use parameterized queries or query builders".to_string(),
            before,
            after,
            explanation,
        )
    }
}

impl Default for SqlInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}
