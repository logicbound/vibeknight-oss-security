use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{Span, SourceType};

use vk_ir::{FileIr, IrNode, IrNodeKind, NodeTag, SourceLocation, shannon_entropy};

use crate::resolver::RequireResolver;

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse a JS/TS source file and emit all behavioural IR nodes.
pub fn analyse_file(source: &str, file_path: &str) -> FileIr {
    let source_type = detect_source_type(file_path);
    // The allocator and program MUST be co-located so their shared 'a lifetime
    // stays bounded within a single function scope — this prevents OXC's
    // arena lifetime from escaping into the caller.
    let nodes = parse_and_walk(source, file_path, source_type);
    FileIr { file: file_path.to_string(), nodes }
}

fn parse_and_walk(source: &str, file_path: &str, source_type: SourceType) -> Vec<IrNode> {
    let allocator = Allocator::default();
    let program = Parser::new(&allocator, source, source_type).parse().program;

    // SAFETY: oxc_allocator::Box<'a, T> is invariant over 'a, which prevents the
    // borrow checker from accepting short-lived borrows of the arena-allocated AST.
    // We transmute the body reference to 'static to bypass this limitation.
    // The transmuted reference is never stored anywhere that outlives this function,
    // and the allocator (which owns the memory) remains alive for the entire call.
    let body: &'static oxc_allocator::Vec<'static, Statement<'static>> =
        unsafe { std::mem::transmute(&program.body) };

    // Pass 1 — collect require/import bindings
    let mut resolver = RequireResolver::new();
    for stmt in body.iter() {
        resolver.collect_stmt(stmt);
    }

    // Pass 2 — walk for behavioural patterns
    let mut nodes: Vec<IrNode> = Vec::new();
    let mut current_fn: Option<String> = None;
    walk_stmts(body, &resolver, file_path, source, &mut nodes, &mut current_fn);

    nodes
    // transmuted refs go out of scope; program and allocator drop here
}

fn detect_source_type(path: &str) -> SourceType {
    let mut st = SourceType::default();
    if path.ends_with(".ts") || path.ends_with(".tsx") {
        st = st.with_typescript(true);
        st = st.with_jsx(path.ends_with(".tsx"));
    } else {
        st = st.with_jsx(path.ends_with(".jsx"));
    }
    st.with_module(true)
}

// ── Walking — free functions to avoid OXC arena lifetime conflicts ────────────

fn walk_stmts<'a>(
    stmts: &'a oxc_allocator::Vec<'a, Statement<'a>>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    for stmt in stmts.iter() {
        walk_stmt(stmt, resolver, file, source, nodes, current_fn);
    }
}

fn walk_stmt<'a>(
    stmt: &'a Statement<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    match stmt {
        Statement::Declaration(decl) => {
            walk_decl(decl, resolver, file, source, nodes, current_fn);
        }
        Statement::ExpressionStatement(es) => {
            walk_expr(&es.expression, resolver, file, source, nodes, current_fn);
        }
        Statement::BlockStatement(b) => {
            walk_stmts(&b.body, resolver, file, source, nodes, current_fn);
        }
        Statement::IfStatement(if_stmt) => {
            walk_stmt(&if_stmt.consequent, resolver, file, source, nodes, current_fn);
            if let Some(alt) = &if_stmt.alternate {
                walk_stmt(alt, resolver, file, source, nodes, current_fn);
            }
        }
        Statement::TryStatement(try_stmt) => {
            walk_stmts(&try_stmt.block.body, resolver, file, source, nodes, current_fn);
            if let Some(handler) = &try_stmt.handler {
                walk_stmts(&handler.body.body, resolver, file, source, nodes, current_fn);
            }
            if let Some(fin) = &try_stmt.finalizer {
                walk_stmts(&fin.body, resolver, file, source, nodes, current_fn);
            }
        }
        Statement::ReturnStatement(ret) => {
            if let Some(arg) = &ret.argument {
                walk_expr(arg, resolver, file, source, nodes, current_fn);
            }
        }
        Statement::WhileStatement(w) => {
            walk_stmt(&w.body, resolver, file, source, nodes, current_fn);
        }
        Statement::ForStatement(f) => {
            walk_stmt(&f.body, resolver, file, source, nodes, current_fn);
        }
        Statement::ForInStatement(f) => {
            walk_stmt(&f.body, resolver, file, source, nodes, current_fn);
        }
        Statement::ForOfStatement(f) => {
            walk_stmt(&f.body, resolver, file, source, nodes, current_fn);
        }
        Statement::SwitchStatement(sw) => {
            for case in sw.cases.iter() {
                for s in case.consequent.iter() {
                    walk_stmt(s, resolver, file, source, nodes, current_fn);
                }
            }
        }
        _ => {}
    }
}

fn walk_decl<'a>(
    decl: &'a Declaration<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    match decl {
        Declaration::FunctionDeclaration(func) => {
            let name = func.id.as_ref().map(|id| id.name.as_str());
            if let Some(body) = &func.body {
                walk_fn_body(name, body, resolver, file, source, nodes, current_fn);
            }
        }
        Declaration::VariableDeclaration(var_decl) => {
            for d in var_decl.declarations.iter() {
                if let Some(init) = &d.init {
                    match init {
                        Expression::FunctionExpression(func) => {
                            let name = func.id.as_ref()
                                .map(|id| id.name.as_str())
                                .or_else(|| binding_ident_name(&d.id));
                            if let Some(body) = &func.body {
                                walk_fn_body(name, body, resolver, file, source, nodes, current_fn);
                            }
                        }
                        Expression::ArrowFunctionExpression(arrow) => {
                            let name = binding_ident_name(&d.id);
                            walk_fn_body(name, &arrow.body, resolver, file, source, nodes, current_fn);
                        }
                        other => {
                            walk_expr(other, resolver, file, source, nodes, current_fn);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn walk_fn_body<'a>(
    name: Option<&str>,
    body: &'a FunctionBody<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    let loc = span_to_loc(body.span, file, source);
    nodes.push(IrNode::new(
        IrNodeKind::Function { name: name.map(str::to_string) },
        loc,
    ));
    let prev = current_fn.take();
    *current_fn = name.map(str::to_string);
    walk_stmts(&body.statements, resolver, file, source, nodes, current_fn);
    *current_fn = prev;
}

fn walk_expr<'a>(
    expr: &'a Expression<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    match expr {
        Expression::CallExpression(call) => {
            handle_call(call, resolver, file, source, nodes, current_fn);
        }
        Expression::NewExpression(new_expr) => {
            handle_new(new_expr, resolver, file, source, nodes, current_fn);
        }
        Expression::AssignmentExpression(assign) => {
            walk_expr(&assign.right, resolver, file, source, nodes, current_fn);
        }
        Expression::LogicalExpression(log) => {
            walk_expr(&log.left, resolver, file, source, nodes, current_fn);
            walk_expr(&log.right, resolver, file, source, nodes, current_fn);
        }
        Expression::SequenceExpression(seq) => {
            for e in seq.expressions.iter() {
                walk_expr(e, resolver, file, source, nodes, current_fn);
            }
        }
        Expression::ConditionalExpression(cond) => {
            walk_expr(&cond.consequent, resolver, file, source, nodes, current_fn);
            walk_expr(&cond.alternate, resolver, file, source, nodes, current_fn);
        }
        Expression::ArrowFunctionExpression(arrow) => {
            walk_fn_body(None, &arrow.body, resolver, file, source, nodes, current_fn);
        }
        Expression::FunctionExpression(func) => {
            let name = func.id.as_ref().map(|id| id.name.as_str());
            if let Some(body) = &func.body {
                walk_fn_body(name, body, resolver, file, source, nodes, current_fn);
            }
        }
        _ => {}
    }
}

fn handle_call<'a>(
    call: &'a CallExpression<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    let span = call.span;

    // Dynamic import(): import('./payload.js')
    if let Expression::ImportExpression(imp) = &call.callee {
        let specifier = extract_string_arg(&imp.source);
        nodes.push(IrNode::new(IrNodeKind::DynamicImport { specifier }, span_to_loc(span, file, source)));
        return;
    }

    // require(someVar) — obfuscated loader
    if is_dynamic_require(&call.callee, &call.arguments) {
        nodes.push(IrNode::new(IrNodeKind::ObfuscatedFlow, span_to_loc(span, file, source)));
        return;
    }

    // Encoded string patterns: Buffer.from(x, 'base64') / atob(x)
    if let Some(encoding) = detect_encoded_call(call) {
        let value = extract_string_arg_at(&call.arguments, 0).unwrap_or_default();
        let mut extra_tags = vec![];
        if shannon_entropy(&value) > 4.5 {
            extra_tags.push(NodeTag::HighEntropyString);
        }
        nodes.push(IrNode::with_tags(
            IrNodeKind::EncodedString { encoding, value },
            span_to_loc(span, file, source),
            extra_tags,
        ));
        return;
    }

    // Resolve callee through the binding table
    let (identity, is_dynamic_callee) = match resolver.resolve_callee(&call.callee) {
        Some(rc) => {
            let dynamic = matches!(rc, crate::resolver::ResolvedCallee::Dynamic);
            (rc.as_str().to_string(), dynamic)
        }
        None => {
            for arg in call.arguments.iter() {
                if let Argument::Expression(e) = arg {
                    walk_expr(e, resolver, file, source, nodes, current_fn);
                }
            }
            return;
        }
    };

    // Emit a Call node (used by call graph builder)
    let call_node = if is_dynamic_callee {
        IrNode::with_tags(
            IrNodeKind::Call { callee: identity.clone() },
            span_to_loc(span, file, source),
            vec![NodeTag::ObfuscatedContext],
        )
    } else {
        IrNode::new(
            IrNodeKind::Call { callee: identity.clone() },
            span_to_loc(span, file, source),
        )
    };
    nodes.push(call_node);

    // Classify into a behavioural pattern
    if let Some(kind) = classify_call(&identity, &call.arguments) {
        let extra_tags = if is_dynamic_callee {
            vec![NodeTag::ObfuscatedContext]
        } else {
            vec![]
        };
        nodes.push(IrNode::with_tags(kind, span_to_loc(span, file, source), extra_tags));
    }

    // Walk arguments for nested calls
    for arg in call.arguments.iter() {
        if let Argument::Expression(e) = arg {
            walk_expr(e, resolver, file, source, nodes, current_fn);
        }
    }
}

fn handle_new<'a>(
    new_expr: &'a NewExpression<'a>,
    resolver: &RequireResolver,
    file: &str,
    source: &str,
    nodes: &mut Vec<IrNode>,
    current_fn: &mut Option<String>,
) {
    let span = new_expr.span;
    if let Expression::Identifier(id) = &new_expr.callee {
        if id.name == "Function" {
            let body = extract_string_arg_at(&new_expr.arguments, 0);
            nodes.push(IrNode::new(IrNodeKind::FunctionConstructor { body }, span_to_loc(span, file, source)));
            return;
        }
    }
    for arg in new_expr.arguments.iter() {
        if let Argument::Expression(e) = arg {
            walk_expr(e, resolver, file, source, nodes, current_fn);
        }
    }
}

// ── Pattern tables ────────────────────────────────────────────────────────────

fn classify_call<'a>(
    identity: &str,
    args: &'a oxc_allocator::Vec<'a, Argument<'a>>,
) -> Option<IrNodeKind> {
    if matches_any(identity, &[
        "child_process.exec",    "child_process.execSync",
        "child_process.execFile","child_process.execFileSync",
        "child_process.spawn",   "child_process.spawnSync",
    ]) {
        return Some(IrNodeKind::ProcessExec { command: extract_string_arg_at(args, 0) });
    }
    if matches_any(identity, &[
        "http.get", "http.request", "https.get", "https.request",
        "fetch", "node-fetch",
        "axios", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete",
        "got", "got.get", "got.post",
        "superagent.get", "superagent.post",
    ]) {
        return Some(IrNodeKind::NetworkRequest { url: extract_string_arg_at(args, 0) });
    }
    if matches_any(identity, &["fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs/promises.readFile"]) {
        return Some(IrNodeKind::FileRead { path: extract_string_arg_at(args, 0) });
    }
    if matches_any(identity, &[
        "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
        "fs.createWriteStream", "fs/promises.writeFile",
    ]) {
        return Some(IrNodeKind::FileWrite { path: extract_string_arg_at(args, 0) });
    }
    if identity == "eval" {
        return Some(IrNodeKind::Eval { raw_arg: extract_string_arg_at(args, 0) });
    }
    None
}

fn matches_any(identity: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|&p| identity == p)
}

// ── Argument extraction ───────────────────────────────────────────────────────

fn extract_string_arg(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::StringLiteral(lit) => Some(lit.value.to_string()),
        Expression::TemplateLiteral(tpl) if tpl.expressions.is_empty() => {
            tpl.quasis.first()
                .and_then(|q| q.value.cooked.as_ref())
                .map(|s| s.to_string())
        }
        _ => None,
    }
}

fn extract_string_arg_at<'a>(
    args: &'a oxc_allocator::Vec<'a, Argument<'a>>,
    idx: usize,
) -> Option<String> {
    match args.get(idx) {
        Some(Argument::Expression(e)) => extract_string_arg(e),
        _ => None,
    }
}

// ── Encoded-string detection ──────────────────────────────────────────────────

fn detect_encoded_call<'a>(call: &'a CallExpression<'a>) -> Option<String> {
    if let Expression::Identifier(id) = &call.callee {
        if id.name == "atob" || id.name == "btoa" {
            return Some("base64".to_string());
        }
    }
    if let Expression::MemberExpression(me) = &call.callee {
        if let MemberExpression::StaticMemberExpression(sme) = &**me {
            if let Expression::Identifier(obj) = &sme.object {
                if obj.name == "Buffer" && sme.property.name == "from" {
                    if let Some(enc) = extract_string_arg_at(&call.arguments, 1) {
                        if matches!(enc.as_str(), "base64" | "hex" | "binary") {
                            return Some(enc);
                        }
                    }
                }
            }
        }
    }
    None
}

// ── Dynamic require detection ─────────────────────────────────────────────────

fn is_dynamic_require<'a>(callee: &'a Expression<'a>, args: &'a oxc_allocator::Vec<'a, Argument<'a>>) -> bool {
    if !matches!(callee, Expression::Identifier(id) if id.name == "require") {
        return false;
    }
    match args.first() {
        Some(Argument::Expression(Expression::StringLiteral(_))) => false,
        Some(Argument::Expression(Expression::TemplateLiteral(tpl))) => !tpl.expressions.is_empty(),
        _ => true,
    }
}

// ── Span → location ───────────────────────────────────────────────────────────

fn span_to_loc(span: Span, file: &str, source: &str) -> SourceLocation {
    let start = span.start as usize;
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, ch) in source.char_indices() {
        if i >= start { break; }
        if ch == '\n' { line += 1; col = 1; } else { col += 1; }
    }
    SourceLocation { file: file.to_string(), line, col }
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn binding_ident_name<'a>(pat: &'a BindingPattern<'a>) -> Option<&'a str> {
    if let BindingPatternKind::BindingIdentifier(ident) = &pat.kind {
        Some(ident.name.as_str())
    } else {
        None
    }
}
