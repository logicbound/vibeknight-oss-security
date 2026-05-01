use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{Span, SourceType};
use oxc_syntax::operator::BinaryOperator;

use vk_ir::{DataSource, FileIr, IrNode, IrNodeKind, NodeTag, SourceLocation, shannon_entropy};

use crate::resolver::{RequireResolver, ResolvedCallee};

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

    // Pass 2 — walk for behavioural patterns, threading a live assignment map
    let mut ctx = WalkCtx {
        resolver: &resolver,
        file: file_path,
        source,
        nodes: Vec::new(),
        assignments: HashMap::new(),
        current_fn: None,
        current_fn_id: None,
    };
    walk_stmts(body, &mut ctx);

    ctx.nodes
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

// ── Walk context ──────────────────────────────────────────────────────────────

/// Per-file walk state. Held as a single struct so we can cleanly thread both
/// the resolver (immutable) and the live assignment map (mutable) through the
/// recursive walk without fighting the borrow checker.
struct WalkCtx<'r> {
    resolver: &'r RequireResolver,
    file: &'r str,
    source: &'r str,
    nodes: Vec<IrNode>,
    /// Local 1-hop assignment map: `name → DataSource` for the most recent
    /// assignment visible at the current walk position. This is the taint map.
    assignments: HashMap<String, DataSource>,
    current_fn: Option<String>,
    /// Node id of the currently enclosing `Function` IR node, if any.
    current_fn_id: Option<String>,
}

impl WalkCtx<'_> {
    /// Push a node, stamping `parent_fn_id` from the current scope.
    fn push(&mut self, node: IrNode) {
        let scoped = node.with_parent_fn(self.current_fn_id.clone());
        self.nodes.push(scoped);
    }
}

// ── Walking ───────────────────────────────────────────────────────────────────

fn walk_stmts<'a>(
    stmts: &'a oxc_allocator::Vec<'a, Statement<'a>>,
    ctx: &mut WalkCtx<'_>,
) {
    for stmt in stmts.iter() {
        walk_stmt(stmt, ctx);
    }
}

fn walk_stmt<'a>(stmt: &'a Statement<'a>, ctx: &mut WalkCtx<'_>) {
    match stmt {
        Statement::Declaration(decl) => {
            walk_decl(decl, ctx);
        }
        Statement::ExpressionStatement(es) => {
            walk_expr(&es.expression, ctx);
        }
        Statement::BlockStatement(b) => {
            walk_stmts(&b.body, ctx);
        }
        Statement::IfStatement(if_stmt) => {
            walk_stmt(&if_stmt.consequent, ctx);
            if let Some(alt) = &if_stmt.alternate {
                walk_stmt(alt, ctx);
            }
        }
        Statement::TryStatement(try_stmt) => {
            walk_stmts(&try_stmt.block.body, ctx);
            if let Some(handler) = &try_stmt.handler {
                walk_stmts(&handler.body.body, ctx);
            }
            if let Some(fin) = &try_stmt.finalizer {
                walk_stmts(&fin.body, ctx);
            }
        }
        Statement::ReturnStatement(ret) => {
            if let Some(arg) = &ret.argument {
                walk_expr(arg, ctx);
            }
        }
        Statement::WhileStatement(w) => walk_stmt(&w.body, ctx),
        Statement::ForStatement(f)   => walk_stmt(&f.body, ctx),
        Statement::ForInStatement(f) => walk_stmt(&f.body, ctx),
        Statement::ForOfStatement(f) => walk_stmt(&f.body, ctx),
        Statement::SwitchStatement(sw) => {
            for case in sw.cases.iter() {
                for s in case.consequent.iter() {
                    walk_stmt(s, ctx);
                }
            }
        }
        _ => {}
    }
}

fn walk_decl<'a>(decl: &'a Declaration<'a>, ctx: &mut WalkCtx<'_>) {
    match decl {
        Declaration::FunctionDeclaration(func) => {
            let name = func.id.as_ref().map(|id| id.name.as_str());
            if let Some(body) = &func.body {
                walk_fn_body(name, body, ctx);
            }
        }
        Declaration::VariableDeclaration(var_decl) => {
            for d in var_decl.declarations.iter() {
                // Record the assignment's data source BEFORE walking (so nested
                // sinks still emit nodes, but the name→source map reflects RHS).
                if let (BindingPatternKind::BindingIdentifier(ident), Some(init)) =
                    (&d.id.kind, &d.init)
                {
                    let ds = classify_expr(init, ctx.resolver, &ctx.assignments);
                    ctx.assignments.insert(ident.name.to_string(), ds);
                }

                if let Some(init) = &d.init {
                    match init {
                        Expression::FunctionExpression(func) => {
                            let name = func.id.as_ref()
                                .map(|id| id.name.as_str())
                                .or_else(|| binding_ident_name(&d.id));
                            if let Some(body) = &func.body {
                                walk_fn_body(name, body, ctx);
                            }
                        }
                        Expression::ArrowFunctionExpression(arrow) => {
                            let name = binding_ident_name(&d.id);
                            walk_fn_body(name, &arrow.body, ctx);
                        }
                        other => {
                            walk_expr(other, ctx);
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
    ctx: &mut WalkCtx<'_>,
) {
    let loc = span_to_loc(body.span, ctx.file, ctx.source);
    // Construct the Function node first so we can capture its id as the
    // new enclosing scope before walking children.
    let fn_node = IrNode::new(
        IrNodeKind::Function { name: name.map(str::to_string) },
        loc,
    )
    .with_parent_fn(ctx.current_fn_id.clone());
    let fn_id = fn_node.id.clone();
    ctx.nodes.push(fn_node);

    let prev_name = ctx.current_fn.take();
    let prev_id = ctx.current_fn_id.take();
    ctx.current_fn = name.map(str::to_string);
    ctx.current_fn_id = Some(fn_id);
    walk_stmts(&body.statements, ctx);
    ctx.current_fn = prev_name;
    ctx.current_fn_id = prev_id;
}

fn walk_expr<'a>(expr: &'a Expression<'a>, ctx: &mut WalkCtx<'_>) {
    match expr {
        Expression::CallExpression(call) => {
            handle_call(call, ctx);
        }
        Expression::NewExpression(new_expr) => {
            handle_new(new_expr, ctx);
        }
        Expression::AssignmentExpression(assign) => {
            // Track taint flow through `x = RHS`
            if let AssignmentTarget::SimpleAssignmentTarget(
                SimpleAssignmentTarget::AssignmentTargetIdentifier(ident)
            ) = &assign.left {
                let ds = classify_expr(&assign.right, ctx.resolver, &ctx.assignments);
                ctx.assignments.insert(ident.name.to_string(), ds);
            }
            walk_expr(&assign.right, ctx);
        }
        Expression::LogicalExpression(log) => {
            walk_expr(&log.left, ctx);
            walk_expr(&log.right, ctx);
        }
        Expression::SequenceExpression(seq) => {
            for e in seq.expressions.iter() {
                walk_expr(e, ctx);
            }
        }
        Expression::ConditionalExpression(cond) => {
            walk_expr(&cond.consequent, ctx);
            walk_expr(&cond.alternate, ctx);
        }
        Expression::ArrowFunctionExpression(arrow) => {
            walk_fn_body(None, &arrow.body, ctx);
        }
        Expression::FunctionExpression(func) => {
            let name = func.id.as_ref().map(|id| id.name.as_str());
            if let Some(body) = &func.body {
                walk_fn_body(name, body, ctx);
            }
        }
        Expression::AwaitExpression(aw) => {
            walk_expr(&aw.argument, ctx);
        }
        _ => {}
    }
}

fn handle_call<'a>(call: &'a CallExpression<'a>, ctx: &mut WalkCtx<'_>) {
    let span = call.span;

    // Dynamic import(): import('./payload.js')
    if let Expression::ImportExpression(imp) = &call.callee {
        let specifier = extract_string_arg(&imp.source);
        let arg_source = classify_expr(&imp.source, ctx.resolver, &ctx.assignments);
        ctx.push(IrNode::new(
            IrNodeKind::DynamicImport { specifier, arg_source },
            span_to_loc(span, ctx.file, ctx.source),
        ));
        return;
    }

    // require(someVar) — obfuscated loader
    if is_dynamic_require(&call.callee, &call.arguments) {
        ctx.push(IrNode::new(
            IrNodeKind::ObfuscatedFlow,
            span_to_loc(span, ctx.file, ctx.source),
        ));
        return;
    }

    // Encoded string patterns: Buffer.from(x, 'base64') / atob(x)
    if let Some(encoding) = detect_encoded_call(call) {
        let value = extract_string_arg_at(&call.arguments, 0).unwrap_or_default();
        let mut extra_tags = vec![];
        if shannon_entropy(&value) > 4.5 {
            extra_tags.push(NodeTag::HighEntropyString);
        }
        ctx.push(IrNode::with_tags(
            IrNodeKind::EncodedString { encoding, value },
            span_to_loc(span, ctx.file, ctx.source),
            extra_tags,
        ));
        return;
    }

    // Resolve callee through the binding table
    let (identity, is_dynamic_callee) = match ctx.resolver.resolve_callee(&call.callee) {
        Some(rc) => {
            let dynamic = matches!(rc, ResolvedCallee::Dynamic);
            (rc.as_str().to_string(), dynamic)
        }
        None => {
            for arg in call.arguments.iter() {
                if let Argument::Expression(e) = arg {
                    walk_expr(e, ctx);
                }
            }
            return;
        }
    };

    // Emit a Call node (used by call graph builder)
    let call_node = if is_dynamic_callee {
        IrNode::with_tags(
            IrNodeKind::Call { callee: identity.clone() },
            span_to_loc(span, ctx.file, ctx.source),
            vec![NodeTag::ObfuscatedContext],
        )
    } else {
        IrNode::new(
            IrNodeKind::Call { callee: identity.clone() },
            span_to_loc(span, ctx.file, ctx.source),
        )
    };
    ctx.push(call_node);

    // Classify into a behavioural sink pattern, attaching arg_source
    if let Some(kind) = classify_call(&identity, &call.arguments, ctx.resolver, &ctx.assignments) {
        let extra_tags = if is_dynamic_callee {
            vec![NodeTag::ObfuscatedContext]
        } else {
            vec![]
        };
        ctx.push(IrNode::with_tags(
            kind,
            span_to_loc(span, ctx.file, ctx.source),
            extra_tags,
        ));
    }

    // Walk arguments for nested calls
    for arg in call.arguments.iter() {
        if let Argument::Expression(e) = arg {
            walk_expr(e, ctx);
        }
    }
}

fn handle_new<'a>(new_expr: &'a NewExpression<'a>, ctx: &mut WalkCtx<'_>) {
    let span = new_expr.span;
    if let Expression::Identifier(id) = &new_expr.callee {
        if id.name == "Function" {
            let body = extract_string_arg_at(&new_expr.arguments, 0);
            let arg_source = arg_data_source_at(&new_expr.arguments, 0, ctx.resolver, &ctx.assignments);
            ctx.push(IrNode::new(
                IrNodeKind::FunctionConstructor { body, arg_source },
                span_to_loc(span, ctx.file, ctx.source),
            ));
            return;
        }
    }
    for arg in new_expr.arguments.iter() {
        if let Argument::Expression(e) = arg {
            walk_expr(e, ctx);
        }
    }
}

// ── Pattern tables ────────────────────────────────────────────────────────────

fn classify_call<'a>(
    identity: &str,
    args: &'a oxc_allocator::Vec<'a, Argument<'a>>,
    resolver: &RequireResolver,
    assignments: &HashMap<String, DataSource>,
) -> Option<IrNodeKind> {
    if is_process_exec(identity) {
        return Some(IrNodeKind::ProcessExec {
            command: extract_string_arg_at(args, 0),
            arg_source: arg_data_source_at(args, 0, resolver, assignments),
        });
    }
    if is_network_request(identity) {
        return Some(IrNodeKind::NetworkRequest {
            url: extract_string_arg_at(args, 0),
            arg_source: arg_data_source_at(args, 0, resolver, assignments),
        });
    }
    if matches_any(identity, &[
        "fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs/promises.readFile",
    ]) {
        return Some(IrNodeKind::FileRead {
            path: extract_string_arg_at(args, 0),
            arg_source: arg_data_source_at(args, 0, resolver, assignments),
        });
    }
    if matches_any(identity, &[
        "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
        "fs.createWriteStream", "fs/promises.writeFile",
    ]) {
        return Some(IrNodeKind::FileWrite {
            path: extract_string_arg_at(args, 0),
            arg_source: arg_data_source_at(args, 0, resolver, assignments),
        });
    }
    if identity == "eval" {
        return Some(IrNodeKind::Eval {
            raw_arg: extract_string_arg_at(args, 0),
            arg_source: arg_data_source_at(args, 0, resolver, assignments),
        });
    }
    None
}

fn is_process_exec(identity: &str) -> bool {
    matches_any(identity, &[
        "child_process.exec",     "child_process.execSync",
        "child_process.execFile", "child_process.execFileSync",
        "child_process.spawn",    "child_process.spawnSync",
    ])
}

fn is_network_request(identity: &str) -> bool {
    matches_any(identity, &[
        "http.get", "http.request", "https.get", "https.request",
        "fetch", "node-fetch",
        "axios", "axios.get", "axios.post", "axios.put", "axios.patch", "axios.delete",
        "got", "got.get", "got.post",
        "superagent.get", "superagent.post",
    ])
}

fn is_decoder_call(identity: &str) -> bool {
    matches!(identity, "atob" | "btoa")
}

fn is_fs_read_call(identity: &str) -> bool {
    matches_any(identity, &[
        "fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs/promises.readFile",
    ])
}

fn matches_any(identity: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|&p| identity == p)
}

// ── Data-source classification ────────────────────────────────────────────────

/// Classify the argument at `idx` as a `DataSource`.
fn arg_data_source_at<'a>(
    args: &'a oxc_allocator::Vec<'a, Argument<'a>>,
    idx: usize,
    resolver: &RequireResolver,
    assignments: &HashMap<String, DataSource>,
) -> DataSource {
    match args.get(idx) {
        Some(Argument::Expression(e)) => classify_expr(e, resolver, assignments),
        _ => DataSource::Unknown,
    }
}

/// Classify an arbitrary expression into a `DataSource` (argument provenance).
///
/// This is the taint classifier — it reads the current `assignments` map to
/// resolve identifier references 1-hop. Deeper analysis is intentionally not
/// attempted here; chain-level reasoning happens in `vk-core`.
fn classify_expr<'a>(
    expr: &'a Expression<'a>,
    resolver: &RequireResolver,
    assignments: &HashMap<String, DataSource>,
) -> DataSource {
    match expr {
        // "literal"
        Expression::StringLiteral(lit) => {
            DataSource::Literal { value: lit.value.to_string() }
        }
        // Numeric / boolean / null literals also count as literal (rare in sink args)
        Expression::NumericLiteral(lit) => {
            DataSource::Literal { value: lit.value.to_string() }
        }
        Expression::BooleanLiteral(lit) => {
            DataSource::Literal { value: lit.value.to_string() }
        }
        Expression::NullLiteral(_) => {
            DataSource::Literal { value: "null".to_string() }
        }

        // `abc` or `abc${x}`
        Expression::TemplateLiteral(tpl) => classify_template(tpl, resolver, assignments),

        // x
        Expression::Identifier(id) => {
            assignments
                .get(id.name.as_str())
                .cloned()
                .unwrap_or(DataSource::Unknown)
        }

        // process.env.X / process.argv / obj.field
        Expression::MemberExpression(me) => classify_member(me, resolver, assignments),

        // fn(...)
        Expression::CallExpression(call) => classify_call_result(call, resolver, assignments),

        // a + b
        Expression::BinaryExpression(be) if matches!(be.operator, BinaryOperator::Addition) => {
            DataSource::Concatenation {
                sources: vec![
                    classify_expr(&be.left, resolver, assignments),
                    classify_expr(&be.right, resolver, assignments),
                ],
            }
        }

        // (x)
        Expression::ParenthesizedExpression(p) => classify_expr(&p.expression, resolver, assignments),

        // x ?? y  or  a || b
        Expression::LogicalExpression(lg) => {
            DataSource::Concatenation {
                sources: vec![
                    classify_expr(&lg.left, resolver, assignments),
                    classify_expr(&lg.right, resolver, assignments),
                ],
            }
        }

        // cond ? a : b
        Expression::ConditionalExpression(cond) => {
            DataSource::Concatenation {
                sources: vec![
                    classify_expr(&cond.consequent, resolver, assignments),
                    classify_expr(&cond.alternate, resolver, assignments),
                ],
            }
        }

        // await fetch(...)
        Expression::AwaitExpression(aw) => classify_expr(&aw.argument, resolver, assignments),

        _ => DataSource::Unknown,
    }
}

fn classify_template<'a>(
    tpl: &'a TemplateLiteral<'a>,
    resolver: &RequireResolver,
    assignments: &HashMap<String, DataSource>,
) -> DataSource {
    if tpl.expressions.is_empty() {
        let segments: Vec<String> = tpl
            .quasis
            .iter()
            .filter_map(|q| q.value.cooked.as_ref().map(|s| s.to_string()))
            .collect();
        return DataSource::TemplateOnly { segments };
    }
    let mut sources: Vec<DataSource> = Vec::new();
    for q in tpl.quasis.iter() {
        if let Some(cooked) = q.value.cooked.as_ref() {
            if !cooked.is_empty() {
                sources.push(DataSource::Literal { value: cooked.to_string() });
            }
        }
    }
    for e in tpl.expressions.iter() {
        sources.push(classify_expr(e, resolver, assignments));
    }
    DataSource::Concatenation { sources }
}

/// Internal classification of `a.b` / `a.b.c` / `a.b[expr]` roots.
///
/// Kept private so it never leaks into the IR — callers always translate
/// these into real `DataSource` variants before returning.
enum MemberRoot {
    /// `process.env.NAME` (with known literal property name)
    ProcessEnvNamed(String),
    /// `process.env[dynamic]` or bare `process.env`
    ProcessEnvUnknown,
    /// `process.argv` or `process.argv[N]`
    ProcessArgv,
    /// None of the above
    Other,
}

fn classify_member<'a>(
    me: &'a oxc_allocator::Box<'a, MemberExpression<'a>>,
    resolver: &RequireResolver,
    assignments: &HashMap<String, DataSource>,
) -> DataSource {
    match member_root(me) {
        MemberRoot::ProcessEnvNamed(name) => DataSource::EnvVar { name: Some(name) },
        MemberRoot::ProcessEnvUnknown     => DataSource::EnvVar { name: None },
        MemberRoot::ProcessArgv           => DataSource::ProcessArgv,
        MemberRoot::Other => {
            // Fall back to the base object's provenance.
            match &**me {
                MemberExpression::StaticMemberExpression(sme) => {
                    classify_expr(&sme.object, resolver, assignments)
                }
                MemberExpression::ComputedMemberExpression(cme) => {
                    classify_expr(&cme.object, resolver, assignments)
                }
                _ => DataSource::Unknown,
            }
        }
    }
}

fn member_root<'a>(me: &'a oxc_allocator::Box<'a, MemberExpression<'a>>) -> MemberRoot {
    match &**me {
        MemberExpression::StaticMemberExpression(sme) => {
            // process.env, process.argv (bare)
            if is_ident(&sme.object, "process") {
                match sme.property.name.as_str() {
                    "env"  => return MemberRoot::ProcessEnvUnknown,
                    "argv" => return MemberRoot::ProcessArgv,
                    _ => {}
                }
            }
            // process.env.NAME
            if let Expression::MemberExpression(inner) = &sme.object {
                if let MemberExpression::StaticMemberExpression(inner_sme) = &**inner {
                    if is_ident(&inner_sme.object, "process") {
                        if inner_sme.property.name == "env" {
                            return MemberRoot::ProcessEnvNamed(sme.property.name.to_string());
                        }
                        if inner_sme.property.name == "argv" {
                            return MemberRoot::ProcessArgv;
                        }
                    }
                }
            }
            MemberRoot::Other
        }
        MemberExpression::ComputedMemberExpression(cme) => {
            if let Expression::MemberExpression(inner) = &cme.object {
                if let MemberExpression::StaticMemberExpression(inner_sme) = &**inner {
                    if is_ident(&inner_sme.object, "process") {
                        if inner_sme.property.name == "env" {
                            return MemberRoot::ProcessEnvUnknown;
                        }
                        if inner_sme.property.name == "argv" {
                            return MemberRoot::ProcessArgv;
                        }
                    }
                }
            }
            MemberRoot::Other
        }
        _ => MemberRoot::Other,
    }
}

fn classify_call_result<'a>(
    call: &'a CallExpression<'a>,
    resolver: &RequireResolver,
    _assignments: &HashMap<String, DataSource>,
) -> DataSource {
    // Handle encoded-string calls first
    if let Some(encoding) = detect_encoded_call(call) {
        return DataSource::Decoded {
            origin_node_id: None,
            encoding,
        };
    }

    // Resolve the callee
    let identity = match resolver.resolve_callee(&call.callee) {
        Some(rc) => rc.as_str().to_string(),
        None => return DataSource::Unknown,
    };

    if is_network_request(&identity) {
        return DataSource::NetworkResponse { origin_node_id: None };
    }
    if is_decoder_call(&identity) {
        return DataSource::Decoded { origin_node_id: None, encoding: "base64".to_string() };
    }
    if is_fs_read_call(&identity) {
        let path = extract_string_arg_at(&call.arguments, 0);
        return DataSource::FileReadResult { path };
    }

    DataSource::Unknown
}

fn is_ident<'a>(expr: &Expression<'a>, name: &str) -> bool {
    matches!(expr, Expression::Identifier(id) if id.name == name)
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
