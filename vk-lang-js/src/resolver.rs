use std::collections::HashMap;
use oxc_ast::ast::*;

/// The fully-qualified identity of a resolved binding.
///
/// Examples:
///   `const cp = require('child_process')`  → `Resolved("child_process")`
///   `const { exec } = require('child_process')` → `Resolved("child_process.exec")`
///   `const exec = require('child_process').exec` → `Resolved("child_process.exec")`
///   `require(someVar)` → `Dynamic`
///   `const exec = someLocalFn` where `someLocalFn` is a function expression → `Shadow`
#[derive(Debug, Clone, PartialEq)]
pub enum Binding {
    /// A statically resolved module binding: "child_process", "child_process.exec", etc.
    Resolved(String),
    /// A dynamic/computed binding — cannot be statically determined.
    Dynamic,
    /// A local function definition that shadows a potential module name.
    /// Calls to this name are not attributed to a module; not flagged as obfuscated.
    Shadow,
}

/// Tracks `require()` / ESM `import` bindings within a single file.
///
/// After a pass over all statements with [`RequireResolver::collect`], use
/// [`RequireResolver::resolve_callee`] to turn any call expression's callee
/// into a canonical identity string (e.g. `"child_process.exec"`).
#[derive(Debug, Default)]
pub struct RequireResolver {
    /// Maps local variable name → module binding.
    bindings: HashMap<String, Binding>,
}

impl RequireResolver {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Collection pass ───────────────────────────────────────────────────────

    /// Record bindings from a single top-level statement.
    pub fn collect_stmt(&mut self, stmt: &Statement<'_>) {
        self.collect_stmt_inner(stmt);
    }

    fn collect_stmt_inner(&mut self, stmt: &Statement<'_>) {
        match stmt {
            // ESM: import cp from 'child_process'
            // ESM: import { exec } from 'child_process'
            Statement::ModuleDeclaration(md) => {
                if let ModuleDeclaration::ImportDeclaration(decl) = &**md {
                    let source = decl.source.value.as_str().to_string();
                    if let Some(specs) = &decl.specifiers {
                        for spec in specs.iter() {
                            match spec {
                                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                                    self.bindings.insert(
                                        s.local.name.to_string(),
                                        Binding::Resolved(source.clone()),
                                    );
                                }
                                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                                    self.bindings.insert(
                                        s.local.name.to_string(),
                                        Binding::Resolved(source.clone()),
                                    );
                                }
                                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                                    let imported = match &s.imported {
                                        ModuleExportName::Identifier(i) => i.name.to_string(),
                                        ModuleExportName::StringLiteral(l) => l.value.to_string(),
                                    };
                                    self.bindings.insert(
                                        s.local.name.to_string(),
                                        Binding::Resolved(format!("{}.{}", source, imported)),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // CJS: const x = require('...') and variants
            Statement::Declaration(Declaration::VariableDeclaration(var_decl)) => {
                for decl in var_decl.declarations.iter() {
                    self.collect_declarator(decl);
                }
            }

            // Reassignment: exec = wrap(exec)
            // Downgrade any Resolved binding to Dynamic if the name is reassigned.
            Statement::ExpressionStatement(es) => {
                if let Expression::AssignmentExpression(assign) = &es.expression {
                    if let AssignmentTarget::SimpleAssignmentTarget(
                        SimpleAssignmentTarget::AssignmentTargetIdentifier(ident)
                    ) = &assign.left {
                        let name = ident.name.as_str();
                        if matches!(self.bindings.get(name), Some(Binding::Resolved(_))) {
                            self.bindings.insert(name.to_string(), Binding::Dynamic);
                        }
                    }
                }
            }

            _ => {}
        }
    }

    fn collect_declarator(&mut self, decl: &VariableDeclarator<'_>) {
        let Some(init) = &decl.init else { return };

        // Shadow: local function definition — track so resolve_callee returns None
        match init {
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
                if let BindingPatternKind::BindingIdentifier(ident) = &decl.id.kind {
                    self.bindings.insert(ident.name.to_string(), Binding::Shadow);
                }
                return;
            }
            _ => {}
        }

        match extract_require(init) {
            // const x = require('module')
            Some(RequireResult::Module(module)) => {
                match &decl.id.kind {
                    BindingPatternKind::BindingIdentifier(ident) => {
                        // const cp = require('child_process') → cp → child_process
                        self.bindings.insert(
                            ident.name.to_string(),
                            Binding::Resolved(module),
                        );
                    }
                    BindingPatternKind::ObjectPattern(obj) => {
                        // const { exec, spawn } = require('child_process')
                        for prop in obj.properties.iter() {
                            if let Some(local) = binding_prop_local(prop) {
                                let key = binding_prop_key(prop).unwrap_or_else(|| local.clone());
                                self.bindings.insert(
                                    local,
                                    Binding::Resolved(format!("{}.{}", module, key)),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }

            // const x = require('module').method
            Some(RequireResult::Member(module, method)) => {
                if let BindingPatternKind::BindingIdentifier(ident) = &decl.id.kind {
                    // const exec = require('child_process').exec
                    self.bindings.insert(
                        ident.name.to_string(),
                        Binding::Resolved(format!("{}.{}", module, method)),
                    );
                }
            }

            // const x = require(someVariable)
            Some(RequireResult::Dynamic) => {
                if let BindingPatternKind::BindingIdentifier(ident) = &decl.id.kind {
                    self.bindings.insert(ident.name.to_string(), Binding::Dynamic);
                }
            }

            None => {
                // 2a. Deep alias chain: const b = a where a is already known
                if let Expression::Identifier(ref_ident) = init {
                    if let Some(existing) = self.bindings.get(ref_ident.name.as_str()).cloned() {
                        if let BindingPatternKind::BindingIdentifier(id) = &decl.id.kind {
                            self.bindings.insert(id.name.to_string(), existing);
                        }
                    }
                }
            }
        }
    }

    // ── Resolution ────────────────────────────────────────────────────────────

    /// Resolve a call expression's callee to a canonical module identity string.
    ///
    /// Returns an owned `String` so callers don't need to wrangle the resolver's
    /// internal lifetime.
    pub fn resolve_callee(&self, callee: &Expression<'_>) -> Option<ResolvedCallee> {
        match callee {
            // Bare identifier call: exec(...) or eval(...)
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();
                // Well-known globals that never go through require
                if matches!(name, "eval" | "fetch" | "atob" | "btoa") {
                    return Some(ResolvedCallee::Global(name.to_string()));
                }
                match self.bindings.get(name) {
                    Some(Binding::Resolved(id)) => Some(ResolvedCallee::Bound(id.clone())),
                    Some(Binding::Dynamic)      => Some(ResolvedCallee::Dynamic),
                    Some(Binding::Shadow)       => None,  // local fn, not a module call
                    None                        => None,
                }
            }

            // Member expression: cp.exec(...) or cp['exec'](...)
            Expression::MemberExpression(me) => {
                // 2b. Inline require(...)[method](...): require('child_process')['exec'](...)
                match &**me {
                    MemberExpression::StaticMemberExpression(sme) => {
                        if let Some(RequireResult::Module(module)) = extract_require(&sme.object) {
                            let method = sme.property.name.to_string();
                            return Some(ResolvedCallee::Bound(format!("{}.{}", module, method)));
                        }
                    }
                    MemberExpression::ComputedMemberExpression(cme) => {
                        if let Some(RequireResult::Module(module)) = extract_require(&cme.object) {
                            if let Expression::StringLiteral(key) = &cme.expression {
                                return Some(ResolvedCallee::Bound(
                                    format!("{}.{}", module, key.value)
                                ));
                            }
                        }
                    }
                    _ => {}
                }

                // Regular identifier-based member expression
                let (obj_name, prop) = extract_member(me)?;
                match self.bindings.get(obj_name) {
                    Some(Binding::Resolved(module)) => {
                        Some(ResolvedCallee::Bound(format!("{}.{}", module, prop)))
                    }
                    Some(Binding::Dynamic) => Some(ResolvedCallee::Dynamic),
                    Some(Binding::Shadow)  => None,
                    None => None,
                }
            }

            _ => None,
        }
    }
}

// ── Resolved callee ───────────────────────────────────────────────────────────

/// The result of resolving a call expression's callee.
#[derive(Debug)]
pub enum ResolvedCallee {
    /// A known global (eval, fetch) that doesn't come through require.
    Global(String),
    /// A statically resolved binding identity (e.g. "child_process.exec").
    Bound(String),
    /// A dynamic/obfuscated binding.
    Dynamic,
}

impl ResolvedCallee {
    pub fn as_str(&self) -> &str {
        match self {
            ResolvedCallee::Global(s) => s.as_str(),
            ResolvedCallee::Bound(s)  => s.as_str(),
            ResolvedCallee::Dynamic   => "<dynamic>",
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

enum RequireResult {
    Module(String),
    Member(String, String),
    Dynamic,
}

fn extract_require(expr: &Expression<'_>) -> Option<RequireResult> {
    match expr {
        // require('...')
        Expression::CallExpression(call) => {
            if is_require_callee(&call.callee) {
                return Some(match call.arguments.first() {
                    Some(Argument::Expression(Expression::StringLiteral(lit))) => {
                        RequireResult::Module(lit.value.to_string())
                    }
                    Some(_) => RequireResult::Dynamic,
                    None    => RequireResult::Dynamic,
                });
            }
            None
        }

        // require('...').method
        Expression::MemberExpression(me) => {
            match &**me {
                MemberExpression::StaticMemberExpression(sme) => {
                    if let Some(RequireResult::Module(module)) = extract_require(&sme.object) {
                        return Some(RequireResult::Member(module, sme.property.name.to_string()));
                    }
                }
                MemberExpression::ComputedMemberExpression(cme) => {
                    if let Some(RequireResult::Module(module)) = extract_require(&cme.object) {
                        if let Expression::StringLiteral(lit) = &cme.expression {
                            return Some(RequireResult::Member(module, lit.value.to_string()));
                        }
                    }
                }
                _ => {}
            }
            None
        }

        _ => None,
    }
}

fn is_require_callee(callee: &Expression<'_>) -> bool {
    matches!(callee, Expression::Identifier(id) if id.name == "require")
}

fn extract_member<'a>(me: &'a MemberExpression<'_>) -> Option<(&'a str, String)> {
    match me {
        MemberExpression::StaticMemberExpression(sme) => {
            if let Expression::Identifier(obj) = &sme.object {
                return Some((obj.name.as_str(), sme.property.name.to_string()));
            }
            None
        }
        MemberExpression::ComputedMemberExpression(cme) => {
            if let Expression::Identifier(obj) = &cme.object {
                if let Expression::StringLiteral(key) = &cme.expression {
                    return Some((obj.name.as_str(), key.value.to_string()));
                }
            }
            None
        }
        _ => None,
    }
}

fn binding_prop_local(prop: &BindingProperty<'_>) -> Option<String> {
    if let BindingPatternKind::BindingIdentifier(ident) = &prop.value.kind {
        Some(ident.name.to_string())
    } else {
        None
    }
}

fn binding_prop_key(prop: &BindingProperty<'_>) -> Option<String> {
    match &prop.key {
        PropertyKey::Identifier(ident) => Some(ident.name.to_string()),
        // PropertyKey::Expression / other variants — fall through to None
        _ => None,
    }
}
