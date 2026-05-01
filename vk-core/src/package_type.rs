//! Package-type classifier.
//!
//! Splits a package into one of `DevTool | Cli | RuntimeLib | Unknown` by
//! combining manifest priors (what `package.json` declares) with behavioural
//! priors (what the IR shows the code actually doing).
//!
//! This is the base-rate fix. A build-tool package like `better-sqlite3` or
//! anything using `node-gyp` will fire a large set of capability signals
//! (`ProcessExec`, `FileWrite`, `PostinstallExecution`) that look identical
//! to malware at the IR level. Classifying it as `DevTool` lets the composite
//! scorer apply a category-adjust to re-centre its base rate.
//!
//! Classification is deterministic and evidence-bearing: the returned
//! `PackageClassification` carries the reason for each contributing signal so
//! the OSINT/AI layer can see *why* it was classified that way.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vk_ir::{IrNode, IrNodeKind};

// ── Public enum ───────────────────────────────────────────────────────────────

/// The coarse-grained role a package plays in the npm ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageClass {
    /// Build tool / native-module installer. Uses `child_process`, writes to
    /// `build/`, `dist/`, or `*.node`, often runs postinstall scripts.
    DevTool,
    /// Command-line utility. Has a `bin` entry, reads `process.argv`, may
    /// import `commander`/`yargs`.
    Cli,
    /// Library meant to be imported by other packages. Exports a stable API,
    /// minimal module-scope side effects.
    RuntimeLib,
    /// Could not confidently classify.
    Unknown,
}

// ── Classification output ─────────────────────────────────────────────────────

/// The full classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageClassification {
    pub class: PackageClass,
    /// Weights for each class, for transparency and downstream ML/AI tuning.
    pub scores: HashMap<String, f32>,
    /// Human-readable evidence that backs the classification.
    pub evidence: Vec<ClassificationEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationEvidence {
    /// `"dev_tool"` / `"cli"` / `"runtime_lib"` — which class this supports.
    pub class: String,
    /// `"manifest.bin"`, `"deps.node-gyp"`, `"ir.process_argv_read"`, etc.
    pub source: String,
    /// Weight added.
    pub weight: f32,
    /// Short human description.
    pub detail: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Classify a package by combining manifest + behavioural (IR) priors.
pub fn classify_package(
    manifest: Option<&Value>,
    ir_nodes: &[IrNode],
) -> PackageClassification {
    let mut scores: HashMap<&'static str, f32> = HashMap::new();
    let mut evidence: Vec<ClassificationEvidence> = Vec::new();

    if let Some(manifest) = manifest {
        manifest_evidence(manifest, &mut scores, &mut evidence);
    }
    ir_evidence(ir_nodes, &mut scores, &mut evidence);

    // Pick the winner.
    let (class, winning_score) = scores
        .iter()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(k, v)| (*k, *v))
        .unwrap_or(("unknown", 0.0));

    // Be honest when the evidence is thin. The threshold is deliberately low
    // because RuntimeLib is the typical npm package shape (main + types +
    // keyword hints) and over-aggressive Unknown-classification would let
    // package-type adjustment miss the common case.
    let final_class = if winning_score < 0.30 {
        PackageClass::Unknown
    } else {
        match class {
            "dev_tool"    => PackageClass::DevTool,
            "cli"         => PackageClass::Cli,
            "runtime_lib" => PackageClass::RuntimeLib,
            _             => PackageClass::Unknown,
        }
    };

    // Serialise scores with String keys for JSON output.
    let out_scores: HashMap<String, f32> =
        scores.into_iter().map(|(k, v)| (k.to_string(), v)).collect();

    evidence.sort_by(|a, b| a.class.cmp(&b.class).then(a.source.cmp(&b.source)));

    PackageClassification {
        class: final_class,
        scores: out_scores,
        evidence,
    }
}

// ── Manifest-based priors ─────────────────────────────────────────────────────

fn manifest_evidence(
    manifest: &Value,
    scores: &mut HashMap<&'static str, f32>,
    evidence: &mut Vec<ClassificationEvidence>,
) {
    // `bin` → CLI prior
    match &manifest["bin"] {
        Value::String(_) | Value::Object(_) => {
            add(scores, "cli", 0.50);
            evidence.push(mk("cli", "manifest.bin", 0.50, "package declares a bin entry"));
        }
        _ => {}
    }

    // Keywords give weak hints both ways.
    if let Some(keywords) = manifest["keywords"].as_array() {
        for kw in keywords {
            let Some(s) = kw.as_str() else { continue };
            match s.to_ascii_lowercase().as_str() {
                "cli" | "command-line" | "commandline" | "terminal" => {
                    add(scores, "cli", 0.15);
                    evidence.push(mk("cli", "manifest.keywords.cli", 0.15, &format!("keyword '{}'", s)));
                }
                "native" | "addon" | "bindings" | "n-api" | "node-gyp" | "node-addon" | "prebuild" => {
                    add(scores, "dev_tool", 0.25);
                    evidence.push(mk("dev_tool", "manifest.keywords.native", 0.25, &format!("keyword '{}'", s)));
                }
                "library" | "util" | "utility" | "helper" | "sdk" => {
                    add(scores, "runtime_lib", 0.10);
                    evidence.push(mk("runtime_lib", "manifest.keywords.library", 0.10, &format!("keyword '{}'", s)));
                }
                _ => {}
            }
        }
    }

    // Deps → DevTool prior
    let dev_tool_deps = [
        "node-gyp", "node-pre-gyp", "prebuild-install", "prebuildify",
        "node-addon-api", "bindings", "nan", "electron-rebuild",
        "cmake-js",
    ];
    for section in ["dependencies", "devDependencies"] {
        if let Some(obj) = manifest[section].as_object() {
            for dep in dev_tool_deps {
                if obj.contains_key(dep) {
                    add(scores, "dev_tool", 0.35);
                    evidence.push(mk(
                        "dev_tool",
                        &format!("manifest.{}.{}", section, dep),
                        0.35,
                        &format!("depends on {}", dep),
                    ));
                }
            }
            let cli_deps = ["commander", "yargs", "minimist", "meow", "clipanion"];
            for dep in cli_deps {
                if obj.contains_key(dep) {
                    add(scores, "cli", 0.20);
                    evidence.push(mk(
                        "cli",
                        &format!("manifest.{}.{}", section, dep),
                        0.20,
                        &format!("depends on CLI library {}", dep),
                    ));
                }
            }
        }
    }

    // Install scripts with known build-tool patterns → DevTool
    if let Some(scripts) = manifest["scripts"].as_object() {
        for lifecycle in ["preinstall", "install", "postinstall"] {
            let Some(cmd) = scripts.get(lifecycle).and_then(Value::as_str) else { continue };
            let lowered = cmd.to_ascii_lowercase();
            if lowered.contains("node-gyp")
                || lowered.contains("prebuild-install")
                || lowered.contains("node-pre-gyp")
                || lowered.contains("electron-rebuild")
                || lowered.contains("husky")
                || lowered.contains("patch-package")
                || lowered.starts_with("npm rebuild")
            {
                add(scores, "dev_tool", 0.40);
                evidence.push(mk(
                    "dev_tool",
                    &format!("manifest.scripts.{}", lifecycle),
                    0.40,
                    &format!("{} script uses build tool: {}", lifecycle, cmd),
                ));
            }
        }
    }

    // Presence of `main`/`exports`/`types` without bin → RuntimeLib weak prior.
    if manifest["bin"].is_null() && !manifest["main"].is_null() {
        add(scores, "runtime_lib", 0.15);
        evidence.push(mk(
            "runtime_lib",
            "manifest.main_without_bin",
            0.15,
            "declares main/exports without a bin entry",
        ));
    }
    if !manifest["types"].is_null() || !manifest["typings"].is_null() {
        add(scores, "runtime_lib", 0.10);
        evidence.push(mk(
            "runtime_lib",
            "manifest.types",
            0.10,
            "ships .d.ts types (library-like)",
        ));
    }
}

// ── IR-based priors ───────────────────────────────────────────────────────────

fn ir_evidence(
    nodes: &[IrNode],
    scores: &mut HashMap<&'static str, f32>,
    evidence: &mut Vec<ClassificationEvidence>,
) {
    let mut saw_process_argv = false;
    let mut writes_build_paths = 0usize;
    let mut module_scope_sinks = 0usize;
    let mut function_scope_sinks = 0usize;

    for node in nodes {
        let is_sink = matches!(
            &node.kind,
            IrNodeKind::ProcessExec { .. }
                | IrNodeKind::FileWrite { .. }
                | IrNodeKind::NetworkRequest { .. }
        );
        if is_sink {
            if node.parent_fn_id.is_none() {
                module_scope_sinks += 1;
            } else {
                function_scope_sinks += 1;
            }
        }

        if let IrNodeKind::FileWrite { path: Some(p), .. } = &node.kind {
            if path_looks_like_build(p) {
                writes_build_paths += 1;
            }
        }

        // process.argv read surfaces through DataSource on a sink OR through
        // an assignment we can't directly see. Check arg_source on any sink.
        if let Some(ds) = node.kind.arg_source() {
            if contains_argv(ds) {
                saw_process_argv = true;
            }
        }
    }

    if saw_process_argv {
        add(scores, "cli", 0.40);
        evidence.push(mk(
            "cli",
            "ir.process_argv_read",
            0.40,
            "sink reads process.argv",
        ));
    }

    if writes_build_paths >= 1 {
        let w = (writes_build_paths as f32 * 0.15).min(0.45);
        add(scores, "dev_tool", w);
        evidence.push(mk(
            "dev_tool",
            "ir.writes_to_build_paths",
            w,
            &format!("{} filesystem writes target build/dist/*.node paths", writes_build_paths),
        ));
    }

    // Heavy module-scope side-effects (sink nodes at top level, not inside
    // a function) push away from RuntimeLib.
    if module_scope_sinks == 0 && function_scope_sinks >= 1 {
        add(scores, "runtime_lib", 0.30);
        evidence.push(mk(
            "runtime_lib",
            "ir.no_module_scope_sinks",
            0.30,
            "all side-effectful sinks are inside functions",
        ));
    }
    if module_scope_sinks >= 3 {
        // Very top-level-heavy — more likely a script/dev-tool than a library.
        add(scores, "dev_tool", 0.15);
        evidence.push(mk(
            "dev_tool",
            "ir.many_module_scope_sinks",
            0.15,
            &format!("{} sink nodes at module scope", module_scope_sinks),
        ));
    }
}

fn path_looks_like_build(p: &str) -> bool {
    let p = p.replace('\\', "/").to_ascii_lowercase();
    p.starts_with("build/")
        || p.starts_with("./build/")
        || p.starts_with("dist/")
        || p.starts_with("./dist/")
        || p.ends_with(".node")
        || p.contains("/build/release/")
        || p.contains("/build/debug/")
        || p.contains("/node_modules/.cache/")
}

fn contains_argv(ds: &vk_ir::DataSource) -> bool {
    use vk_ir::DataSource as D;
    match ds {
        D::ProcessArgv => true,
        D::Concatenation { sources } => sources.iter().any(contains_argv),
        _ => false,
    }
}

fn add(scores: &mut HashMap<&'static str, f32>, key: &'static str, delta: f32) {
    *scores.entry(key).or_insert(0.0) += delta;
}

fn mk(class: &str, source: &str, weight: f32, detail: &str) -> ClassificationEvidence {
    ClassificationEvidence {
        class: class.to_string(),
        source: source.to_string(),
        weight,
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn node_gyp_postinstall_classifies_as_devtool() {
        let m = json!({
            "name": "native-thing",
            "version": "1.0.0",
            "scripts": { "postinstall": "node-gyp rebuild" },
            "dependencies": { "node-addon-api": "*" }
        });
        let c = classify_package(Some(&m), &[]);
        assert_eq!(c.class, PackageClass::DevTool);
    }

    #[test]
    fn package_with_bin_classifies_as_cli() {
        let m = json!({
            "name": "mytool",
            "version": "1.0.0",
            "bin": { "mytool": "./cli.js" },
            "dependencies": { "commander": "^10" }
        });
        let c = classify_package(Some(&m), &[]);
        assert_eq!(c.class, PackageClass::Cli);
    }

    #[test]
    fn library_classifies_as_runtime_lib() {
        let m = json!({
            "name": "mylib",
            "version": "1.0.0",
            "main": "./index.js",
            "types": "./index.d.ts",
            "keywords": ["library", "util"]
        });
        let c = classify_package(Some(&m), &[]);
        assert_eq!(c.class, PackageClass::RuntimeLib);
    }

    #[test]
    fn empty_manifest_is_unknown() {
        // With only name/version (no main, no bin, no keywords, no deps, no
        // scripts), there is literally no evidence — should fall back to
        // Unknown rather than fabricating a guess.
        let m = json!({ "name": "x", "version": "0.0.0" });
        let c = classify_package(Some(&m), &[]);
        assert_eq!(c.class, PackageClass::Unknown);
    }
}
