use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Schema version ────────────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "1.0";

// ── Source location ───────────────────────────────────────────────────────────

/// Source location for any IR node — file-relative path, 1-indexed line and column.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

// ── Execution context ─────────────────────────────────────────────────────────

/// When in the package lifecycle this code executes.
///
/// Populated by the flow linker after IR construction; defaults to `Unknown`
/// for nodes that haven't been reached from a known entry point yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    /// Runs during `npm install` (preinstall / install / postinstall).
    Install,
    /// Normal require-time or export-time execution.
    Runtime,
    /// Deferred execution (setTimeout, setInterval, Promise.then).
    Deferred,
    /// Cannot be determined statically.
    #[default]
    Unknown,
}

/// The execution context in which an IR node was observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExecutionContext {
    /// The lifecycle script that triggers this node, if known (e.g. "postinstall").
    pub entry_point: Option<String>,
    pub phase: ExecutionPhase,
}

// ── Node tags ─────────────────────────────────────────────────────────────────

/// Lightweight annotations on an IR node — not signals, just facts about the node.
///
/// Used by confidence scoring and downstream ML/AI layers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeTag {
    /// The call argument was a static string literal (high confidence).
    UsesLiteralArg,
    /// The call argument was dynamic / could not be statically resolved.
    DynamicArg,
    /// The string value has Shannon entropy > 4.5 bits/char (likely encoded/obfuscated).
    HighEntropyString,
    /// This node was reached through an obfuscated or unresolved code path.
    ObfuscatedContext,
}

// ── Data source / argument provenance ────────────────────────────────────────

/// Where the argument to a sink came from — the *provenance* of a value.
///
/// This is the core feature the scorer uses to distinguish
/// `execSync("npm rebuild")` (Literal) from `execSync(decodedPayload)`
/// (Decoded-of-NetworkResponse).
///
/// Populated by the language walker during IR construction via a local
/// 1-hop assignment map. Nothing in this enum is interpreted — it is
/// purely a fact describing where a value originated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataSource {
    /// A static string literal: `"npm rebuild"`.
    Literal { value: String },
    /// A template literal with no interpolations — materially a literal.
    TemplateOnly { segments: Vec<String> },
    /// A read of `process.env.X` (or `process.env[...]`).
    EnvVar { name: Option<String> },
    /// A read of `process.argv`.
    ProcessArgv,
    /// The result of a filesystem read.
    FileReadResult { path: Option<String> },
    /// The result of a network request (fetch / axios / http.get / ...).
    NetworkResponse { origin_node_id: Option<String> },
    /// The result of a decoder call (`atob`, `Buffer.from(x, 'base64')`, ...).
    Decoded { origin_node_id: Option<String>, encoding: String },
    /// A concatenation or template-with-interpolations mixing multiple sources.
    Concatenation { sources: Vec<DataSource> },
    /// A parameter of the enclosing function (provenance is caller-dependent).
    FunctionArg { param_name: Option<String> },
    /// Unknown — the walker couldn't classify the source statically.
    Unknown,
}

impl Default for DataSource {
    fn default() -> Self {
        DataSource::Unknown
    }
}

impl DataSource {
    /// The variant name as a stable snake-case string — used for features and evidence.
    pub fn kind_str(&self) -> &'static str {
        match self {
            DataSource::Literal { .. }         => "literal",
            DataSource::TemplateOnly { .. }    => "template_only",
            DataSource::EnvVar { .. }          => "env_var",
            DataSource::ProcessArgv            => "process_argv",
            DataSource::FileReadResult { .. }  => "file_read_result",
            DataSource::NetworkResponse { .. } => "network_response",
            DataSource::Decoded { .. }         => "decoded",
            DataSource::Concatenation { .. }   => "concatenation",
            DataSource::FunctionArg { .. }     => "function_arg",
            DataSource::Unknown                => "unknown",
        }
    }

    /// True if this source (or any transitive sub-source) is attacker-controllable.
    pub fn is_attacker_controllable(&self) -> bool {
        match self {
            DataSource::Literal { .. } | DataSource::TemplateOnly { .. } => false,
            DataSource::EnvVar { .. }
            | DataSource::ProcessArgv
            | DataSource::FileReadResult { .. }
            | DataSource::NetworkResponse { .. }
            | DataSource::Decoded { .. }
            | DataSource::FunctionArg { .. }
            | DataSource::Unknown => true,
            DataSource::Concatenation { sources } => {
                sources.iter().any(|s| s.is_attacker_controllable())
            }
        }
    }

    /// True if this source is (transitively) derived from network input.
    pub fn derives_from_network(&self) -> bool {
        match self {
            DataSource::NetworkResponse { .. } => true,
            DataSource::Decoded { .. } => true, // conservative: decoded could be network-rooted
            DataSource::Concatenation { sources } => {
                sources.iter().any(|s| s.derives_from_network())
            }
            _ => false,
        }
    }

    /// True if this source is (transitively) a decode of some origin.
    pub fn derives_from_decoded(&self) -> bool {
        match self {
            DataSource::Decoded { .. } => true,
            DataSource::Concatenation { sources } => {
                sources.iter().any(|s| s.derives_from_decoded())
            }
            _ => false,
        }
    }

    /// True if this source is (transitively) a purely literal value.
    pub fn is_fully_literal(&self) -> bool {
        match self {
            DataSource::Literal { .. } | DataSource::TemplateOnly { .. } => true,
            DataSource::Concatenation { sources } => {
                sources.iter().all(|s| s.is_fully_literal())
            }
            _ => false,
        }
    }
}

// ── IR node kinds ─────────────────────────────────────────────────────────────

/// The kind of IR node — what *exists* in the code.
///
/// Facts only. No signals, no risk scores, no interpretation.
/// Signals are derived from these facts in the analysis layer (`vk-core`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IrNodeKind {
    /// An execution entry point (main field, lifecycle script, bin entry).
    EntryPoint {
        /// The install script name if this came from package.json `scripts`,
        /// e.g. "postinstall", "preinstall", "install". `None` for file-level entries.
        script: Option<String>,
    },

    /// A function declaration or expression boundary.
    Function {
        /// The function's identifier, if statically known (`None` for anonymous).
        name: Option<String>,
    },

    /// A function call expression.
    Call {
        /// The callee text as resolved through the binding table.
        callee: String,
    },

    /// A child_process method invocation (exec, spawn, execSync, execFile, …).
    ProcessExec {
        /// The command string if statically determinable.
        command: Option<String>,
        /// Provenance of the command argument (literal / env / network / decoded / ...).
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A filesystem read operation.
    FileRead {
        path: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A filesystem write operation.
    FileWrite {
        path: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// An outbound network request (http/https, fetch, axios, node-fetch, got, …).
    NetworkRequest {
        url: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A direct `eval()` call.
    Eval {
        raw_arg: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A dynamic `import()` expression.
    DynamicImport {
        specifier: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A `new Function(...)` constructor call.
    FunctionConstructor {
        body: Option<String>,
        #[serde(default)]
        arg_source: DataSource,
    },

    /// A statically detected encoded string (base64, hex, …).
    EncodedString {
        encoding: String,
        value: String,
    },

    /// A dynamic or obfuscated code flow (e.g. `require(variable)`).
    ObfuscatedFlow,
}

impl IrNodeKind {
    /// If this is a sink node, return its argument provenance.
    pub fn arg_source(&self) -> Option<&DataSource> {
        match self {
            IrNodeKind::ProcessExec { arg_source, .. }
            | IrNodeKind::FileRead { arg_source, .. }
            | IrNodeKind::FileWrite { arg_source, .. }
            | IrNodeKind::NetworkRequest { arg_source, .. }
            | IrNodeKind::Eval { arg_source, .. }
            | IrNodeKind::DynamicImport { arg_source, .. }
            | IrNodeKind::FunctionConstructor { arg_source, .. } => Some(arg_source),
            _ => None,
        }
    }
}

// ── IR node ───────────────────────────────────────────────────────────────────

/// A single node in the behavioural IR graph.
///
/// **ID design:** `"<file>:<line>:<Kind>:<sha256_12>"` — the 12-char hash folds
/// in column number and any payload value (callee text, command, URL…) so two
/// same-kind nodes on the same line get distinct, stable IDs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IrNode {
    pub id: String,
    pub kind: IrNodeKind,
    pub location: SourceLocation,
    /// Lightweight fact-annotations auto-computed at construction time.
    pub tags: Vec<NodeTag>,
    /// Execution context populated by the flow linker; defaults to `Unknown`.
    pub context: ExecutionContext,
    /// The id of the enclosing `Function` node, if the walker knew it.
    /// `None` for module-scope nodes or nodes emitted before a function opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_fn_id: Option<String>,
}

impl IrNode {
    /// Construct an `IrNode` with auto-computed tags and a collision-safe ID.
    pub fn new(kind: IrNodeKind, location: SourceLocation) -> Self {
        let id = make_stable_id(&kind, &location);
        let tags = auto_tags(&kind);
        Self {
            id,
            kind,
            location,
            tags,
            context: ExecutionContext::default(),
            parent_fn_id: None,
        }
    }

    /// Construct an `IrNode` and append extra tags to the auto-computed set.
    pub fn with_tags(kind: IrNodeKind, location: SourceLocation, extra_tags: Vec<NodeTag>) -> Self {
        let mut node = Self::new(kind, location);
        for tag in extra_tags {
            if !node.tags.contains(&tag) {
                node.tags.push(tag);
            }
        }
        node
    }

    /// Attach an enclosing function id to this node.
    pub fn with_parent_fn(mut self, parent_fn_id: Option<String>) -> Self {
        self.parent_fn_id = parent_fn_id;
        self
    }
}

// ── ID generation ─────────────────────────────────────────────────────────────

fn make_stable_id(kind: &IrNodeKind, loc: &SourceLocation) -> String {
    let extra = id_extra(kind);
    let raw = match &extra {
        Some(e) => format!("{}:{}:{}:{}:{}", loc.file, loc.line, loc.col, kind_tag(kind), e),
        None    => format!("{}:{}:{}:{}", loc.file, loc.line, loc.col, kind_tag(kind)),
    };
    let digest = Sha256::digest(raw.as_bytes());
    let hash12 = &hex::encode(digest)[..12];
    format!("{}:{}:{}:{}", loc.file, loc.line, kind_tag(kind), hash12)
}

/// Extract the payload value used to disambiguate same-kind nodes on the same line.
fn id_extra(kind: &IrNodeKind) -> Option<String> {
    match kind {
        IrNodeKind::Call { callee }                   => Some(callee.clone()),
        IrNodeKind::ProcessExec { command, .. }       => command.clone(),
        IrNodeKind::NetworkRequest { url, .. }        => url.clone(),
        IrNodeKind::FileRead { path, .. }             => path.clone(),
        IrNodeKind::FileWrite { path, .. }            => path.clone(),
        IrNodeKind::Function { name }                 => name.clone(),
        IrNodeKind::Eval { raw_arg, .. }              => raw_arg.clone(),
        IrNodeKind::FunctionConstructor { body, .. }  => body.clone(),
        IrNodeKind::DynamicImport { specifier, .. }   => specifier.clone(),
        IrNodeKind::EncodedString { value, .. }       => Some(value.clone()),
        IrNodeKind::EntryPoint { script }             => script.clone(),
        IrNodeKind::ObfuscatedFlow                    => None,
    }
}

pub fn kind_tag(kind: &IrNodeKind) -> &'static str {
    match kind {
        IrNodeKind::EntryPoint { .. }          => "EntryPoint",
        IrNodeKind::Function { .. }            => "Function",
        IrNodeKind::Call { .. }                => "Call",
        IrNodeKind::ProcessExec { .. }         => "ProcessExec",
        IrNodeKind::FileRead { .. }            => "FileRead",
        IrNodeKind::FileWrite { .. }           => "FileWrite",
        IrNodeKind::NetworkRequest { .. }      => "NetworkRequest",
        IrNodeKind::Eval { .. }                => "Eval",
        IrNodeKind::DynamicImport { .. }       => "DynamicImport",
        IrNodeKind::FunctionConstructor { .. } => "FunctionConstructor",
        IrNodeKind::EncodedString { .. }       => "EncodedString",
        IrNodeKind::ObfuscatedFlow             => "ObfuscatedFlow",
    }
}

// ── Auto-tagging ──────────────────────────────────────────────────────────────

/// Infer `UsesLiteralArg` / `DynamicArg` / `HighEntropyString` from the node kind.
fn auto_tags(kind: &IrNodeKind) -> Vec<NodeTag> {
    let mut tags = Vec::new();

    match kind {
        IrNodeKind::ProcessExec { command, .. } => {
            push_arg_tag(&mut tags, command.as_deref());
        }
        IrNodeKind::NetworkRequest { url, .. } => {
            push_arg_tag(&mut tags, url.as_deref());
        }
        IrNodeKind::FileRead { path, .. } | IrNodeKind::FileWrite { path, .. } => {
            push_arg_tag(&mut tags, path.as_deref());
        }
        IrNodeKind::Eval { raw_arg, .. } => {
            push_arg_tag(&mut tags, raw_arg.as_deref());
        }
        IrNodeKind::FunctionConstructor { body, .. } => {
            push_arg_tag(&mut tags, body.as_deref());
        }
        IrNodeKind::DynamicImport { specifier, .. } => {
            push_arg_tag(&mut tags, specifier.as_deref());
        }
        IrNodeKind::EncodedString { value, .. } => {
            tags.push(NodeTag::UsesLiteralArg);
            if shannon_entropy(value) > 4.5 {
                tags.push(NodeTag::HighEntropyString);
            }
        }
        IrNodeKind::ObfuscatedFlow => {
            tags.push(NodeTag::DynamicArg);
        }
        _ => {}
    }

    tags
}

fn push_arg_tag(tags: &mut Vec<NodeTag>, value: Option<&str>) {
    match value {
        Some(v) => {
            tags.push(NodeTag::UsesLiteralArg);
            if shannon_entropy(v) > 4.5 {
                tags.push(NodeTag::HighEntropyString);
            }
        }
        None => tags.push(NodeTag::DynamicArg),
    }
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let n = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / n; -p * p.log2() })
        .sum()
}

// ── File IR ───────────────────────────────────────────────────────────────────

/// The complete IR output for a single JS/TS file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIr {
    pub file: String,
    pub nodes: Vec<IrNode>,
}
