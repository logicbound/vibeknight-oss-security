use vk_lang_js::{lower_to_ir, lower_to_ir_with_path};
use std::fs;
use vk_ir::SymbolKind;

#[test]
fn resolves_imports() {
    let source = fs::read_to_string("tests/fixtures/auth.js")
        .expect("Failed to read test fixture");
    
    let program = lower_to_ir(&source);
    
    // Verify imports are resolved
    assert!(!program.modules.is_empty());
    let module = &program.modules[0];
    
    // auth.js has 3 imports: bcrypt, jwt, User
    assert!(module.imports.len() >= 3);
    
    // Verify symbols are in symbol table
    let bcrypt_symbols = module.symbols.find_symbols("bcrypt");
    assert!(!bcrypt_symbols.is_empty());
    assert_eq!(bcrypt_symbols[0].kind, SymbolKind::Import);
    
    let jwt_symbols = module.symbols.find_symbols("jwt");
    assert!(!jwt_symbols.is_empty());
    assert_eq!(jwt_symbols[0].kind, SymbolKind::Import);
}

#[test]
fn resolves_function_parameters() {
    let source = r#"
        function test(a, b, c) {
            return a + b;
        }
    "#;
    
    let program = lower_to_ir(source);
    
    assert!(!program.modules.is_empty());
    let module = &program.modules[0];
    assert!(!module.functions.is_empty());
    
    let func = &module.functions[0];
    assert_eq!(func.name, "test");
    assert_eq!(func.params.len(), 3);
    
    // Verify parameters are in symbol table
    let a_symbols = module.symbols.find_symbols("a");
    assert!(!a_symbols.is_empty());
    assert_eq!(a_symbols[0].kind, SymbolKind::Parameter);
}

#[test]
fn builds_module_graph() {
    let source = r#"
        import { something } from './other.js';
        import utils from './utils.js';
    "#;
    
    let program = lower_to_ir_with_path(source, "test.js");
    
    // Verify module graph is built
    let deps = program.module_graph.get_dependencies("test.js");
    assert!(deps.len() >= 2);
    
    // Verify imports are tracked
    assert!(!program.modules.is_empty());
    let module = &program.modules[0];
    assert_eq!(module.imports.len(), 2);
}

