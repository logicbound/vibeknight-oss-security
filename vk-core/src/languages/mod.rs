//! Built-in language frontend implementations
//! 
//! This module provides language frontend implementations.
//! Each language crate can provide its own frontend implementation.

use std::path::Path;
use crate::taint::pattern_provider::PatternProvider;

mod patterns;

/// JavaScript/TypeScript frontend wrapper
/// 
/// This wraps the vk-lang-js crate to provide a LanguageFrontend implementation
pub struct JavaScriptFrontend {
    pattern_provider: Box<dyn PatternProvider>,
}

impl JavaScriptFrontend {
    pub fn new() -> Self {
        Self {
            pattern_provider: Box::new(patterns::JavaScriptPatternProvider::new()),
        }
    }
}

impl crate::language::LanguageFrontend for JavaScriptFrontend {
    fn id(&self) -> &'static str {
        "javascript"
    }
    
    fn name(&self) -> &'static str {
        "JavaScript/TypeScript"
    }
    
    fn can_handle(&self, path: &Path) -> bool {
        // Check file extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            return ext_str == "js" || ext_str == "jsx" || ext_str == "ts" || ext_str == "tsx" || ext_str == "mjs" || ext_str == "cjs";
        }
        
        // Could also check shebang or other heuristics
        false
    }
    
    fn lower_to_ir(&self, source: &str, file_path: &str) -> vk_ir::Program {
        vk_lang_js::lower_to_ir_with_path(source, file_path)
    }
    
    fn pattern_provider(&self) -> Box<dyn PatternProvider> {
        // Clone the pattern provider by creating a new one
        // (PatternProvider doesn't require Clone, so we recreate it)
        Box::new(patterns::JavaScriptPatternProvider::new())
    }
}

/// Get all built-in language frontends
pub fn all_frontends() -> Vec<Box<dyn crate::language::LanguageFrontend>> {
    vec![
        Box::new(JavaScriptFrontend::new()),
    ]
}