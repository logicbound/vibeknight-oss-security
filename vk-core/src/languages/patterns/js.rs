//! JavaScript/TypeScript pattern provider implementation
//!
//! This module implements PatternProvider for JavaScript/TypeScript.
//! It uses pattern definitions from vk-lang-js but implements the trait here
//! to avoid circular dependencies.

use crate::taint::{
    PatternProvider, SourceDef, SinkDef, SanitizerDef,
    model::{Sink, Sanitizer, SinkPattern, SanitizerPattern, SanitizerMethod},
};

/// Pattern provider for JavaScript/TypeScript
pub struct JavaScriptPatternProvider;

impl JavaScriptPatternProvider {
    pub fn new() -> Self {
        Self
    }
}

impl PatternProvider for JavaScriptPatternProvider {
    fn language_id(&self) -> &'static str {
        "javascript"
    }
    
    fn sql_sinks(&self) -> SinkDef {
        let mut sinks = SinkDef::new();
        
        // Get patterns from vk-lang-js
        let patterns = vk_lang_js::patterns::build_sql_sinks();
        
        for pattern in patterns {
            let sink_pattern = if let Some(object) = pattern.object {
                SinkPattern::MethodCall {
                    object,
                    method: pattern.method,
                }
            } else {
                SinkPattern::FunctionName(pattern.method)
            };
            
            sinks.add(Sink {
                description: pattern.description,
                pattern: sink_pattern,
                sensitive_args: Some(pattern.sensitive_args),
                vuln_type: "sql-injection".to_string(),
            });
        }
        
        sinks
    }
    
    fn sql_sanitizers(&self) -> SanitizerDef {
        let mut sanitizers = SanitizerDef::new();
        
        // Get patterns from vk-lang-js
        let patterns = vk_lang_js::patterns::build_sql_sanitizers();
        
        for pattern in patterns {
            let sanitizer_pattern = if let Some(object) = pattern.object {
                SanitizerPattern::MethodCall {
                    object,
                    method: pattern.method,
                }
            } else {
                SanitizerPattern::FunctionName(pattern.method)
            };
            
            sanitizers.add(Sanitizer {
                description: pattern.description,
                pattern: sanitizer_pattern,
                method: SanitizerMethod::ParameterizedQuery,
            });
        }
        
        sanitizers
    }
    
    fn taint_sources(&self) -> SourceDef {
        // Use default sources which includes req.body, req.query, etc.
        SourceDef::default()
    }
}

