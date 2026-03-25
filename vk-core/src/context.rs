use vk_ir::Program;
use crate::taint::pattern_provider::PatternProvider;

/// Analysis context passed to rules during execution
/// 
/// Provides all necessary information for rule analysis
pub struct AnalysisContext<'a> {
    /// The IR program being analyzed
    pub program: &'a Program,
    
    /// Path to the source file being analyzed
    pub file_path: String,
    
    /// Language identifier (e.g., "javascript", "python", "php")
    pub language_id: &'a str,
    
    /// Pattern provider for language-specific taint analysis patterns
    pub pattern_provider: &'a dyn PatternProvider,
}

impl<'a> AnalysisContext<'a> {
    /// Create a new analysis context
    pub fn new(
        program: &'a Program,
        file_path: String,
        language_id: &'a str,
        pattern_provider: &'a dyn PatternProvider,
    ) -> Self {
        Self {
            program,
            file_path,
            language_id,
            pattern_provider,
        }
    }
}

