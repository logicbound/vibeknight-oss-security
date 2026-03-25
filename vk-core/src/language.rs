use vk_ir::Program;
use std::path::Path;
use crate::taint::pattern_provider::PatternProvider;

/// Trait for language-specific frontends
/// 
/// Each language frontend (vk-lang-js, vk-lang-c++, etc.) implements this
/// to provide language-specific parsing and IR lowering
pub trait LanguageFrontend: Send + Sync {
    /// Unique identifier for this language (e.g., "javascript", "cpp", "python")
    fn id(&self) -> &'static str;
    
    /// Human-readable name of the language
    fn name(&self) -> &'static str;
    
    /// Check if this frontend can handle the given file
    /// 
    /// Should check file extension, shebang, or other heuristics
    fn can_handle(&self, path: &Path) -> bool;
    
    /// Parse source code and lower it to IR
    /// 
    /// Returns the IR Program representation of the source code
    fn lower_to_ir(&self, source: &str, file_path: &str) -> Program;
    
    /// Get the pattern provider for this language
    /// 
    /// Returns language-specific patterns for taint analysis (sources, sinks, sanitizers)
    fn pattern_provider(&self) -> Box<dyn PatternProvider>;
}

/// Registry for language frontends
pub struct LanguageRegistry {
    frontends: Vec<Box<dyn LanguageFrontend>>,
}

impl LanguageRegistry {
    /// Create a new empty language registry
    pub fn new() -> Self {
        Self {
            frontends: Vec::new(),
        }
    }
    
    /// Register a language frontend
    pub fn register(&mut self, frontend: Box<dyn LanguageFrontend>) {
        self.frontends.push(frontend);
    }
    
    /// Register multiple frontends
    pub fn register_all(&mut self, frontends: Vec<Box<dyn LanguageFrontend>>) {
        self.frontends.extend(frontends);
    }
    
    /// Find a frontend that can handle the given file
    pub fn find_frontend(&self, path: &Path) -> Option<&dyn LanguageFrontend> {
        self.frontends.iter()
            .find(|f| f.can_handle(path))
            .map(|f| f.as_ref())
    }
    
    /// Get all registered frontends
    pub fn all_frontends(&self) -> Vec<&dyn LanguageFrontend> {
        self.frontends.iter().map(|f| f.as_ref()).collect()
    }
    
    /// Check if any frontend can handle the file
    pub fn can_handle_file(&self, path: &Path) -> bool {
        self.find_frontend(path).is_some()
    }
}

impl Default for LanguageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

