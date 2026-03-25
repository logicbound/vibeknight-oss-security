use vk_ir::Program;
use crate::registry::RuleRegistry;
use crate::config::RuleConfig;
use crate::finding::Finding;
use crate::context::AnalysisContext;

/// Pipeline for executing security analysis rules
/// 
/// The pipeline coordinates rule execution, applies configuration,
/// and aggregates findings from all enabled rules
pub struct RulePipeline {
    registry: RuleRegistry,
    config: RuleConfig,
}

impl RulePipeline {
    /// Create a new pipeline with the given registry and config
    pub fn new(registry: RuleRegistry, config: RuleConfig) -> Self {
        Self {
            registry,
            config,
        }
    }
    
    /// Create a pipeline with default (empty) registry and config
    pub fn default() -> Self {
        Self {
            registry: RuleRegistry::new(),
            config: RuleConfig::default(),
        }
    }
    
    /// Get a mutable reference to the rule registry
    pub fn registry_mut(&mut self) -> &mut RuleRegistry {
        &mut self.registry
    }
    
    /// Get a reference to the rule registry
    pub fn registry(&self) -> &RuleRegistry {
        &self.registry
    }
    
    /// Get a mutable reference to the rule configuration
    pub fn config_mut(&mut self) -> &mut RuleConfig {
        &mut self.config
    }
    
    /// Get a reference to the rule configuration
    pub fn config(&self) -> &RuleConfig {
        &self.config
    }
    
    /// Execute all enabled rules on a program
    /// 
    /// Returns aggregated findings from all enabled rules
    /// 
    /// NOTE: This method is deprecated. Use execute_with_context instead,
    /// which requires language-specific pattern providers.
    #[deprecated(note = "Use execute_with_context with pattern provider")]
    pub fn execute(&self, _program: &Program, _file_path: &str) -> Vec<Finding> {
        // This method can't work without a pattern provider
        // It's kept for backward compatibility but will panic
        panic!("execute() requires pattern provider. Use execute_with_context() instead.")
    }
    
    /// Execute all enabled rules with an analysis context
    /// 
    /// Returns aggregated findings from all enabled rules
    pub fn execute_with_context(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut all_findings = Vec::new();
        
        // Iterate through all registered rules
        for rule in self.registry.all_rules() {
            let rule_id = rule.id();
            
            // Skip disabled rules
            if !self.config.is_rule_enabled(rule_id) {
                continue;
            }
            
            // Execute the rule and collect findings
            let findings = rule.detect(ctx);
            all_findings.extend(findings);
        }
        
        all_findings
    }
    
    /// Execute rules on multiple programs (e.g., from multiple files)
    /// 
    /// Returns findings grouped by file path
    /// 
    /// NOTE: This method is deprecated. Each program needs its own AnalysisContext
    /// with a language-specific pattern provider.
    #[deprecated(note = "Use execute_with_context for each program individually")]
    pub fn execute_many(&self, _programs: &[(Program, String)]) -> Vec<Finding> {
        // This method can't work without pattern providers
        // It's kept for backward compatibility but will panic
        panic!("execute_many() requires pattern providers. Use execute_with_context() for each program instead.")
    }
}

impl Default for RulePipeline {
    fn default() -> Self {
        Self::default()
    }
}

