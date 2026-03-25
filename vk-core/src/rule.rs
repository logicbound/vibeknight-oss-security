use crate::finding::Finding;
use crate::context::AnalysisContext;

/// Trait for security analysis rules
/// 
/// Rules analyze the IR and produce findings when vulnerabilities are detected
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule (e.g., "sql-injection", "xss")
    fn id(&self) -> &'static str;
    
    /// Human-readable name of the rule
    fn name(&self) -> &'static str;
    
    /// Severity level of findings from this rule
    fn severity(&self) -> Severity;
    
    /// Description of what this rule detects
    fn description(&self) -> &'static str;
    
    /// Detect security issues in the given analysis context
    /// 
    /// This is the main entry point for rule execution.
    /// Rules should analyze the IR in the context and return any security findings.
    fn detect(&self, ctx: &AnalysisContext) -> Vec<Finding>;
}

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    /// Informational - best practices, code quality
    Info,
    /// Low - minor security concerns
    Low,
    /// Medium - moderate security risks
    Medium,
    /// High - significant security risks
    High,
    /// Critical - severe security vulnerabilities
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

