use serde::{Deserialize, Serialize};
use crate::rule::Severity;
use vk_ir::SourceLocation;

/// A security finding detected by a rule
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Finding {
    /// Unique identifier for this finding (UUID or hash)
    pub id: String,
    
    /// ID of the rule that detected this finding
    pub rule_id: String,
    
    /// Severity level of the finding
    pub severity: Severity,
    
    /// Short title/summary of the finding
    pub title: String,
    
    /// Detailed description of the vulnerability
    pub description: String,
    
    /// File path where the finding was detected
    pub file: String,
    
    /// Line number (1-indexed)
    pub line: usize,
    
    /// Column number (1-indexed, 0 if unknown)
    pub column: usize,
    
    /// Code snippet around the finding location
    pub code_snippet: String,
    
    /// Data flow path from source to sink (if applicable)
    pub data_flow: Option<DataFlowPath>,
    
    /// Fix suggestion for this finding
    pub fix: Option<FixSuggestion>,
}

/// Represents a data flow path from a taint source to a sink
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DataFlowPath {
    /// Source location where taint originates
    pub source: FlowNode,
    
    /// Sink location where taint reaches
    pub sink: FlowNode,
    
    /// Intermediate steps in the data flow
    pub steps: Vec<FlowStep>,
    
    /// Taint kinds that flow through this path
    pub taint_kinds: Vec<String>,
}

/// A node in the data flow path
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FlowNode {
    /// Location in source code
    pub location: SourceLocation,
    
    /// Description of what happens at this node
    pub description: String,
    
    /// Code snippet at this location
    pub code: String,
}

/// A step in the data flow path
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FlowStep {
    /// Location where this step occurs
    pub location: SourceLocation,
    
    /// Description of the data flow operation
    pub description: String,
    
    /// Code snippet showing the operation
    pub code: String,
    
    /// Type of flow operation
    pub operation: FlowOperation,
}

/// Type of data flow operation
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum FlowOperation {
    /// Variable assignment: `x = source`
    Assignment,
    
    /// Function argument passing: `func(x)`
    ArgumentPass,
    
    /// Function return: `return x`
    Return,
    
    /// Property access: `obj.prop`
    PropertyAccess,
    
    /// Method call: `obj.method()`
    MethodCall,
    
    /// Binary operation: `x + y`
    BinaryOp,
}

/// Fix suggestion for a finding
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FixSuggestion {
    /// Short description of the fix
    pub description: String,
    
    /// Code example showing the fix (before)
    pub before: String,
    
    /// Code example showing the fix (after)
    pub after: String,
    
    /// Additional explanation or references
    pub explanation: Option<String>,
}

impl Finding {
    /// Create a new finding with a generated ID
    pub fn new(
        rule_id: String,
        severity: Severity,
        title: String,
        description: String,
        file: String,
        line: usize,
        column: usize,
        code_snippet: String,
    ) -> Self {
        Self {
            id: Self::generate_id(&rule_id, &file, line, column),
            rule_id,
            severity,
            title,
            description,
            file,
            line,
            column,
            code_snippet,
            data_flow: None,
            fix: None,
        }
    }
    
    /// Generate a unique ID for a finding
    fn generate_id(rule_id: &str, file: &str, line: usize, column: usize) -> String {
        // Simple hash-based ID (can be improved with proper UUID later)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        rule_id.hash(&mut hasher);
        file.hash(&mut hasher);
        line.hash(&mut hasher);
        column.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
    
    /// Set the data flow path for this finding
    pub fn with_data_flow(mut self, data_flow: DataFlowPath) -> Self {
        self.data_flow = Some(data_flow);
        self
    }
    
    /// Set the fix suggestion for this finding
    pub fn with_fix(mut self, fix: FixSuggestion) -> Self {
        self.fix = Some(fix);
        self
    }
    
    /// Render the data flow path as a human-readable string
    pub fn render_data_flow(&self) -> String {
        if let Some(ref path) = self.data_flow {
            path.render()
        } else {
            String::new()
        }
    }
    
    /// Render the fix suggestion as a human-readable string
    pub fn render_fix(&self) -> String {
        if let Some(ref fix) = self.fix {
            fix.render()
        } else {
            String::new()
        }
    }
}

impl DataFlowPath {
    /// Render the data flow path as a human-readable string
    pub fn render(&self) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("Source: {}:{}\n", self.source.location.line, self.source.location.column));
        output.push_str(&format!("  {}\n", self.source.description));
        output.push_str(&format!("  Code: {}\n", self.source.code));
        
        for step in &self.steps {
            output.push_str(&format!("\n  → {}:{} ({:?})\n", 
                step.location.line, 
                step.location.column,
                step.operation
            ));
            output.push_str(&format!("    {}\n", step.description));
            output.push_str(&format!("    Code: {}\n", step.code));
        }
        
        output.push_str(&format!("\nSink: {}:{}\n", self.sink.location.line, self.sink.location.column));
        output.push_str(&format!("  {}\n", self.sink.description));
        output.push_str(&format!("  Code: {}\n", self.sink.code));
        
        if !self.taint_kinds.is_empty() {
            output.push_str(&format!("\nTaint kinds: {}\n", self.taint_kinds.join(", ")));
        }
        
        output
    }
    
    /// Create a simple data flow path from source to sink
    pub fn simple(
        source_location: SourceLocation,
        source_code: String,
        sink_location: SourceLocation,
        sink_code: String,
        taint_kinds: Vec<String>,
    ) -> Self {
        Self {
            source: FlowNode {
                location: source_location.clone(),
                description: "Taint source".to_string(),
                code: source_code,
            },
            sink: FlowNode {
                location: sink_location.clone(),
                description: "Taint sink".to_string(),
                code: sink_code,
            },
            steps: Vec::new(),
            taint_kinds,
        }
    }
}

impl FixSuggestion {
    /// Render the fix suggestion as a human-readable string
    pub fn render(&self) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("Fix: {}\n", self.description));
        output.push_str("\nBefore:\n");
        output.push_str(&self.before);
        output.push_str("\n\nAfter:\n");
        output.push_str(&self.after);
        
        if let Some(ref explanation) = self.explanation {
            output.push_str(&format!("\n\nExplanation: {}\n", explanation));
        }
        
        output
    }
    
    /// Create a simple fix suggestion
    pub fn simple(description: String, before: String, after: String) -> Self {
        Self {
            description,
            before,
            after,
            explanation: None,
        }
    }
    
    /// Create a fix suggestion with explanation
    pub fn with_explanation(
        description: String,
        before: String,
        after: String,
        explanation: String,
    ) -> Self {
        Self {
            description,
            before,
            after,
            explanation: Some(explanation),
        }
    }
}

/// Helper to extract code snippet from source location
pub fn extract_code_snippet(file: &str, line: usize, context_lines: usize) -> String {
    use std::fs;
    
    // Read the file
    let content = match fs::read_to_string(file) {
        Ok(c) => c,
        Err(_) => return format!("// Could not read file: {}", file),
    };
    
    let lines: Vec<&str> = content.lines().collect();
    let line_count = lines.len();
    
    // Calculate range (1-indexed to 0-indexed)
    let line_idx = (line - 1).min(line_count.saturating_sub(1));
    let start = line_idx.saturating_sub(context_lines);
    let end = (line_idx + context_lines + 1).min(line_count);
    
    // Build snippet with line numbers
    let mut snippet = String::new();
    for i in start..end {
        let prefix = if i == line_idx { ">>> " } else { "    " };
        snippet.push_str(&format!("{}{:4} | {}\n", prefix, i + 1, lines[i]));
    }
    
    snippet.trim_end().to_string()
}

