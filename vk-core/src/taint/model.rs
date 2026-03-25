//! Taint model definitions: Sources, Sinks, and Sanitizers

use vk_ir::{TaintKind, Expr};

/// A taint source - where untrusted data enters the program
#[derive(Debug, Clone)]
pub struct Source {
    /// The taint kind produced by this source
    pub kind: TaintKind,
    /// Description of the source
    pub description: String,
    /// Pattern to match (e.g., function name, API call)
    pub pattern: SourcePattern,
}

/// Pattern for matching sources
#[derive(Debug, Clone)]
pub enum SourcePattern {
    /// Match by function/method name
    FunctionName(String),
    /// Match by object.method pattern
    MethodCall { object: String, method: String },
    /// Match by identifier name (e.g., req.body, req.query)
    Identifier(String),
}

/// A taint sink - where tainted data is used in a dangerous way
#[derive(Debug, Clone)]
pub struct Sink {
    /// Description of the sink
    pub description: String,
    /// Pattern to match
    pub pattern: SinkPattern,
    /// Which argument positions are sensitive (None = all)
    pub sensitive_args: Option<Vec<usize>>,
    /// Vulnerability type (e.g., "sql-injection", "xss")
    pub vuln_type: String,
}

/// Pattern for matching sinks
#[derive(Debug, Clone)]
pub enum SinkPattern {
    /// Match by function/method name
    FunctionName(String),
    /// Match by object.method pattern
    MethodCall { object: String, method: String },
}

/// A sanitizer - removes taint from data
#[derive(Debug, Clone)]
pub struct Sanitizer {
    /// Description of the sanitizer
    pub description: String,
    /// Pattern to match
    pub pattern: SanitizerPattern,
    /// Sanitization method
    pub method: SanitizerMethod,
}

/// Pattern for matching sanitizers
#[derive(Debug, Clone)]
pub enum SanitizerPattern {
    /// Match by function/method name
    FunctionName(String),
    /// Match by object.method pattern
    MethodCall { object: String, method: String },
}

/// Sanitization methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerMethod {
    /// Regex escaping
    RegexEscape,
    /// Parameterized query (SQL)
    ParameterizedQuery,
    /// HTML escaping
    HtmlEscape,
    /// URL encoding
    UrlEncode,
    /// Custom sanitization
    Custom,
}

/// Registry of source definitions
pub struct SourceDef {
    sources: Vec<Source>,
}

impl SourceDef {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }
    
    pub fn add(&mut self, source: Source) {
        self.sources.push(source);
    }
    
    pub fn find_source(&self, expr: &Expr) -> Option<&Source> {
        self.sources.iter().find(|s| match &s.pattern {
            SourcePattern::FunctionName(name) => {
                matches!(expr, Expr::Identifier(id) if id == name)
            }
            SourcePattern::MethodCall { object: _, method } => {
                matches!(expr, Expr::Member { obj: _, prop } if prop == method)
            }
            SourcePattern::Identifier(id) => {
                // Check for exact identifier match
                if matches!(expr, Expr::Identifier(expr_id) if expr_id == id) {
                    return true;
                }
                // Check for member expression like req.body, req.query, etc.
                // req.body would match pattern "req.body"
                // req.body.email would also match pattern "req.body" (prefix match)
                if let Expr::Member { .. } = expr {
                    // Build the full path (e.g., "req.body.email")
                    let path = Self::build_member_path(expr);
                    // Match if path equals the pattern or starts with pattern + "."
                    path == *id || path.starts_with(&format!("{}.", id))
                } else {
                    false
                }
            }
        })
    }
    
    /// Build a string path from a member expression (e.g., "req.body.email")
    fn build_member_path(expr: &Expr) -> String {
        match expr {
            Expr::Member { obj, prop } => {
                let obj_path = Self::build_member_path(&obj.node);
                if obj_path.is_empty() {
                    prop.clone()
                } else {
                    format!("{}.{}", obj_path, prop)
                }
            }
            Expr::Identifier(name) => name.clone(),
            _ => String::new(),
        }
    }
    
    pub fn all_sources(&self) -> &[Source] {
        &self.sources
    }
}

impl Default for SourceDef {
    fn default() -> Self {
        let mut def = Self::new();
        
        // Common JavaScript/Node.js sources
        def.add(Source {
            kind: TaintKind::UserInput,
            description: "HTTP request body".to_string(),
            pattern: SourcePattern::Identifier("req.body".to_string()),
        });
        
        def.add(Source {
            kind: TaintKind::UserInput,
            description: "HTTP request query parameters".to_string(),
            pattern: SourcePattern::Identifier("req.query".to_string()),
        });
        
        def.add(Source {
            kind: TaintKind::UserInput,
            description: "HTTP request parameters".to_string(),
            pattern: SourcePattern::Identifier("req.params".to_string()),
        });
        
        def.add(Source {
            kind: TaintKind::Cookie,
            description: "HTTP cookies".to_string(),
            pattern: SourcePattern::Identifier("req.cookies".to_string()),
        });
        
        def.add(Source {
            kind: TaintKind::Env,
            description: "Environment variables".to_string(),
            pattern: SourcePattern::MethodCall {
                object: "process".to_string(),
                method: "env".to_string(),
            },
        });
        
        def.add(Source {
            kind: TaintKind::FileSystem,
            description: "File system reads".to_string(),
            pattern: SourcePattern::FunctionName("fs.readFile".to_string()),
        });
        
        def
    }
}

/// Registry of sink definitions
#[derive(Clone)]
pub struct SinkDef {
    sinks: Vec<Sink>,
}

impl SinkDef {
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
        }
    }
    
    pub fn add(&mut self, sink: Sink) {
        self.sinks.push(sink);
    }
    
    pub fn find_sink(&self, expr: &Expr) -> Option<&Sink> {
        self.sinks.iter().find(|s| match &s.pattern {
            SinkPattern::FunctionName(name) => {
                matches!(expr, Expr::Identifier(id) if id == name)
            }
            SinkPattern::MethodCall { object, method } => {
                match expr {
                    Expr::Member { obj, prop } => {
                        // Check if method matches
                        if prop != method {
                            return false;
                        }
                        // Check if object matches - handle nested members
                        let obj_path = Self::build_member_path(&obj.node);
                        // Match if the object path equals the pattern or ends with it
                        // e.g., "models.sequelize" matches "sequelize", or "sequelize" matches "sequelize"
                        obj_path == *object || obj_path.ends_with(&format!(".{}", object))
                    }
                    _ => false,
                }
            }
        })
    }
    
    /// Build a string path from a member expression (e.g., "models.sequelize")
    fn build_member_path(expr: &Expr) -> String {
        match expr {
            Expr::Member { obj, prop } => {
                let obj_path = Self::build_member_path(&obj.node);
                if obj_path.is_empty() {
                    prop.clone()
                } else {
                    format!("{}.{}", obj_path, prop)
                }
            }
            Expr::Identifier(name) => name.clone(),
            _ => String::new(),
        }
    }
    
    pub fn all_sinks(&self) -> &[Sink] {
        &self.sinks
    }
}

impl Default for SinkDef {
    fn default() -> Self {
        let mut def = Self::new();
        
        // SQL injection sinks
        def.add(Sink {
            description: "SQL query execution".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "db".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]), // First argument is the query
            vuln_type: "sql-injection".to_string(),
        });
        
        def.add(Sink {
            description: "SQL query execution".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "connection".to_string(),
                method: "query".to_string(),
            },
            sensitive_args: Some(vec![0]),
            vuln_type: "sql-injection".to_string(),
        });
        
        // XSS sinks
        def.add(Sink {
            description: "HTML output".to_string(),
            pattern: SinkPattern::MethodCall {
                object: "res".to_string(),
                method: "send".to_string(),
            },
            sensitive_args: Some(vec![0]),
            vuln_type: "xss".to_string(),
        });
        
        def.add(Sink {
            description: "DOM manipulation".to_string(),
            pattern: SinkPattern::FunctionName("innerHTML".to_string()),
            sensitive_args: Some(vec![0]),
            vuln_type: "xss".to_string(),
        });
        
        // Command injection sinks
        def.add(Sink {
            description: "Command execution".to_string(),
            pattern: SinkPattern::FunctionName("exec".to_string()),
            sensitive_args: Some(vec![0]),
            vuln_type: "command-injection".to_string(),
        });
        
        def
    }
}

/// Registry of sanitizer definitions
#[derive(Clone)]
pub struct SanitizerDef {
    sanitizers: Vec<Sanitizer>,
}

impl SanitizerDef {
    pub fn new() -> Self {
        Self {
            sanitizers: Vec::new(),
        }
    }
    
    pub fn add(&mut self, sanitizer: Sanitizer) {
        self.sanitizers.push(sanitizer);
    }
    
    pub fn find_sanitizer(&self, expr: &Expr) -> Option<&Sanitizer> {
        self.sanitizers.iter().find(|s| match &s.pattern {
            SanitizerPattern::FunctionName(name) => {
                matches!(expr, Expr::Identifier(id) if id == name)
            }
            SanitizerPattern::MethodCall { object: _, method } => {
                matches!(expr, Expr::Member { obj: _, prop } if prop == method)
            }
        })
    }
    
    pub fn all_sanitizers(&self) -> &[Sanitizer] {
        &self.sanitizers
    }
}

impl Default for SanitizerDef {
    fn default() -> Self {
        let mut def = Self::new();
        
        // SQL sanitizers
        def.add(Sanitizer {
            description: "Parameterized query".to_string(),
            pattern: SanitizerPattern::MethodCall {
                object: "db".to_string(),
                method: "prepared".to_string(),
            },
            method: SanitizerMethod::ParameterizedQuery,
        });
        
        // HTML sanitizers
        def.add(Sanitizer {
            description: "HTML escape".to_string(),
            pattern: SanitizerPattern::FunctionName("escapeHtml".to_string()),
            method: SanitizerMethod::HtmlEscape,
        });
        
        def.add(Sanitizer {
            description: "HTML escape".to_string(),
            pattern: SanitizerPattern::FunctionName("htmlEscape".to_string()),
            method: SanitizerMethod::HtmlEscape,
        });
        
        // Regex sanitizers
        def.add(Sanitizer {
            description: "Regex escape".to_string(),
            pattern: SanitizerPattern::FunctionName("escapeRegex".to_string()),
            method: SanitizerMethod::RegexEscape,
        });
        
        def
    }
}

