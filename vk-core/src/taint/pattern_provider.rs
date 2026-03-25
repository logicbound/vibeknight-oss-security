//! Pattern provider trait for language-specific taint analysis patterns
//!
//! Each language frontend implements this trait to provide language-specific
//! patterns for sources, sinks, and sanitizers.

use crate::taint::model::{SourceDef, SinkDef, SanitizerDef};

/// Trait for providing language-specific taint analysis patterns
///
/// Each language frontend (JavaScript, Python, etc.) implements this to
/// provide patterns specific to that language's ecosystem (APIs, frameworks, etc.)
pub trait PatternProvider: Send + Sync {
    /// Get SQL injection sink patterns for this language
    ///
    /// Examples:
    /// - JavaScript: `sequelize.query()`, `db.query()`
    /// - Python: `cursor.execute()`, `db.query()`
    /// - PHP: `mysqli_query()`, `PDO::query()`
    fn sql_sinks(&self) -> SinkDef;
    
    /// Get SQL sanitizer patterns for this language
    ///
    /// Examples:
    /// - JavaScript: Sequelize query builder, parameterized queries
    /// - Python: SQLAlchemy ORM, parameterized queries
    fn sql_sanitizers(&self) -> SanitizerDef;
    
    /// Get taint source patterns for this language
    ///
    /// Examples:
    /// - JavaScript: `req.body`, `req.query`, `process.env`
    /// - Python: `request.form`, `request.args`, `os.environ`
    fn taint_sources(&self) -> SourceDef;
    
    /// Get language identifier (e.g., "javascript", "python", "php")
    fn language_id(&self) -> &'static str;
}

/// Default pattern provider that returns empty pattern sets
///
/// Useful as a fallback or for languages that don't have specific patterns yet
pub struct DefaultPatternProvider {
    language_id: &'static str,
}

impl DefaultPatternProvider {
    pub fn new(language_id: &'static str) -> Self {
        Self { language_id }
    }
}

impl PatternProvider for DefaultPatternProvider {
    fn sql_sinks(&self) -> SinkDef {
        SinkDef::new()
    }
    
    fn sql_sanitizers(&self) -> SanitizerDef {
        SanitizerDef::new()
    }
    
    fn taint_sources(&self) -> SourceDef {
        SourceDef::default()
    }
    
    fn language_id(&self) -> &'static str {
        self.language_id
    }
}

