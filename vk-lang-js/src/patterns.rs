//! JavaScript/TypeScript-specific taint analysis patterns
//!
//! This module provides helper functions to build JavaScript/TypeScript-specific
//! taint analysis patterns. The actual PatternProvider implementation is in
//! vk-core to avoid circular dependencies.

/// Build SQL sink patterns for JavaScript/TypeScript
pub fn build_sql_sinks() -> Vec<SqlSinkPattern> {
    vec![
        SqlSinkPattern {
            description: "SQL query execution via db.query()".to_string(),
            object: Some("db".to_string()),
            method: "query".to_string(),
            sensitive_args: vec![0],
        },
        SqlSinkPattern {
            description: "SQL query execution via connection.query()".to_string(),
            object: Some("connection".to_string()),
            method: "query".to_string(),
            sensitive_args: vec![0],
        },
        SqlSinkPattern {
            description: "SQL query execution via execute()".to_string(),
            object: None,
            method: "execute".to_string(),
            sensitive_args: vec![0],
        },
        SqlSinkPattern {
            description: "ORM raw query execution".to_string(),
            object: Some("sequelize".to_string()),
            method: "query".to_string(),
            sensitive_args: vec![0],
        },
        SqlSinkPattern {
            description: "TypeORM raw query".to_string(),
            object: Some("queryRunner".to_string()),
            method: "query".to_string(),
            sensitive_args: vec![0],
        },
        SqlSinkPattern {
            description: "Generic query() function".to_string(),
            object: None,
            method: "query".to_string(),
            sensitive_args: vec![0],
        },
    ]
}

/// Build SQL sanitizer patterns for JavaScript/TypeScript
pub fn build_sql_sanitizers() -> Vec<SqlSanitizerPattern> {
    vec![
        SqlSanitizerPattern {
            description: "Sequelize query builder (safe - parameterized)".to_string(),
            object: Some("sequelize".to_string()),
            method: "findAll".to_string(),
        },
        SqlSanitizerPattern {
            description: "Sequelize findOne (safe - parameterized)".to_string(),
            object: Some("sequelize".to_string()),
            method: "findOne".to_string(),
        },
        SqlSanitizerPattern {
            description: "TypeORM repository find (safe - parameterized)".to_string(),
            object: Some("repository".to_string()),
            method: "find".to_string(),
        },
        SqlSanitizerPattern {
            description: "Knex select (safe - query builder)".to_string(),
            object: Some("knex".to_string()),
            method: "select".to_string(),
        },
        SqlSanitizerPattern {
            description: "MySQL escape function".to_string(),
            object: None,
            method: "escape".to_string(),
        },
    ]
}

/// Pattern definition for SQL sinks (language-agnostic representation)
pub struct SqlSinkPattern {
    pub description: String,
    pub object: Option<String>, // None means function name, Some means method call
    pub method: String,
    pub sensitive_args: Vec<usize>,
}

/// Pattern definition for SQL sanitizers (language-agnostic representation)
pub struct SqlSanitizerPattern {
    pub description: String,
    pub object: Option<String>,
    pub method: String,
}

// Note: The actual PatternProvider implementation is in vk-core/src/languages/patterns/js.rs
// to avoid circular dependencies between vk-core and vk-lang-js

