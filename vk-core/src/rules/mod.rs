//! Built-in security analysis rules
//! 
//! This module contains example implementations of security rules.
//! Rules can be organized into submodules by category (e.g., sql, xss, auth).

mod sql_injection;

pub use sql_injection::SqlInjectionRule;

/// Get all built-in rules
pub fn all_rules() -> Vec<Box<dyn crate::rule::Rule>> {
    vec![
        Box::new(SqlInjectionRule::new()),
    ]
}

