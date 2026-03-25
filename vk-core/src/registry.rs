use std::collections::HashMap;
use crate::rule::Rule;

/// Registry for managing security analysis rules
/// 
/// The registry stores all available rules and provides lookup functionality
pub struct RuleRegistry {
    rules: HashMap<String, Box<dyn Rule>>,
}

impl RuleRegistry {
    /// Create a new empty rule registry
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }
    
    /// Register a rule in the registry
    /// 
    /// # Panics
    /// Panics if a rule with the same ID is already registered
    pub fn register(&mut self, rule: Box<dyn Rule>) {
        let id = rule.id().to_string();
        if self.rules.contains_key(&id) {
            panic!("Rule with ID '{}' is already registered", id);
        }
        self.rules.insert(id, rule);
    }
    
    /// Register multiple rules at once
    pub fn register_all(&mut self, rules: Vec<Box<dyn Rule>>) {
        for rule in rules {
            self.register(rule);
        }
    }
    
    /// Get a rule by ID
    pub fn get(&self, rule_id: &str) -> Option<&dyn Rule> {
        self.rules.get(rule_id).map(|r| r.as_ref())
    }
    
    /// Get all registered rule IDs
    pub fn rule_ids(&self) -> Vec<String> {
        self.rules.keys().cloned().collect()
    }
    
    /// Get all registered rules
    pub fn all_rules(&self) -> Vec<&dyn Rule> {
        self.rules.values().map(|r| r.as_ref()).collect()
    }
    
    /// Check if a rule is registered
    pub fn contains(&self, rule_id: &str) -> bool {
        self.rules.contains_key(rule_id)
    }
    
    /// Get the number of registered rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }
    
    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

