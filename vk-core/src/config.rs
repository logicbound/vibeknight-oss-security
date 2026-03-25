use std::collections::HashSet;

/// Configuration for rule execution
/// 
/// Controls which rules are enabled/disabled and their settings
#[derive(Debug, Clone)]
pub struct RuleConfig {
    /// Set of enabled rule IDs
    enabled_rules: HashSet<String>,
    
    /// Set of disabled rule IDs
    disabled_rules: HashSet<String>,
    
    /// Whether to enable all rules by default (if true, only disabled_rules applies)
    enable_all_by_default: bool,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled_rules: HashSet::new(),
            disabled_rules: HashSet::new(),
            enable_all_by_default: true,
        }
    }
}

impl RuleConfig {
    /// Create a new rule configuration
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Enable a specific rule by ID
    pub fn enable_rule(&mut self, rule_id: &str) {
        self.enabled_rules.insert(rule_id.to_string());
        self.disabled_rules.remove(rule_id);
    }
    
    /// Disable a specific rule by ID
    pub fn disable_rule(&mut self, rule_id: &str) {
        self.disabled_rules.insert(rule_id.to_string());
        self.enabled_rules.remove(rule_id);
    }
    
    /// Enable multiple rules
    pub fn enable_rules(&mut self, rule_ids: &[&str]) {
        for rule_id in rule_ids {
            self.enable_rule(rule_id);
        }
    }
    
    /// Disable multiple rules
    pub fn disable_rules(&mut self, rule_ids: &[&str]) {
        for rule_id in rule_ids {
            self.disable_rule(rule_id);
        }
    }
    
    /// Enable all rules (disable the allowlist mode)
    pub fn enable_all(&mut self) {
        self.enable_all_by_default = true;
        self.enabled_rules.clear();
    }
    
    /// Disable all rules except those explicitly enabled (enable allowlist mode)
    pub fn enable_only(&mut self, rule_ids: &[&str]) {
        self.enable_all_by_default = false;
        self.enabled_rules.clear();
        self.enable_rules(rule_ids);
    }
    
    /// Check if a rule is enabled based on the current configuration
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        // If explicitly disabled, it's disabled
        if self.disabled_rules.contains(rule_id) {
            return false;
        }
        
        // If enable_all_by_default is true, rule is enabled unless disabled
        if self.enable_all_by_default {
            return true;
        }
        
        // Otherwise, only enabled if explicitly in enabled_rules
        self.enabled_rules.contains(rule_id)
    }
    
    /// Get all enabled rule IDs
    pub fn enabled_rules(&self) -> &HashSet<String> {
        &self.enabled_rules
    }
    
    /// Get all disabled rule IDs
    pub fn disabled_rules(&self) -> &HashSet<String> {
        &self.disabled_rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_enables_all() {
        let config = RuleConfig::default();
        assert!(config.is_rule_enabled("any-rule"));
    }
    
    #[test]
    fn test_disable_rule() {
        let mut config = RuleConfig::default();
        config.disable_rule("rule1");
        assert!(!config.is_rule_enabled("rule1"));
        assert!(config.is_rule_enabled("rule2"));
    }
    
    #[test]
    fn test_enable_only_mode() {
        let mut config = RuleConfig::default();
        config.enable_only(&["rule1", "rule2"]);
        assert!(config.is_rule_enabled("rule1"));
        assert!(config.is_rule_enabled("rule2"));
        assert!(!config.is_rule_enabled("rule3"));
    }
    
    #[test]
    fn test_explicit_disable_overrides_enable() {
        let mut config = RuleConfig::default();
        config.enable_only(&["rule1"]);
        config.disable_rule("rule1");
        assert!(!config.is_rule_enabled("rule1"));
    }
}

