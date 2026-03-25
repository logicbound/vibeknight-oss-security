# vk-core: Security Analysis Engine

The core analysis engine for Vibe Knight SAST tool.

## Module Structure

The codebase is organized into focused modules for maintainability:

### Core Modules

- **`rule.rs`** - Defines the `Rule` trait that all security rules must implement
- **`registry.rs`** - Manages registration and lookup of rules
- **`config.rs`** - Handles rule configuration (enable/disable rules)
- **`pipeline.rs`** - Orchestrates rule execution and aggregates findings
- **`scan.rs`** - File system scanning and IR analysis coordination

### Rules Module

- **`rules/mod.rs`** - Module for built-in security rules
- **`rules/sql_injection.rs`** - Example SQL injection detection rule

## Usage Example

```rust
use vk_core::*;
use vk_ir::Program;
use vk_lang_js::lower_to_ir;

// Create a rule registry and register built-in rules
let mut registry = RuleRegistry::new();
for rule in rules::all_rules() {
    registry.register(rule);
}

// Configure which rules to run
let mut config = RuleConfig::default();
config.disable_rule("sql-injection"); // Disable a specific rule
// Or use allowlist mode:
// config.enable_only(&["sql-injection", "xss"]);

// Create the execution pipeline
let pipeline = RulePipeline::new(registry, config);

// Analyze a program
let source = "db.query(userInput);";
let program = lower_to_ir(source);
let findings = pipeline.execute(&program, "test.js");

// Process findings
for finding in findings {
    println!("[{}:{}] {} - {}", 
        finding.file, 
        finding.line, 
        finding.description,
        finding.severity.unwrap_or("unknown")
    );
}
```

## Creating Custom Rules

Implement the `Rule` trait:

```rust
use vk_core::{Rule, Severity};
use vk_ir::Program;
use vk_core::scan::Finding;

pub struct MyCustomRule;

impl Rule for MyCustomRule {
    fn id(&self) -> &'static str {
        "my-custom-rule"
    }
    
    fn name(&self) -> &'static str {
        "My Custom Rule"
    }
    
    fn description(&self) -> &'static str {
        "Detects my custom security issue"
    }
    
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    
    fn analyze(&self, program: &Program, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Your analysis logic here
        // Traverse the IR and detect issues
        
        findings
    }
}
```

## Rule Configuration

The `RuleConfig` supports two modes:

1. **Default mode (allowlist)**: All rules enabled by default, explicitly disable unwanted ones
2. **Allowlist mode**: Only explicitly enabled rules run

```rust
let mut config = RuleConfig::default();

// Disable specific rules
config.disable_rule("sql-injection");

// Enable only specific rules (switches to allowlist mode)
config.enable_only(&["xss", "auth-bypass"]);

// Re-enable all rules
config.enable_all();
```

## Architecture Benefits

- **Separation of Concerns**: Each module has a single responsibility
- **Extensibility**: Easy to add new rules without modifying existing code
- **Testability**: Each component can be tested independently
- **Maintainability**: Clear module boundaries make the codebase easier to navigate
- **Configuration**: Flexible rule enable/disable without code changes

