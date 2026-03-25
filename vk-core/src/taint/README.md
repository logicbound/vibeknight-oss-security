# Taint Analysis Engine

Comprehensive taint analysis system for tracking data flow from sources to sinks.

## Architecture

### Modules

- **`model.rs`** - Source, Sink, and Sanitizer definitions
- **`graph.rs`** - Intra-procedural dataflow graph construction
- **`propagation.rs`** - Forward taint propagation engine
- **`interprocedural.rs`** - Inter-procedural analysis with function summaries
- **`reachability.rs`** - Control flow reachability analysis

## Taint Model

### TaintKind Enum
- `UserInput` - Forms, query params, user-provided data
- `Network` - HTTP requests, sockets
- `FileSystem` - File reads
- `Env` - Environment variables
- `Cookie` - HTTP cookies
- `Unknown` - Unspecified source

### TaintState
- `Untainted` - No taint
- `Tainted { kinds }` - Tainted with specific kinds
- `Sanitized { original_kinds, sanitizer }` - Taint removed by sanitizer
- `Unknown` - Ambiguous state

## Dataflow Graph

Builds intra-procedural dataflow graphs tracking:
- Variable assignments (`src -> dst`)
- Function arguments → parameters
- Return values → call sites
- Object property flow

## Propagation Engine

### Forward Propagation
1. **Mark Sources**: Identify taint sources in the function
2. **Propagate**: Flow taint through dataflow edges
3. **Sanitize**: Apply sanitization rules

### Sanitization Methods
- `RegexEscape` - Regex escaping
- `ParameterizedQuery` - SQL parameterized queries
- `HtmlEscape` - HTML escaping
- `UrlEncode` - URL encoding

## Inter-Procedural Analysis

- **Function Summaries**: Cache taint propagation summaries per function
- **Summary Application**: Apply summaries at call sites
- **Parameter Tracking**: Track which parameters can be tainted
- **Return Value Tracking**: Track taint in return values

## Reachability

- **Control Flow Graph**: Build CFG from branch/jump instructions
- **Reachability Analysis**: BFS from entry block
- **Sink Filtering**: Only flag sinks reachable from entry

## Usage Example

```rust
use vk_core::taint::*;

// Create propagator with default sources/sinks/sanitizers
let propagator = TaintPropagator::new();

// Build dataflow graph
let graph = DataflowGraph::build_for_function(&function);

// Propagate taint
let taint_map = propagator.propagate(&function, &graph);

// Check for sink reachability
let findings = propagator.check_sink_reachability(&function, &taint_map);

// Inter-procedural analysis
let mut inter_analyzer = InterProceduralAnalyzer::new();
let summary = inter_analyzer.compute_summary(&function, &taint_map);
```

## Integration with Rules

Rules can use the taint analysis engine to detect vulnerabilities:

```rust
impl Rule for SqlInjectionRule {
    fn detect(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let propagator = TaintPropagator::new();
        let graph = DataflowGraph::build_for_function(&function);
        let taint_map = propagator.propagate(&function, &graph);
        let sink_findings = propagator.check_sink_reachability(&function, &taint_map);
        
        // Convert sink findings to security findings
        // ...
    }
}
```

