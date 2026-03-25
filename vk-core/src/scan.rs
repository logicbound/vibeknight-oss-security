use std::fs;
use std::path::Path;
use crate::pipeline::RulePipeline;
use crate::registry::RuleRegistry;
use crate::config::RuleConfig;
use crate::rules;
use crate::language::LanguageRegistry;
use crate::languages;
use crate::finding::Finding;
use crate::context::AnalysisContext;
use crate::rule::Severity;
use serde::{Serialize, Deserialize};
use macros::dbg_eprintln;

/// Scan report containing findings and summary statistics
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScanReport {
    /// List of security findings
    findings: Vec<Finding>,
    /// Summary statistics
    summary: ScanSummary,
}

/// Summary statistics for a scan
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScanSummary {
    /// Total number of findings
    total: usize,
    /// Count of findings by severity
    by_severity: SeverityCounts,
}

/// Count of findings grouped by severity
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

/// Scan a project directory and return findings
pub fn scan_project(path: &str, output: &str, exclude_patterns: &[String]) {
    let findings = scan_directory(path, exclude_patterns);
    
    // Calculate summary statistics
    let summary = calculate_summary(&findings);
    
    match output {
        "json" => {
            // Determine the output directory (use the scanned path, or its parent if it's a file)
            let scan_path = Path::new(path);
            let output_dir = if scan_path.is_file() {
                scan_path.parent().unwrap_or(Path::new("."))
            } else {
                scan_path
            };
            
            // Create output file path
            let output_file = output_dir.join("vibeknight-report.json");
            
            // Create scan report with findings and summary
            let report = ScanReport {
                findings: findings.clone(),
                summary: summary.clone(),
            };
            
            // Serialize report to JSON
            let json_output = match serde_json::to_string_pretty(&report) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error serializing findings to JSON: {}", e);
                    return;
                }
            };
            
            // Write to file
            match fs::write(&output_file, json_output) {
                Ok(_) => {
                    println!("✅ Scan complete. Report saved to: {}", output_file.display());
                    print_summary(&summary);
                }
                Err(e) => {
                    eprintln!("Error writing JSON report to {}: {}", output_file.display(), e);
                }
            }
        }
        _ => {
            if findings.is_empty() {
                println!("✅ No issues found.");
            } else {
                for f in &findings {
                    println!("⚠️ [{}] {}:{} - {}", 
                        f.severity.as_str(), 
                        f.file, 
                        f.line, 
                        f.title
                    );
                    println!("   {}", f.description);
                    if let Some(ref data_flow) = f.data_flow {
                        println!("   Data Flow:\n{}", data_flow.render());
                    }
                    if let Some(ref fix) = f.fix {
                        println!("   {}", fix.render());
                    }
                }
                
                // Print summary at the end
                println!("\n{}", "=".repeat(60));
                print_summary(&summary);
            }
        }
    }
}

/// Calculate summary statistics from findings
fn calculate_summary(findings: &[Finding]) -> ScanSummary {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }
    
    ScanSummary {
        total: findings.len(),
        by_severity: counts,
    }
}

/// Print summary statistics to console
fn print_summary(summary: &ScanSummary) {
    println!("📊 Scan Summary:");
    println!("   Total findings: {}", summary.total);
    
    if summary.total > 0 {
        println!("   By severity:");
        if summary.by_severity.critical > 0 {
            println!("     🔴 Critical: {}", summary.by_severity.critical);
        }
        if summary.by_severity.high > 0 {
            println!("     🟠 High: {}", summary.by_severity.high);
        }
        if summary.by_severity.medium > 0 {
            println!("     🟡 Medium: {}", summary.by_severity.medium);
        }
        if summary.by_severity.low > 0 {
            println!("     🔵 Low: {}", summary.by_severity.low);
        }
        if summary.by_severity.info > 0 {
            println!("     ⚪ Info: {}", summary.by_severity.info);
        }
    }
}

fn scan_directory(path: &str, exclude_patterns: &[String]) -> Vec<Finding> {
    // Create pipeline once for all files (more efficient)
    let pipeline = create_pipeline();
    
    // Create language registry with all built-in frontends
    let mut language_registry = LanguageRegistry::new();
    for frontend in languages::all_frontends() {
        language_registry.register(frontend);
    }
    
    let mut findings = Vec::new();
    walk(Path::new(path), &mut findings, &pipeline, &language_registry, exclude_patterns);
    findings
}

fn walk(
    path: &Path,
    findings: &mut Vec<Finding>,
    pipeline: &RulePipeline,
    language_registry: &LanguageRegistry,
    exclude_patterns: &[String],
) {
    // Check if this path should be excluded
    if should_exclude(path, exclude_patterns) {
        return;
    }
    
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            
            // Skip hidden files/directories (starting with .)
            if p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with('.'))
                .unwrap_or(false)
            {
                continue;
            }
            
            walk(&p, findings, pipeline, language_registry, exclude_patterns);
        }
    } else {
        // Check if any language frontend can handle this file
        if language_registry.can_handle_file(path) {
            let result = check_file(path, pipeline, language_registry);
            findings.extend(result);
        }
    }
}

/// Check if a path should be excluded based on exclude patterns
fn should_exclude(path: &Path, exclude_patterns: &[String]) -> bool {
    if exclude_patterns.is_empty() {
        return false;
    }
    
    // Convert path to string for pattern matching
    let path_str = path.to_string_lossy();
    
    // Check if any exclude pattern matches
    for pattern in exclude_patterns {
        // Simple substring matching - check if pattern appears in the path
        // This handles both folder names and partial paths
        if path_str.contains(pattern) {
            return true;
        }
        
        // Also check if the last component (file/folder name) matches
        if let Some(file_name) = path.file_name()
            .and_then(|n| n.to_str())
        {
            if file_name == pattern {
                return true;
            }
        }
    }
    
    false
}

/// Create a rule pipeline with all built-in rules registered
fn create_pipeline() -> RulePipeline {
    let mut registry = RuleRegistry::new();
    
    // Register all built-in rules
    for rule in rules::all_rules() {
        registry.register(rule);
    }
    
    // Use default config (all rules enabled)
    let config = RuleConfig::default();
    
    RulePipeline::new(registry, config)
}

fn check_file(path: &Path, pipeline: &RulePipeline, language_registry: &LanguageRegistry) -> Vec<Finding> {
    println!("Checking file: {}", path.display());
    let text = fs::read_to_string(path).unwrap_or_default();
    
    // Find the appropriate language frontend
    let frontend = match language_registry.find_frontend(path) {
        Some(f) => f,
        None => {
            dbg_eprintln!("Warning: No language frontend found for {}", path.display());
            return Vec::new();
        }
    };
    
    // Lower source code to IR using the language-specific frontend
    let file_path_str = path.to_string_lossy().to_string();
    let program = frontend.lower_to_ir(&text, &file_path_str);
    
    // Get pattern provider from the language frontend
    let pattern_provider = frontend.pattern_provider();
    
    // Create analysis context with language-specific patterns
    let ctx = AnalysisContext::new(
        &program,
        file_path_str.clone(),
        frontend.id(),
        pattern_provider.as_ref(),
    );
    
    // Use rule pipeline to analyze the IR program
    // The pipeline executes all enabled rules which analyze the IR
    // Rules are language-agnostic - they work on the IR but use language-specific patterns
    pipeline.execute_with_context(&ctx)
}

// Legacy scan_ir function removed - now using rule pipeline
// The rule engine handles all analysis through registered rules
