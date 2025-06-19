use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use serde::Serialize;

use std::fs;
use std::path::Path;

#[derive(Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub description: String,
}

pub fn scan_js(path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    walk(Path::new(path), &mut findings);
    findings
}

fn walk(path: &Path, findings: &mut Vec<Finding>) {
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.file_name().unwrap().to_str().unwrap().starts_with('.') {
                continue;
            }
            walk(&p, findings);
        }
    } else if path
        .extension()
        .map(|e| e == "js" || e == "ts")
        .unwrap_or(false)
    {
        check_file(path, findings);
    }
}

fn check_file(path: &Path, findings: &mut Vec<Finding>) {
    let text = fs::read_to_string(path).unwrap_or_default();
    let allocator = Allocator::default();
    let source_type = SourceType::default();
    let parser = Parser::new(&allocator, &text, source_type);
    let _program = parser.parse();

    if text.contains("req.query") && text.contains("db.query") {
        findings.push(Finding {
            file: path.to_string_lossy().into(),
            line: 1,
            description: "Possible unvalidated user input in DB query".into(),
        });
    }
}
