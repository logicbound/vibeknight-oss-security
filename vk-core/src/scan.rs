use vk_lang_js::scan_js;

pub fn scan_project(path: &str, output: &str) {
    let findings = scan_js(path);
    if findings.is_empty() {
        println!("✅ No issues found.");
    }

    match output {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&findings).unwrap());
        }
        _ => {
            for f in findings {
                println!("⚠️ [{}:{}] {}", f.file, f.line, f.description);
            }
        }
    }
}
