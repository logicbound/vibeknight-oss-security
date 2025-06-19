use vk_lang_js::scan_js;

#[test]
fn detects_simple_taint() {
    let findings = scan_js("tests/fixtures");
    assert!(!findings.is_empty());
}
