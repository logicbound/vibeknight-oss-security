use crate::parser::RawEvent;
use crate::state::IngestorState;

/// Install-script names that are execution triggers during `npm install`.
const INSTALL_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

/// Evaluate a raw change event and return a priority score in [0.0, 1.0].
///
/// Returns `None` if no heuristic fired (the event should be dropped).
pub fn score(event: &RawEvent, state: &IngestorState) -> Option<f32> {
    let mut priority: f32 = 0.0;

    // +0.6 for any install-lifecycle script
    if event.scripts.iter().any(|s| INSTALL_SCRIPTS.contains(&s.as_str())) {
        priority += 0.6;
    }

    // +0.2 for a version that has not been seen before
    let key = format!("{}@{}", event.package, event.version);
    if !state.seen.contains_key(&key) {
        priority += 0.2;
    }

    // +0.2 for a suspicious/obfuscated package name
    if looks_obfuscated(&event.package) {
        priority += 0.2;
    }

    if priority > 0.0 {
        Some(priority.min(1.0))
    } else {
        None
    }
}

/// Heuristic: a name that looks randomly generated or obfuscated.
///
/// Signals:
/// - very short (≤ 3 chars)
/// - consists only of hex-like characters
/// - contains high-entropy-looking substring (many mixed case + digits)
fn looks_obfuscated(name: &str) -> bool {
    let name = name.trim_start_matches('@').split('/').last().unwrap_or(name);

    if name.len() <= 3 {
        return true;
    }

    // All hex chars and length that looks like a hash fragment
    let hex_chars: usize = name
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .count();
    if name.len() >= 8 && hex_chars == name.len() {
        return true;
    }

    false
}
