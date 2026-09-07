//! Ratchet baseline for the Windows call surface, mirroring the spec-lint
//! ratchet: the checked-in list only ever shrinks. A gap absent from it fails
//! the gate on the commit that introduces it, and an entry the tree has since
//! closed fails as stale, so the file cannot drift into a silent disable.

use std::collections::BTreeSet;

const FILE: &str = "tests/windows_call_surface/baseline.txt";
/// Set to rewrite the baseline from the current surface, as `lint-ratchet-update` does.
const UPDATE: &str = "OXIDE_WINDOWS_SURFACE_UPDATE";

fn path() -> String { format!("{}/{FILE}", env!("CARGO_MANIFEST_DIR")) }

/// # C: O(baseline lines)
pub fn load() -> BTreeSet<String> {
    std::fs::read_to_string(path()).unwrap_or_default().lines()
        .map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string).collect()
}

/// Rewrite the baseline when explicitly asked, and report whether it grew.
/// # C: O(current gaps)
pub fn update(current: &BTreeSet<String>) -> bool {
    if std::env::var_os(UPDATE).is_none() { return false; }
    let mut body = String::from("# Windows call-surface gaps still open. Ratchet: entries only leave.\n");
    for key in current { body.push_str(key); body.push('\n'); }
    std::fs::write(path(), body).expect("baseline must be writable");
    true
}
