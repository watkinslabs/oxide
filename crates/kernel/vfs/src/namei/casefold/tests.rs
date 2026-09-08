use super::*;

#[test]
fn folding_matches_regardless_of_case_and_never_across_different_names() {
    assert!(names_fold_equal("windows", "Windows"));
    assert!(names_fold_equal("KERNEL32.DLL", "kernel32.dll"));
    assert!(names_fold_equal("System32", "SYSTEM32"));
    assert!(names_fold_equal("", ""));
    assert!(!names_fold_equal("windows", "window"));
    assert!(!names_fold_equal("window", "windows"));
    assert!(!names_fold_equal("windows", "windowz"));
    // A prefix must not compare equal in either direction.
    assert!(!names_fold_equal("a", "ab"));
    assert!(!names_fold_equal("ab", "a"));
}

#[test]
fn folding_is_not_limited_to_ascii() {
    assert!(names_fold_equal("Ä", "ä"));
    assert!(names_fold_equal("ÉCOLE", "école"));
    assert!(!names_fold_equal("é", "e"));
}

fn scan(wanted: &str, entries: &[&str]) -> Option<alloc::string::String> {
    let mut actor = MatchingName { wanted, found: None, scanned: 0 };
    for entry in entries {
        if !actor.emit(entry, 1, FileType::Directory, 0) { break; }
    }
    actor.found
}

#[test]
fn a_scan_answers_with_the_stored_spelling_and_skips_the_exact_name() {
    let entries = ["windows", "Windows", "Program Files"];
    // The exact name comes FIRST here on purpose. An exact lookup has already
    // missed it, so answering with it would return a name known not to
    // resolve; the scan must walk past it to the stored spelling.
    assert_eq!(scan("Windows", &["Windows", "windows"]).as_deref(), Some("windows"));
    assert_eq!(scan("windows", &["windows", "Windows"]).as_deref(), Some("Windows"));
    assert_eq!(scan("Windows", &entries).as_deref(), Some("windows"));
    assert_eq!(scan("SYSTEM32", &["windows", "system32"]).as_deref(), Some("system32"));
    assert_eq!(scan("absent", &entries), None);
}

#[test]
fn a_scan_stops_at_the_entry_bound_rather_than_holding_the_walk() {
    let mut actor = MatchingName { wanted: "absent", found: None, scanned: 0 };
    let mut emitted = 0u64;
    while actor.emit("other", 1, FileType::Regular, 0) {
        emitted += 1;
        assert!(emitted <= MAX_SCANNED_ENTRIES, "the scan must be bounded");
    }
    assert_eq!(actor.scanned, MAX_SCANNED_ENTRIES);
    assert_eq!(actor.found, None);
}

/// The walk owns the two directory entries and the empty name; a scan must
/// never be entered for them.
#[test]
fn the_empty_name_and_the_dot_entries_are_never_resolved_by_a_scan() {
    assert!(!resolvable_component(""));
    assert!(!resolvable_component("."));
    assert!(!resolvable_component(".."));
    assert!(resolvable_component("windows"));
    assert!(resolvable_component("..."));
    assert!(resolvable_component("..a"));
}
