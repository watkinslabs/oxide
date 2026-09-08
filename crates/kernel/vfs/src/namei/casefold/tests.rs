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

#[test]
fn a_scan_answers_with_the_stored_spelling_and_skips_the_exact_name() {
    struct Entry(&'static str);
    let entries = [Entry("windows"), Entry("Windows"), Entry("Program Files")];
    let mut actor = MatchingName { wanted: "Windows", found: None, scanned: 0 };
    for entry in &entries {
        if !actor.emit(entry.0, 1, FileType::Directory, 0) { break; }
    }
    // "Windows" itself is skipped: an exact lookup already missed it, so the
    // directory listing containing it cannot be the resolution.
    assert_eq!(actor.found.as_deref(), Some("windows"));

    let mut actor = MatchingName { wanted: "SYSTEM32", found: None, scanned: 0 };
    for entry in [Entry("windows"), Entry("system32")] {
        if !actor.emit(entry.0, 1, FileType::Directory, 0) { break; }
    }
    assert_eq!(actor.found.as_deref(), Some("system32"));

    let mut actor = MatchingName { wanted: "absent", found: None, scanned: 0 };
    for entry in &entries {
        if !actor.emit(entry.0, 1, FileType::Directory, 0) { break; }
    }
    assert_eq!(actor.found, None);
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

#[test]
fn dot_entries_never_resolve_by_folding() {
    let mut actor = MatchingName { wanted: ".", found: None, scanned: 0 };
    assert!(actor.emit("..", 1, FileType::Directory, 0));
    assert_eq!(actor.found, None);
}
