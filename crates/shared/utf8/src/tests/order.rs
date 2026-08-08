// Canonical ordering of combining marks, ignorable handling, and the
// algorithmic Hangul path.
//
// Dot below is combining class 220 and acute above is 230, so canonical order
// sorts them ascending whatever order they were typed in. Soft hyphen
// (`\u{ad}`) is ignorable: it contributes nothing, but is a starter.

use super::fold::enc;
use crate::{casefold_eq, casefold_hash};

fn eq(a: &str, b: &str) -> bool { casefold_eq(&enc(), a.as_bytes(), b.as_bytes()).unwrap() }

#[test]
fn combining_marks_are_canonically_ordered() {
    assert!(eq("q\u{323}\u{301}", "q\u{301}\u{323}"));
    // A precomposed base plus a trailing lower mark reaches the same sequence
    // as the fully decomposed spelling.
    assert!(eq("\u{e9}\u{323}", "e\u{323}\u{301}"));
}

#[test]
fn ordering_does_not_erase_distinctions() {
    // Different marks, not a reordering.
    assert!(!eq("q\u{323}", "q\u{316}"));
    // Same marks on different bases.
    assert!(!eq("q\u{323}\u{301}", "p\u{301}\u{323}"));
    // Two marks of the SAME class (both 220) keep the order they were written
    // in -- the sort is stable, so these are two different names.
    assert!(!eq("a\u{316}\u{323}", "a\u{323}\u{316}"));
}

#[test]
fn a_starter_separates_runs() {
    // The marks decorate different bases; swapping them across the starter
    // names a different file.
    assert!(!eq("a\u{301}b\u{323}", "a\u{323}b\u{301}"));
}

#[test]
fn ignorables_vanish_but_still_break_a_run() {
    assert!(eq("a\u{ad}b", "ab"));
    assert!(eq("A\u{ad}B", "ab"));
    assert!(eq("e\u{301}\u{ad}", "é"));
    assert!(eq("\u{ad}", ""));
    // Marks either side of an ignorable are in different runs and cannot
    // reorder across it -- dropping the ignorable without breaking the run
    // would wrongly equate these two names.
    assert!(!eq("e\u{301}\u{ad}\u{323}", "e\u{323}\u{ad}\u{301}"));
}

#[test]
fn hangul_syllables_decompose_algorithmically() {
    assert!(eq("가", "\u{1100}\u{1161}"));
    assert!(eq("한", "\u{1112}\u{1161}\u{11ab}"));
    assert!(eq("한국", "\u{1112}\u{1161}\u{11ab}\u{1100}\u{116e}\u{11a8}"));
    assert!(!eq("한", "\u{1112}\u{1161}"));
    let e = enc();
    assert_eq!(casefold_hash(&e, "가".as_bytes()).unwrap(),
               casefold_hash(&e, "\u{1100}\u{1161}".as_bytes()).unwrap());
}

#[test]
fn a_name_of_many_runs_normalizes_the_same_as_a_short_one() {
    const UPPER: &str = "Q\u{323}\u{301}Q\u{323}\u{301}Q\u{323}\u{301}Q\u{323}\u{301}";
    const LOWER: &str = "q\u{301}\u{323}q\u{301}\u{323}q\u{301}\u{323}q\u{301}\u{323}";
    assert!(eq(UPPER, LOWER));
    assert!(!eq(UPPER, "q\u{301}\u{323}"));
    let e = enc();
    assert_eq!(casefold_hash(&e, UPPER.as_bytes()).unwrap(),
               casefold_hash(&e, LOWER.as_bytes()).unwrap());
}
