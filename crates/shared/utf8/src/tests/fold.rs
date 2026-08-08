// Case-folded equality. Every expectation here is the Unicode contract the
// generator cross-checks against the character database in its own self-test.

use crate::{casefold_eq, casefold_hash, casefold_into, normalize_eq, Encoding, FoldError};

pub(super) fn enc() -> Encoding { Encoding::from_charset("utf8").unwrap() }

fn eq(a: &str, b: &str) -> bool { casefold_eq(&enc(), a.as_bytes(), b.as_bytes()).unwrap() }

fn hashes_match(a: &str, b: &str) -> bool {
    let e = enc();
    casefold_hash(&e, a.as_bytes()).unwrap() == casefold_hash(&e, b.as_bytes()).unwrap()
}

#[test]
fn ascii_case_folds() {
    assert!(eq("ABC", "abc"));
    assert!(eq("README.TXT", "readme.txt"));
    assert!(!eq("abc", "abd"));
    assert!(!eq("abc", "abcd"));
    assert!(!eq("", "a"));
    assert!(eq("", ""));
}

#[test]
fn non_ascii_case_folds() {
    assert!(eq("ÉCOLE", "école"));
    assert!(eq("ПРИВЕТ", "привет"));
    assert!(eq("ΑΘΗΝΑ", "αθηνα"));
    assert!(!eq("é", "è"));
    // Latin `a` and Cyrillic `а` look alike and are different files.
    assert!(!eq("a", "а"));
}

#[test]
fn full_fold_expands_multi_character_cases() {
    // Full (C+F) folding, not simple folding: sharp s folds to `ss`.
    assert!(eq("STRASSE", "straße"));
    assert!(eq("ẞ", "ss"));
    // Capital dotted I folds to `i` plus a combining dot above.
    assert!(eq("İ", "i\u{307}"));
    // Final and medial sigma fold together.
    assert!(eq("Σ", "ς"));
    assert!(eq("σ", "ς"));
}

#[test]
fn precomposed_and_decomposed_spellings_are_one_name() {
    assert!(eq("é", "e\u{301}"));
    assert!(eq("É", "e\u{301}"));
    assert!(normalize_eq(&enc(), "é".as_bytes(), "e\u{301}".as_bytes()).unwrap());
    // ...but the case-sensitive form still separates case.
    assert!(!normalize_eq(&enc(), "É".as_bytes(), "e\u{301}".as_bytes()).unwrap());
}

#[test]
fn hash_matches_the_comparison() {
    assert!(hashes_match("ABC", "abc"));
    assert!(hashes_match("é", "e\u{301}"));
    assert!(hashes_match("STRASSE", "straße"));
    assert!(!hashes_match("abc", "abd"));
}

#[test]
fn fold_into_buffer_matches_a_folded_name() {
    let e = enc();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let na = casefold_into(&e, "ÉCOLE".as_bytes(), &mut a).unwrap();
    let nb = casefold_into(&e, "école".as_bytes(), &mut b).unwrap();
    assert_eq!(&a[..na], &b[..nb]);
    assert_eq!(casefold_into(&e, "école".as_bytes(), &mut [0u8; 2]), Err(FoldError::NoSpace));
}
