// The `%` specifier table: what each one interpolates, and how a component
// that could change the destination directory is neutralised.

use crate::coredump::pattern::{expand, CoreKind};

use super::victim;

fn file(p: &[u8]) -> alloc::vec::Vec<u8> { expand(p, &victim(), CoreKind::File).text }

#[test]
fn text_outside_a_specifier_is_copied_verbatim() {
    assert_eq!(file(b"/var/crash/core"), b"/var/crash/core");
    assert_eq!(file(b""), b"");
}

#[test]
fn every_identity_specifier_interpolates_its_own_number() {
    // The namespace-visible and global ids are DIFFERENT values, so a pattern
    // that asks for one must not silently get the other.
    assert_eq!(file(b"%p"), b"42");
    assert_eq!(file(b"%P"), b"4242");
    assert_eq!(file(b"%i"), b"43");
    assert_eq!(file(b"%I"), b"4243");
    assert_eq!(file(b"%u"), b"1000");
    assert_eq!(file(b"%g"), b"100");
    assert_eq!(file(b"%s"), b"11");
    assert_eq!(file(b"%d"), b"1");
    assert_eq!(file(b"%t"), b"1700000000");
    assert_eq!(file(b"%C"), b"3");
    assert_eq!(file(b"%c"), b"18446744073709551615");
}

#[test]
fn the_name_specifiers_are_distinct() {
    // `%e` is the command name, `%E` the whole program path, `%f` its last
    // component. Collapsing them loses the directory a crash came from.
    assert_eq!(file(b"%e"), b"bash");
    assert_eq!(file(b"%f"), b"bash");
    assert_eq!(file(b"%E"), b"!usr!bin!bash");
    assert_eq!(file(b"%h"), b"oxide");
}

#[test]
fn an_interpolated_component_cannot_escape_its_directory() {
    let mut cx = victim();
    // A program that renamed itself to a path fragment must not be able to
    // steer the dump into another directory.
    cx.comm = b"../../etc/passwd".to_vec();
    assert_eq!(expand(b"%e", &cx, CoreKind::File).text, b"..!..!etc!passwd");
    cx.comm = b"..".to_vec();
    assert_eq!(expand(b"%e", &cx, CoreKind::File).text, b"!.");
    cx.comm = b".".to_vec();
    assert_eq!(expand(b"%e", &cx, CoreKind::File).text, b"!");
    // An empty component would collapse two separators into one.
    cx.comm = Vec::new();
    assert_eq!(expand(b"core.%e.x", &cx, CoreKind::File).text, b"core.!.x");
}

#[test]
fn a_doubled_percent_is_one_literal() {
    assert_eq!(file(b"%%"), b"%");
    assert_eq!(file(b"a%%b"), b"a%b");
}

#[test]
fn an_unknown_specifier_contributes_nothing() {
    // A pattern written for a newer kernel degrades rather than failing.
    assert_eq!(file(b"a%zb"), b"ab");
}

#[test]
fn a_trailing_percent_is_dropped() {
    assert_eq!(file(b"core%"), b"core");
    assert_eq!(file(b"%"), b"");
}

#[test]
fn a_process_descriptor_is_only_offered_to_a_program() {
    // There is nowhere to put a descriptor when the dump goes to a file, so the
    // specifier expands to nothing and no descriptor is requested.
    let f = expand(b"%F", &victim(), CoreKind::File);
    assert_eq!(f.text, b"");
    assert!(!f.wants_pidfd);
    let p = expand(b"%F", &victim(), CoreKind::Pipe);
    assert_eq!(p.text, b"3");
    assert!(p.wants_pidfd);
}

use alloc::vec::Vec;
