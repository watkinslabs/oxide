// Folding, hashing and matching one query name.
//
// The hash is the load-bearing part. A directory entry stores the hash of the
// FOLDED name, so a query hashed from its raw bytes searches a bucket the
// entry is not in and the name reads as absent while a listing still shows it.

use syscall::errno::Errno;

use crate::casefold::{Fold, Query};
use crate::hash::name_hash;

use super::fixture::{lenient, strict};

/// Invalid UTF-8: a lone continuation byte cannot start a sequence.
const BAD: &[u8] = b"bad\xffname";

#[test]
fn ascii_case_variants_are_one_name() {
    let cf = lenient();
    let q = Query::prepare(&cf, b"README.TXT").unwrap();
    assert_eq!(q.kind(), Fold::Folded);
    assert!(q.matches(b"README.TXT"));
    assert!(q.matches(b"readme.txt"));
    assert!(q.matches(b"ReadMe.Txt"));
    assert!(!q.matches(b"readme.txtx"));
    assert!(!q.matches(b"readme"));
    assert!(!q.matches(b""));
}

#[test]
fn non_ascii_case_variants_are_one_name() {
    let cf = lenient();
    let q = Query::prepare(&cf, "ÉCOLE".as_bytes()).unwrap();
    assert!(q.matches("école".as_bytes()));
    assert!(q.matches("École".as_bytes()));
    assert!(q.matches("ÉCOLE".as_bytes()));
    // A precomposed query still matches a decomposed entry.
    assert!(q.matches("e\u{301}cole".as_bytes()));
    assert!(!q.matches("ecole".as_bytes()));

    let cyr = Query::prepare(&cf, "ПРИВЕТ".as_bytes()).unwrap();
    assert!(cyr.matches("привет".as_bytes()));
    // Latin `a` and Cyrillic `а` look alike and are different files.
    let lat = Query::prepare(&cf, "a".as_bytes()).unwrap();
    assert!(!lat.matches("а".as_bytes()));
}

#[test]
fn folding_can_change_the_byte_length_of_a_name() {
    let cf = lenient();
    // Capital sharp s is three bytes and folds to two.
    let q = Query::prepare(&cf, "ẞ".as_bytes()).unwrap();
    assert_eq!(q.name().len(), 3);
    assert_eq!(q.folded(), b"ss");
    assert!(q.matches(b"ss"));
    assert!(q.matches("ß".as_bytes()));

    // Capital dotted I is two bytes and folds to three.
    let dotted = Query::prepare(&cf, "İ".as_bytes()).unwrap();
    assert_eq!(dotted.name().len(), 2);
    assert_eq!(dotted.folded().len(), 3);
    assert!(dotted.matches("i\u{307}".as_bytes()));
}

#[test]
fn the_hash_is_over_the_folded_name_not_the_stored_bytes() {
    let cf = lenient();
    let upper = Query::prepare(&cf, b"README").unwrap();
    let lower = Query::prepare(&cf, b"readme").unwrap();
    assert_eq!(upper.folded(), b"readme");
    // The two spellings must land in one bucket.
    assert_eq!(upper.hash(), lower.hash());
    // ...and that bucket is the folded name's, not the query's own bytes'.
    assert_eq!(upper.hash(), name_hash(b"readme"));
    assert_ne!(upper.hash(), name_hash(b"README"));
}

#[test]
fn genuinely_different_names_hash_apart() {
    let cf = lenient();
    let a = Query::prepare(&cf, b"readme").unwrap();
    let b = Query::prepare(&cf, b"license").unwrap();
    let c = Query::prepare(&cf, b"readme2").unwrap();
    assert_ne!(a.hash(), b.hash());
    assert_ne!(a.hash(), c.hash());
    assert_ne!(b.hash(), c.hash());
    assert!(!a.matches(b"license"));
}

#[test]
fn a_multi_character_fold_hashes_with_its_expansion() {
    let cf = lenient();
    let sharp = Query::prepare(&cf, "STRASSE".as_bytes()).unwrap();
    let eszett = Query::prepare(&cf, "straße".as_bytes()).unwrap();
    assert_eq!(sharp.hash(), eszett.hash());
    assert_eq!(sharp.hash(), name_hash(b"strasse"));
    // The raw bytes of the two spellings differ, so a raw hash would not.
    assert_ne!(name_hash("straße".as_bytes()), name_hash(b"strasse"));
}

#[test]
fn dot_and_dotdot_are_never_folded() {
    let cf = lenient();
    for n in [&b"."[..], &b".."[..]] {
        let q = Query::prepare(&cf, n).unwrap();
        assert_eq!(q.kind(), Fold::DotName);
        assert_eq!(q.hash(), 0);
        assert_eq!(q.folded(), b"");
        assert!(q.matches(n));
    }
    let dot = Query::prepare(&cf, b".").unwrap();
    assert!(!dot.matches(b".."));
    let dotdot = Query::prepare(&cf, b"..").unwrap();
    assert!(!dotdot.matches(b"."));
    // A name that merely begins with a dot is an ordinary name.
    let hidden = Query::prepare(&cf, b".bashrc").unwrap();
    assert_eq!(hidden.kind(), Fold::Folded);
    assert_ne!(hidden.hash(), 0);
    assert!(hidden.matches(b".BASHRC"));
}

#[test]
fn a_name_the_encoding_cannot_read_is_opaque_bytes_when_permitted() {
    let cf = lenient();
    let q = Query::prepare(&cf, BAD).unwrap();
    assert_eq!(q.kind(), Fold::Opaque);
    assert_eq!(q.folded(), b"");
    // Hashed and compared raw, so the entry is still reachable by its bytes.
    assert_eq!(q.hash(), name_hash(BAD));
    assert!(q.matches(BAD));
    // No folding is applied to it, so no case variant matches.
    assert!(!q.matches(b"BAD\xffNAME"));
}

#[test]
fn a_name_the_encoding_cannot_read_is_an_error_under_strict_encoding() {
    let cf = strict();
    assert_eq!(Query::prepare(&cf, BAD).err(), Some(Errno::Einval));
    assert_eq!(Query::prepare(&cf, b"\xff").err(), Some(Errno::Einval));
    assert_eq!(Query::prepare(&cf, b"\xc3").err(), Some(Errno::Einval));
    // Valid names are unaffected by the flag, and fold identically.
    let ok = Query::prepare(&cf, b"README").unwrap();
    assert_eq!(ok.kind(), Fold::Folded);
    assert_eq!(ok.hash(), Query::prepare(&lenient(), b"README").unwrap().hash());
    // The exempt names are not Unicode-checked at all, so strictness is moot.
    assert_eq!(Query::prepare(&cf, b".").unwrap().kind(), Fold::DotName);
    assert_eq!(Query::prepare(&cf, b"..").unwrap().kind(), Fold::DotName);
}

#[test]
fn an_entry_whose_own_name_is_unreadable_hides_nothing() {
    // One corrupt or foreign-encoded entry must not fail the lookup, or every
    // other name in the directory becomes unreachable.
    let cf = lenient();
    let q = Query::prepare(&cf, b"readme").unwrap();
    assert!(!q.matches(BAD));
    assert!(!q.matches(b"\xff\xfe"));
    assert!(q.matches(b"README"));
}

#[test]
fn an_exactly_spelled_name_matches_without_consulting_the_table() {
    // Byte equality is the common case and answers even for names the
    // encoding cannot read.
    let cf = lenient();
    let q = Query::prepare(&cf, BAD).unwrap();
    assert!(q.matches(BAD));
    let empty = Query::prepare(&cf, b"").unwrap();
    assert!(empty.matches(b""));
    assert!(!empty.matches(b"a"));
}

#[test]
fn a_fold_that_would_not_fit_an_entry_name_degrades_like_an_unreadable_one() {
    // Every folded byte has to fit the width an entry name is stored in.
    // A name that folds past it cannot be stored folded, so it is treated as
    // one the encoding cannot produce.
    let mut long = alloc::vec::Vec::new();
    for _ in 0..128 { long.extend_from_slice("ẞ".as_bytes()); }  // 384 bytes raw
    let cf = lenient();
    let q = Query::prepare(&cf, &long).unwrap();
    assert_eq!(q.kind(), Fold::Opaque);
    assert_eq!(q.hash(), name_hash(&long));
    assert_eq!(Query::prepare(&strict(), &long).err(), Some(Errno::Einval));
}
