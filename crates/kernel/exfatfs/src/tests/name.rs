use super::*;
use crate::upcase;
use syscall::errno::Errno;

fn table() -> crate::upcase::UpCase { upcase::builtin() }

#[test]
fn a_name_encodes_to_utf16_units() {
    let n = encode(&table(), "abc").unwrap();
    assert_eq!(n.units, alloc::vec![0x61, 0x62, 0x63]);
    assert_eq!(n.len(), 3);
}

#[test]
fn the_hash_is_taken_over_the_upcased_name() {
    // Which is what makes a lookup spelled in any case produce the hash the
    // entry recorded.
    let t = table();
    assert_eq!(encode(&t, "readme").unwrap().hash, encode(&t, "README").unwrap().hash);
    assert_ne!(encode(&t, "readme").unwrap().hash, encode(&t, "readm").unwrap().hash);
}

#[test]
fn a_name_of_nothing_is_refused() {
    assert_eq!(encode(&table(), "").unwrap_err(), Errno::Enoent);
}

#[test]
fn a_name_past_the_length_ceiling_is_refused() {
    let long: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert_eq!(encode(&table(), &long).unwrap_err(), Errno::Enametoolong);
    let at_limit: alloc::string::String = core::iter::repeat('x').take(255).collect();
    assert!(encode(&table(), &at_limit).is_ok());
}

#[test]
fn the_characters_the_format_refuses_are_refused_on_create() {
    for bad in ["a\"b", "a*b", "a/b", "a:b", "a<b", "a>b", "a?b", "a\\b", "a|b", "a\u{1}b"] {
        assert_eq!(encode(&table(), bad).unwrap_err(), Errno::Einval, "{bad:?}");
    }
}

#[test]
fn a_name_a_medium_already_holds_can_still_be_looked_up() {
    // A refusal on lookup would make a name another system wrote unreachable,
    // which is worse than being able to name it.
    let n = resolve(&table(), "a:b", false, Usage::Lookup).unwrap();
    assert_eq!(n.len(), 3);
}

#[test]
fn trailing_dots_are_removed_by_default() {
    let t = table();
    assert_eq!(resolve(&t, "name...", false, Usage::Create).unwrap().units,
               resolve(&t, "name", false, Usage::Create).unwrap().units);
}

#[test]
fn keeping_trailing_dots_still_refuses_to_create_one() {
    // Windows cannot address such a name; a mount that keeps them can find
    // one that is already there but may not make a new one.
    let t = table();
    assert_eq!(resolve(&t, "name.", true, Usage::Create).unwrap_err(), Errno::Einval);
    assert_eq!(resolve(&t, "name.", true, Usage::Lookup).unwrap().len(), 5);
}

#[test]
fn a_name_of_nothing_but_dots_has_no_name_left() {
    assert_eq!(resolve(&table(), "...", false, Usage::Create).unwrap_err(), Errno::Enoent);
}

#[test]
fn a_name_spans_as_many_entries_as_it_needs() {
    assert_eq!(name_entries(1), 1);
    assert_eq!(name_entries(15), 1);
    assert_eq!(name_entries(16), 2);
    assert_eq!(name_entries(255), 17);
}

#[test]
fn a_set_is_two_entries_plus_its_name_entries() {
    assert_eq!(entry_count(1), Ok(3));
    assert_eq!(entry_count(15), Ok(3));
    assert_eq!(entry_count(16), Ok(4));
    // Nineteen is the widest set the format admits.
    assert_eq!(entry_count(255), Ok(19));
    assert_eq!(entry_count(0), Err(Errno::Einval));
    assert_eq!(entry_count(256), Err(Errno::Einval));
}

#[test]
fn stored_units_decode_back_to_the_name() {
    assert_eq!(decode(&[0x48, 0x69]), "Hi");
    // A surrogate with no pair is replaced rather than making the whole
    // directory unreadable.
    assert_eq!(decode(&[0xD800]), "\u{FFFD}");
}

#[test]
fn a_name_outside_the_basic_plane_round_trips_as_a_surrogate_pair() {
    let t = table();
    let n = encode(&t, "a\u{1F600}b").unwrap();
    assert_eq!(n.len(), 4);
    assert_eq!(decode(&n.units), "a\u{1F600}b");
}
