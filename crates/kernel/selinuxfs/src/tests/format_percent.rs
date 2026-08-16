// The escape a created object's name arrives in.

use crate::format::percent::percent_decode;
use vfs::VfsError;

#[test]
fn a_plus_is_a_space_and_an_escape_is_its_byte() {
    assert_eq!(percent_decode("plain").unwrap(), "plain");
    assert_eq!(percent_decode("two+words").unwrap(), "two words");
    assert_eq!(percent_decode("two%20words").unwrap(), "two words");
    assert_eq!(percent_decode("a%2Fb").unwrap(), "a/b");
    assert_eq!(percent_decode("a%2fb").unwrap(), "a/b");
    assert_eq!(percent_decode("100%25").unwrap(), "100%");
}

#[test]
fn an_incomplete_escape_is_refused_never_truncated() {
    // Decoding as far as it goes would name a different object than the
    // caller did, and the answer would be attributed to that other one.
    for text in ["name%", "name%2", "%", "%A"] {
        assert_eq!(percent_decode(text).err(), Some(VfsError::Einval), "{text}");
    }
}

#[test]
fn a_non_hexadecimal_escape_is_refused() {
    for text in ["name%zz", "name%2g", "name%g2", "name% 0"] {
        assert_eq!(percent_decode(text).err(), Some(VfsError::Einval), "{text}");
    }
}

#[test]
fn every_escape_in_a_name_is_decoded_not_just_the_first() {
    assert_eq!(percent_decode("%41%42+%43").unwrap(), "AB C");
}
