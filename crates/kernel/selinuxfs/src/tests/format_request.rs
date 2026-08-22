// The request lines the write and transaction nodes parse.

use crate::format::request::{parse_access_request, parse_context_request, parse_create_request,
                             parse_validatetrans_request};
use vfs::VfsError;

#[test]
fn an_access_request_consumes_its_first_three_fields() {
    let r = parse_access_request("u:r:s:s0 u:object_r:t:s0 6 ignored tail").unwrap();
    assert_eq!(r.scontext, "u:r:s:s0");
    assert_eq!(r.tcontext, "u:object_r:t:s0");
    assert_eq!(r.class, 6);
}

#[test]
fn surrounding_whitespace_is_not_a_field() {
    let r = parse_access_request("  a  b   6  \n").unwrap();
    assert_eq!((r.scontext.as_str(), r.tcontext.as_str(), r.class), ("a", "b", 6));
}

#[test]
fn a_request_with_the_wrong_field_count_is_refused() {
    for text in ["", "a", "a b"] {
        assert_eq!(parse_access_request(text).err(), Some(VfsError::Einval), "{text}");
    }
}

#[test]
fn a_non_numeric_or_zero_class_is_refused() {
    assert_eq!(parse_access_request("a b file").err(), Some(VfsError::Einval));
    assert_eq!(parse_access_request("a b 0").err(), Some(VfsError::Einval));
    assert_eq!(parse_create_request("a b file").err(), Some(VfsError::Einval));
    assert_eq!(parse_validatetrans_request("a b file c").err(), Some(VfsError::Einval));
}

#[test]
fn a_create_request_names_the_object_or_does_not() {
    let bare = parse_create_request("a b 6").unwrap();
    assert_eq!(bare.name, None);
    let named = parse_create_request("a b 6 shadow").unwrap();
    assert_eq!(named.name.as_deref(), Some("shadow"));
}

#[test]
fn a_create_request_takes_the_first_optional_name() {
    assert_eq!(parse_create_request("a b").err(), Some(VfsError::Einval));
    assert_eq!(parse_create_request("a b 6 name ignored tail").unwrap().name.as_deref(),
               Some("name"));
}

#[test]
fn a_relabel_validation_consumes_its_first_four_fields() {
    let r = parse_validatetrans_request("old new 6 task ignored tail").unwrap();
    assert_eq!((r.old.as_str(), r.new.as_str(), r.class, r.task.as_str()),
               ("old", "new", 6, "task"));
    assert_eq!(parse_validatetrans_request("old new 6").err(), Some(VfsError::Einval));
}

#[test]
fn a_context_request_is_one_field() {
    assert_eq!(parse_context_request(" u:r:t:s0 ").unwrap(), "u:r:t:s0");
    assert_eq!(parse_context_request("").err(), Some(VfsError::Einval));
    assert_eq!(parse_context_request("a b").err(), Some(VfsError::Einval));
}
