//! Redirect values: what is accepted, and where a lookup goes next.

extern crate alloc;

use alloc::string::ToString;
use syscall::errno::Errno;

use crate::limits::REDIRECT_MAX;

use super::{build, check, rewrite, still_valid, Redirect};

#[test]
fn a_bare_name_is_relative() {
    assert_eq!(check(b"olddir"), Ok(Redirect::Relative("olddir".to_string())));
}

#[test]
fn a_rooted_path_is_absolute() {
    assert_eq!(check(b"/a/b/c"), Ok(Redirect::Absolute("/a/b/c".to_string())));
}

#[test]
fn an_empty_value_is_refused() {
    assert_eq!(check(b""), Err(Errno::Einval));
}

#[test]
fn a_slash_inside_a_relative_name_is_refused() {
    // A relative value names one component of the same parent. Accepting a
    // slash would let an upper layer reach a lower object under a directory
    // the caller never walked through.
    assert_eq!(check(b"a/b"), Err(Errno::Einval));
}

#[test]
fn an_empty_component_is_refused() {
    assert_eq!(check(b"/a//b"), Err(Errno::Einval));
    assert_eq!(check(b"/"), Err(Errno::Einval));
    assert_eq!(check(b"/a/"), Err(Errno::Einval));
}

#[test]
fn a_relative_value_replaces_only_its_own_component() {
    let r = check(b"was").unwrap();
    assert_eq!(rewrite("/top/", &r, "/rest"), "/top/was/rest");
}

#[test]
fn an_absolute_value_replaces_everything_before_it() {
    let r = check(b"/elsewhere").unwrap();
    assert_eq!(rewrite("/top/", &r, "/rest"), "/elsewhere/rest");
}

#[test]
fn a_relative_value_is_the_objects_own_name() {
    assert_eq!(build(&["a", "b", "leaf"], false), Ok(Redirect::Relative("leaf".to_string())));
}

#[test]
fn an_absolute_value_is_the_whole_path() {
    assert_eq!(build(&["a", "b", "leaf"], true), Ok(Redirect::Absolute("/a/b/leaf".to_string())));
}

#[test]
fn an_ancestors_own_absolute_value_wins_over_everything_above_it() {
    // The middle ancestor was itself renamed and recorded where its lower half
    // lives; the path below it hangs off THAT, not off where it now appears.
    assert_eq!(build(&["a", "/moved", "leaf"], true),
               Ok(Redirect::Absolute("/moved/leaf".to_string())));
}

#[test]
fn a_value_too_long_to_store_is_exdev() {
    let long = "x".repeat(REDIRECT_MAX);
    assert_eq!(build(&[&long, &long], true), Err(Errno::Exdev));
}

#[test]
fn a_relative_value_is_not_reusable_when_an_absolute_one_is_needed() {
    let rel = check(b"n").unwrap();
    let abs = check(b"/n").unwrap();
    assert!(still_valid(Some(&rel), false));
    assert!(!still_valid(Some(&rel), true));
    assert!(still_valid(Some(&abs), true));
    assert!(!still_valid(None, false));
}
