//! Which attributes are hidden and which are copied.

extern crate alloc;

use crate::config::Config;
use crate::uapi::Marker;

use super::{is_escaped, is_private, must_copy, name};

/// A configuration with the markers in the unprivileged namespace.
fn user() -> Config { Config { userxattr: true, ..Config::default() } }

#[test]
fn marker_names_carry_the_mount_prefix() {
    assert_eq!(name(&Config::default(), Marker::Opaque), "trusted.overlay.opaque");
    assert_eq!(name(&user(), Marker::Opaque), "user.overlay.opaque");
    assert_eq!(name(&Config::default(), Marker::Xwhiteout), "trusted.overlay.whiteout");
}

#[test]
fn every_marker_has_a_distinct_name() {
    let all = [Marker::Opaque, Marker::Redirect, Marker::Origin, Marker::Impure, Marker::Nlink,
               Marker::Upper, Marker::Uuid, Marker::Metacopy, Marker::Protattr, Marker::Xwhiteout];
    let mut seen = alloc::vec::Vec::new();
    for m in all { let n = name(&Config::default(), m); assert!(!seen.contains(&n)); seen.push(n); }
    assert_eq!(seen.len(), 10);
}

#[test]
fn a_marker_is_private() {
    let c = Config::default();
    assert!(is_private(&c, "trusted.overlay.opaque"));
    assert!(is_private(&c, "trusted.overlay.origin"));
}

#[test]
fn an_unrelated_attribute_is_not() {
    let c = Config::default();
    assert!(!is_private(&c, "user.mime_type"));
    assert!(!is_private(&c, "security.selinux"));
    assert!(!is_private(&c, "user.overlay.opaque"));
}

#[test]
fn the_doubled_namespace_escapes_an_objects_own_attribute() {
    let c = Config::default();
    assert!(is_escaped(&c, "trusted.overlay.overlay.opaque"));
    assert!(!is_private(&c, "trusted.overlay.overlay.opaque"));
}

#[test]
fn the_bare_doubled_name_is_escaped_too_under_trusted() {
    // The trusted form is matched one character short of the doubled prefix,
    // so a layer carrying the bare name is still passed through rather than
    // swallowed as a marker. The unprivileged form is matched in full.
    assert!(is_escaped(&Config::default(), "trusted.overlay.overlay"));
    assert!(!is_escaped(&user(), "user.overlay.overlay"));
    assert!(is_escaped(&user(), "user.overlay.overlay."));
}

#[test]
fn the_user_namespace_swaps_which_side_is_private() {
    let c = user();
    assert!(is_private(&c, "user.overlay.opaque"));
    assert!(!is_private(&c, "trusted.overlay.opaque"));
}

#[test]
fn access_control_and_security_must_survive_copy_up() {
    assert!(must_copy("system.posix_acl_access"));
    assert!(must_copy("system.posix_acl_default"));
    assert!(must_copy("security.selinux"));
    assert!(must_copy("security.capability"));
    assert!(!must_copy("user.mime_type"));
    assert!(!must_copy("system.something_else"));
}
