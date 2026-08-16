//! Which extended attributes are the overlay's own, and which belong to the
//! object.
//!
//! The private markers share a namespace with attributes a caller may legally
//! set, so the split has to be exact in both directions. Leaking a marker into
//! `listxattr` tells a `tar` of the overlay to write a marker into the archive
//! — restoring which produces a file that is invisible. Hiding an attribute
//! that merely LOOKS like one loses it on copy-up.
//!
//! The escape is what makes the two separable: an object that genuinely wants
//! an attribute in the overlay's namespace has it stored with the namespace
//! written twice, and only the doubled form is passed through.

extern crate alloc;

use alloc::format;
use alloc::string::String;

use crate::config::Config;
use crate::uapi::{Marker, XATTR_NAMESPACE, XATTR_TRUSTED_PREFIX, XATTR_USER_PREFIX};

/// Full attribute name of one marker under this mount's namespace. # C: O(1)
pub fn name(config: &Config, marker: Marker) -> String {
    format!("{}{}", config.xattr_prefix(), marker.suffix())
}

/// Is `n` in the namespace this mount keeps its markers in? # C: O(len(n))
pub fn is_own(config: &Config, n: &str) -> bool { n.starts_with(config.xattr_prefix()) }

/// Is `n` an object's own attribute that merely lives in that namespace, stored
/// with the namespace doubled so the two never collide?
///
/// The trusted form is recognised one character short of the doubled prefix, so
/// the bare name `trusted.overlay.overlay` — with no marker suffix after it —
/// is an escaped attribute too. The unprivileged form requires the full
/// doubled prefix. The asymmetry is part of the on-disk contract: a layer
/// written by another kernel carries whichever form that kernel wrote.
/// # C: O(len(n))
pub fn is_escaped(config: &Config, n: &str) -> bool {
    if config.userxattr {
        n.starts_with(&format!("{XATTR_USER_PREFIX}{XATTR_NAMESPACE}"))
    } else {
        let doubled = format!("{XATTR_TRUSTED_PREFIX}{XATTR_NAMESPACE}");
        n.starts_with(&doubled[..doubled.len() - 1])
    }
}

/// Is `n` a marker of the overlay's own, to be hidden from the object and
/// never copied up? # C: O(len(n))
pub fn is_private(config: &Config, n: &str) -> bool {
    is_own(config, n) && !is_escaped(config, n)
}

/// Attributes that MUST survive copy-up: losing an access-control entry or a
/// security label silently widens or narrows what the copied object permits,
/// so a layer that cannot store them fails the copy rather than completing it
/// with weaker protection. # C: O(len(n))
pub fn must_copy(n: &str) -> bool {
    n == ACL_ACCESS || n == ACL_DEFAULT || n.starts_with(SECURITY_PREFIX)
}

/// Is `n` an access-control list, which is cloned rather than copied verbatim
/// so the destination filesystem re-encodes it in its own form? # C: O(len(n))
pub fn is_acl(n: &str) -> bool { n == ACL_ACCESS || n == ACL_DEFAULT }

/// Access-control list applying to the object itself.
pub const ACL_ACCESS: &str = "system.posix_acl_access";
/// Access-control list new children of a directory inherit.
pub const ACL_DEFAULT: &str = "system.posix_acl_default";
/// Namespace security labels live in.
pub const SECURITY_PREFIX: &str = "security.";
/// File capabilities, which a write to the file clears — so a data copy-up has
/// to put them back afterwards.
pub const NAME_CAPS: &str = "security.capability";

#[cfg(test)]
#[path = "xattr/tests.rs"]
mod tests;
