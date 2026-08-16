//! Where a renamed object left its lower half.
//!
//! Renaming a merged directory cannot move the lower directory, so the upper
//! directory records the name the lower one still has. Every later lookup of
//! the new name follows that record into the lower layers — which is exactly
//! a symbolic link into a layer, made without the permission check walking
//! there would have applied. That is why a malformed value is rejected rather
//! than repaired, and why following one at all is a mount decision.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::limits::REDIRECT_MAX;

/// A redirect value, already checked.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Redirect {
    /// A single name, resolved in the same lower directory the parent
    /// resolved to.
    Relative(String),
    /// A path from the root of each lower layer.
    Absolute(String),
}

impl Redirect {
    /// The stored form. # C: O(1)
    pub fn as_str(&self) -> &str {
        match self { Redirect::Relative(s) | Redirect::Absolute(s) => s }
    }
    /// Does resolution restart at the layer root? # C: O(1)
    pub fn is_absolute(&self) -> bool { matches!(self, Redirect::Absolute(_)) }
}

/// Check a value read from a layer.
///
/// An absolute value is a `/`-rooted path whose every component is non-empty;
/// a relative one is a single name with no `/` at all. An empty value, a
/// doubled slash or a slash inside a relative name would each resolve
/// somewhere the writer did not name, so each is refused.
/// # C: O(len(value))
pub fn check(value: &[u8]) -> Result<Redirect, Errno> {
    let s = core::str::from_utf8(value).map_err(|_| Errno::Einval)?;
    if s.is_empty() { return Err(Errno::Einval); }
    if let Some(rest) = s.strip_prefix('/') {
        if rest.is_empty() || rest.split('/').any(|c| c.is_empty()) { return Err(Errno::Einval); }
        Ok(Redirect::Absolute(s.to_string()))
    } else {
        if s.contains('/') { return Err(Errno::Einval); }
        Ok(Redirect::Relative(s.to_string()))
    }
}

/// Rewrite the name being looked up after a redirect is found part-way down an
/// absolute lookup.
///
/// `prefix` is the part of the current name already consumed, `post` the part
/// still to come. A relative value replaces only the component it was found
/// on; an absolute one replaces the whole path so far, which is what lets a
/// directory that was moved across parents still be found.
/// # C: O(len(prefix) + len(value) + len(post))
pub fn rewrite(prefix: &str, value: &Redirect, post: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + value.as_str().len() + post.len());
    if !value.is_absolute() { out.push_str(prefix); }
    out.push_str(value.as_str());
    out.push_str(post);
    out
}

/// Build the value to write when `name` is renamed.
///
/// `ancestors` names the path from the layer root down to the object, each
/// entry being either the redirect already recorded on that ancestor or its
/// plain name — an ancestor that was itself renamed contributes where its
/// lower half is, not where it now appears.
///
/// An absolute value longer than the limit is refused with `EXDEV`, which
/// tells the caller to copy the tree by hand rather than leaving a rename
/// half-done.
/// # C: O(total length)
pub fn build(ancestors: &[&str], absolute: bool) -> Result<Redirect, Errno> {
    if !absolute {
        let last = ancestors.last().ok_or(Errno::Einval)?;
        return Ok(Redirect::Relative((*last).to_string()));
    }
    let mut parts: Vec<&str> = Vec::new();
    // An ancestor whose own recorded value is already absolute names the whole
    // path on its own; nothing above it contributes.
    for (i, a) in ancestors.iter().enumerate() {
        if a.starts_with('/') { parts.clear(); parts.push(&a[1..]); } else { parts.push(a); }
        let _ = i;
    }
    let mut out = String::new();
    for p in &parts { out.push('/'); out.push_str(p); }
    if out.len() > REDIRECT_MAX { return Err(Errno::Exdev); }
    Ok(Redirect::Absolute(out))
}

/// Is a recorded value still good for a rename that stays in the same parent?
///
/// An absolute value survives any rename; a relative one names a single
/// component, so it must be rewritten whenever an absolute one is now needed.
/// # C: O(1)
pub fn still_valid(current: Option<&Redirect>, need_absolute: bool) -> bool {
    match current {
        None => false,
        Some(r) => !need_absolute || r.is_absolute(),
    }
}

#[cfg(test)]
#[path = "redirect/tests.rs"]
mod tests;
