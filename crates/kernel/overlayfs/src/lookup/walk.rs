//! A whole layer, including a redirect's path from its root.
//!
//! Usually this is one call: the name has no slash in it and resolves inside
//! the parent directory. An ABSOLUTE redirect turns it into a path walk from
//! the layer root instead, and each component of that walk may carry a
//! redirect of its own — so the name being resolved can change under the walk
//! that is resolving it.
//!
//! That is why the position is tracked as the length still to come rather than
//! as an index: the prefix in front of the cursor is exactly what a rewrite
//! replaces, and the suffix behind it is exactly what it preserves.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::layers::Layer;

use super::data::Data;
use super::single::{is_dir, single};

/// Resolve the current name in one layer, starting at `base`.
///
/// `base` is the parent directory's object in this layer for an ordinary name,
/// and the layer's root for a name that an absolute redirect turned into a
/// path.
/// # C: O(components · log n)
pub fn layer(base: &InodeRef, d: &mut Data, l: &Arc<Layer>) -> Result<Option<InodeRef>, Errno> {
    if !d.name.starts_with('/') {
        let name = d.name.clone();
        return single(base, d, l, &name, 0, "");
    }

    let mut rem = d.name.len() - 1;
    let mut found: Option<InodeRef> = None;
    let mut cur = base.clone();
    loop {
        if !is_dir(&cur) { break; }
        let start = d.name.len() - rem;
        let rest = &d.name[start..];
        let this_len = rest.find('/').unwrap_or(rest.len());
        let end = start + this_len == d.name.len();
        let name: String = rest[..this_len].into();
        let post: String = d.name[start + this_len..].into();

        match single(&cur, d, l, &name, start, &post)? {
            None => return Ok(None),
            Some(next) => { cur = next.clone(); found = Some(next); }
        }
        if end { break; }
        // A rewrite may have changed the name's length, but never its tail, so
        // stepping by what was consumed keeps the cursor on the same suffix.
        rem -= this_len + 1;
        if rem >= d.name.len() { return Err(Errno::Eio); }
    }
    Ok(found)
}
