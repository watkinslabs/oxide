//! One name in one layer, and what it says about going deeper.
//!
//! The order of the checks here is the whole contract. A whiteout has to be
//! recognised before anything else is read off the object, or a deleted file
//! reappears. A non-directory has to stop the walk unless it is a
//! metadata-only stand-in, or a file in an upper layer would be merged with a
//! directory below it. And the redirect has to be read LAST, because it
//! rewrites the name the next layer will be asked for.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::types::FileType;
use vfs::{InodeRef, VfsError};

use crate::config::Config;
use crate::layers::Layer;
use crate::marker;
use crate::metacopy;
use crate::redirect;
use crate::uapi::Marker;
use crate::whiteout::{self, Opacity};

use super::data::Data;

/// Size of the metadata-only record on `inode`, zero when there is none.
///
/// Only a regular file can carry one: a directory or a symlink with the same
/// attribute was not written by an overlay, and treating it as metadata-only
/// would send the walk looking for data that does not exist.
/// # C: O(log n)
pub fn check_metacopy(config: &Config, inode: &InodeRef) -> Result<usize, Errno> {
    if inode.file_type() != FileType::Regular { return Ok(0); }
    let Some(v) = marker::get(config, inode, Marker::Metacopy) else { return Ok(0) };
    metacopy::decode(&v)?;
    Ok(metacopy::recorded_size(Some(&v)))
}

/// Look one name up in one layer.
///
/// `prelen` is how much of the current name has already been consumed and
/// `post` what still follows it, so that a redirect found here can rewrite the
/// whole name correctly. `Ok(None)` means the walk found nothing usable at
/// this name — which is not an error, and may still have set `stop`.
/// # C: O(log n) plus the layer's own lookup
pub fn single(base: &InodeRef, d: &mut Data, layer: &Arc<Layer>, name: &str, prelen: usize,
              post: &str) -> Result<Option<InodeRef>, Errno> {
    let last_element = post.is_empty();
    let config = &d.stack.config;

    let this = match base.lookup(name) {
        Ok(i) => i,
        Err(VfsError::Enoent) | Err(VfsError::Enametoolong) => return Ok(None),
        Err(e) => return Err(crate::err::to_errno(e)),
    };

    if whiteout::is_whiteout(config, &this, layer.xwhiteouts()) {
        d.stop = true;
        d.opaque = true;
        return Ok(None);
    }

    // A metadata-only object one layer up promised a regular file below it.
    // Anything else means the two layers disagree about what this name is, and
    // continuing would attach one object's metadata to another's contents.
    if last_element && d.metacopy > 0 && this.file_type() != FileType::Regular {
        d.stop = true;
        return Ok(None);
    }

    if this.file_type() != FileType::Directory {
        if d.is_dir || !last_element { d.stop = true; return Ok(None); }
        d.metacopy = check_metacopy(config, &this)?;
        d.stop = d.metacopy == 0;
        if d.metacopy == 0 || d.last { return Ok(Some(this)); }
    } else {
        if last_element { d.is_dir = true; }
        if d.last { return Ok(Some(this)); }
        match whiteout::opacity(config, &this) {
            Opacity::MarkedWhiteouts if last_element && !layer.is_upper() => {
                d.xwhiteouts = true;
                layer.set_xwhiteouts();
            }
            Opacity::Opaque => {
                d.stop = true;
                if last_element { d.opaque = true; }
                return Ok(Some(this));
            }
            _ => {}
        }
    }

    follow_redirect(&this, d, prelen, post)?;
    Ok(Some(this))
}

/// Read a redirect off `inode` and rewrite the name the next layer will be
/// asked for.
///
/// An absolute redirect CLEARS `stop`: an opaque directory higher up stopped
/// the walk, but a descendant naming a path from the layer root is reaching
/// somewhere that opacity never covered.
/// # C: O(len(name))
fn follow_redirect(inode: &InodeRef, d: &mut Data, prelen: usize, post: &str)
    -> Result<(), Errno> {
    d.absolute_redirect = false;
    let Some(v) = marker::get(&d.stack.config, inode, Marker::Redirect) else { return Ok(()) };
    let r = redirect::check(&v)?;
    if r.is_absolute() { d.absolute_redirect = true; d.stop = false; }
    let name = redirect::rewrite(&d.name[..prelen], &r, post);
    d.redirect = Some(name.clone());
    d.name = name;
    Ok(())
}

/// Is this object a directory? # C: O(1)
pub fn is_dir(i: &InodeRef) -> bool { i.file_type() == FileType::Directory }
