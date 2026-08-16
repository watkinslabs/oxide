//! Performing a copy-up against real layers.
//!
//! The copy is assembled under a name in the work directory that nothing else
//! can reach, and moved into place by a rename once it is complete. That is
//! the whole crash-safety argument: a rename either happened or did not, so
//! the destination name holds either the object as it was below or the
//! finished copy, and never a half-written one.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};
use syscall::errno::Errno;
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFMT};
use vfs::InodeRef;

use crate::config::Config;
use crate::err::to_errno;
use crate::layers::{LayerStack, OvlEntry};
use crate::limits::COPY_UP_CHUNK_SIZE;
use crate::marker;
use crate::metacopy::Metacopy;
use crate::origin;
use crate::uapi::Marker;

use super::attrs::{copy_attrs, copy_size, copy_xattrs, protattr_value, DIVERTED_FLAGS};
use super::plan::{need_meta_copy_up, need_index, steps, Kind, Step};

/// Counter behind the temporary names. Wrapping is harmless: a temporary name
/// lives only between its creation and the rename that consumes it.
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// A name nothing else in the work directory uses. # C: O(1)
fn tempname() -> String { format!("#{:x}", TEMP_ID.fetch_add(1, Ordering::Relaxed)) }

/// Copy `entry` into the writable layer under `name` in `parent`.
///
/// `parent` must already have an upper object; [`copy_up_parents`] is what
/// guarantees that. `open_flags` decides whether the contents come too — an
/// open that is about to write them makes copying them pointless, and an open
/// that only reads metadata makes copying them wasteful.
/// # C: O(size) for a regular file, O(1) otherwise
pub fn copy_up(stack: &Arc<LayerStack>, parent: &OvlEntry, entry: &mut OvlEntry, name: &str,
               open_flags: u32) -> Result<(), Errno> {
    if entry.upper.is_some() { return Ok(()); }
    let Some(lower) = entry.lower_top().map(|p| p.inode.clone()) else { return Err(Errno::Eio) };
    let Some(destdir) = parent.upper.clone() else { return Err(Errno::Eio) };
    let Some(workdir) = stack.workdir.clone() else { return Err(Errno::Erofs) };
    let config = &stack.config;

    let meta_only = need_meta_copy_up(config, lower.file_type(), open_flags, false);
    let kind = Kind::of(lower.file_type(), meta_only);
    let record_origin = kind == Kind::Dir || lower.nlink() == 1 || indexed(stack, &lower);
    let plan = steps(kind, record_origin, config.should_sync_metadata());

    let tmp = tempname();
    let temp = create_temp(&workdir, &lower, &tmp)?;
    let truncate = open_flags & super::plan::O_TRUNC != 0;

    for step in plan {
        if let Err(e) = one(stack, step, &lower, &temp, &destdir, &workdir, &tmp, name,
                            meta_only, truncate) {
            // Nothing was moved into place, so removing the half-built copy
            // returns the layer to exactly where it started.
            cleanup(&workdir, &tmp, &temp);
            return Err(e);
        }
    }

    let upper = destdir.lookup(name).map_err(to_errno)?;
    if need_index(stack.has_index(), stack.index_all(),
                  lower.file_type() == FileType::Directory, lower.nlink()) {
        add_index(stack, &lower, &upper)?;
        entry.indexed = true;
    }
    entry.upper = Some(upper);
    entry.upper_alias = true;
    entry.metacopy = meta_only;
    let _ = config;
    Ok(())
}

/// Would this object be indexed? # C: O(1)
fn indexed(stack: &LayerStack, lower: &InodeRef) -> bool {
    need_index(stack.has_index(), stack.index_all(),
               lower.file_type() == FileType::Directory, lower.nlink())
}

/// Run one step. # C: step-dependent
#[allow(clippy::too_many_arguments)]
fn one(stack: &Arc<LayerStack>, step: Step, lower: &InodeRef, temp: &InodeRef,
       destdir: &InodeRef, workdir: &InodeRef, tmp: &str, name: &str, meta_only: bool,
       truncate: bool) -> Result<(), Errno> {
    let config = &stack.config;
    match step {
        Step::CreateTemp => Ok(()),
        Step::CopyData => if truncate { Ok(()) } else { copy_data(lower, temp) },
        Step::CopyXattrs => copy_xattrs(config, lower, temp),
        Step::CopyFileattr => divert_flags(config, lower, temp),
        Step::SetOrigin => match origin::encode(config, lower, false) {
            Some(rec) => origin::set(config, temp, &rec),
            None => Ok(()),
        },
        Step::SetMetacopy => {
            let _ = meta_only;
            marker::set(config, temp, Marker::Metacopy, &Metacopy::empty().encode(),
                        Errno::Eopnotsupp)
        }
        Step::SetSize => if truncate { Ok(()) } else { copy_size(lower, temp) },
        Step::SetAttrs => copy_attrs(lower, temp),
        Step::Fsync => Ok(()),
        Step::MoveIntoPlace => workdir
            .rename_child(tmp, destdir, name, 0, &CreateCtx::root())
            .map_err(to_errno),
        Step::RestoreParentTimes => Ok(()),
    }
}

/// Build the empty object the copy will be assembled in. Its type and device
/// number are fixed here because neither can be changed afterwards. # C: O(1)
fn create_temp(workdir: &InodeRef, lower: &InodeRef, name: &str) -> Result<InodeRef, Errno> {
    let ctx = CreateCtx::root();
    let mode = lower.i_mode() as u32;
    match lower.file_type() {
        FileType::Regular => workdir.create_child(name, mode, &ctx).map_err(to_errno),
        FileType::Directory => workdir.mkdir(name, mode, &ctx).map_err(to_errno),
        FileType::Symlink => {
            let target = lower.get_link().map_err(to_errno)?;
            workdir.symlink_child(name, &target, &ctx).map_err(to_errno)?;
            workdir.lookup(name).map_err(to_errno)
        }
        _ => {
            workdir.mknod_child(name, (mode & S_IFMT as u32) as u16, lower.rdev(), &ctx)
                .map_err(to_errno)?;
            workdir.lookup(name).map_err(to_errno)
        }
    }
}

/// Remove a copy that will never be moved into place. # C: O(1)
fn cleanup(workdir: &InodeRef, name: &str, temp: &InodeRef) {
    let _ = if temp.file_type() == FileType::Directory {
        workdir.rmdir(name)
    } else {
        workdir.unlink_child(name)
    };
}

/// Copy a regular file's contents. # C: O(size)
fn copy_data(from: &InodeRef, to: &InodeRef) -> Result<(), Errno> {
    if from.file_type() != FileType::Regular { return Ok(()); }
    let mut off = 0u64;
    let mut buf = vec![0u8; COPY_UP_CHUNK_SIZE.min(64 * 1024) as usize];
    loop {
        let n = from.read(off, &mut buf).map_err(to_errno)?;
        if n == 0 { break; }
        let mut done = 0;
        while done < n {
            let w = to.write(off + done as u64, &buf[done..n]).map_err(to_errno)?;
            if w == 0 { return Err(Errno::Eio); }
            done += w;
        }
        off += n as u64;
    }
    Ok(())
}

/// Record the flags that cannot be set on the copy itself.
///
/// Setting immutable or append-only on the object being built would stop the
/// copy-up finishing, so they are written into a marker and applied to the
/// overlay object instead of the layer's.
/// # C: O(1)
fn divert_flags(config: &Config, lower: &InodeRef, temp: &InodeRef) -> Result<(), Errno> {
    let diverted = lower.i_flags() & DIVERTED_FLAGS;
    if diverted == 0 { return Ok(()); }
    let v = protattr_value(diverted);
    match marker::set(config, temp, Marker::Protattr, &v, Errno::Eperm) {
        // A layer that will not hold the marker costs the object its
        // protection flags, not its contents.
        Err(Errno::Eperm) | Err(Errno::Eopnotsupp) => Ok(()),
        other => other,
    }
}

/// Link the copied-up object into the index under its origin's name, so a
/// second name for the same lower file finds this copy instead of making
/// another. # C: O(1)
fn add_index(stack: &Arc<LayerStack>, lower: &InodeRef, upper: &InodeRef) -> Result<(), Errno> {
    let Some(idx) = stack.indexdir.clone() else { return Ok(()) };
    let Some(rec) = origin::encode(&stack.config, lower, false) else { return Ok(()) };
    let name = crate::fh::index_name(&rec)?;
    if idx.lookup(&name).is_ok() { return Ok(()); }
    idx.link_child(upper, &name, &CreateCtx::root()).map_err(to_errno)
}

/// Copy the contents of an object that was copied up metadata-only.
///
/// The file capabilities are read before the write and put back after it,
/// because writing the contents clears them — the same reason the ordinary
/// copy-up writes data before attributes.
/// # C: O(size)
pub fn copy_up_data(stack: &Arc<LayerStack>, entry: &mut OvlEntry) -> Result<(), Errno> {
    if !entry.metacopy { return Ok(()); }
    let (Some(upper), Some(lower)) = (entry.upper.clone(), entry.lower.last().map(|p| p.inode.clone()))
        else { return Err(Errno::Eio) };
    let caps = upper.getxattr(crate::xattr::NAME_CAPS).ok();
    copy_data(&lower, &upper)?;
    if let Some(c) = caps { let _ = upper.setxattr(crate::xattr::NAME_CAPS, c, false, false); }
    marker::remove(&stack.config, &upper, Marker::Metacopy)?;
    entry.metacopy = false;
    Ok(())
}

/// Copy up every ancestor that has no upper object yet, deepest last.
///
/// A copy-up cannot create its own destination directory: the object has to be
/// moved into a directory that already exists in the writable layer, so the
/// chain above it is copied first, from the topmost missing one down.
/// # C: O(depth)
pub fn copy_up_parents(stack: &Arc<LayerStack>, chain: &mut [(OvlEntry, String)])
    -> Result<(), Errno> {
    for i in 0..chain.len() {
        if chain[i].0.upper.is_some() { continue; }
        let (before, rest) = chain.split_at_mut(i);
        let Some(parent) = before.last() else { return Err(Errno::Eio) };
        let name = rest[0].1.clone();
        let parent_entry = parent.0.clone();
        copy_up(stack, &parent_entry, &mut rest[0].0, &name, 0)?;
    }
    Ok(())
}
