//! A read-only lower layer made writable by a volatile upper one.
//!
//! This is the live-image root: an immutable filesystem carries the system and
//! every write lands in memory, discarded at power-off. Linux composes it in
//! the initramfs — dracut mounts the image, mounts a tmpfs, and mounts an
//! overlay of the two before switching root — so the shape here is that
//! composition, not a new kind of overlay: the same option string, the same
//! layer stack, the same mount-time refusals.
//!
//! The layers arrive as directory inodes rather than as paths. Nothing in the
//! composition needs them to be mounted anywhere, and requiring a path would
//! mean the root could only be built after a root already existed.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::InodeRef;

use crate::mount::OverlayFs;

/// The option string a volatile root is built from. The names are what the
/// resolver below answers to, not paths on any filesystem.
const VOLATILE_DATA: &str = "lowerdir=lower,upperdir=upper,workdir=work";

/// Layer names, so the option string above and the resolver cannot drift.
const LOWER: &str = "lower";
const UPPER: &str = "upper";
const WORK: &str = "work";

/// Compose `lower` under a writable `upper`, with `work` as the overlay's
/// working directory.
///
/// `upper` and `work` must be directories on the SAME writable filesystem, and
/// neither may contain the other: a work directory inside the upper layer
/// shows its half-built objects as overlay contents. Linux refuses that by
/// comparing the PATHS the mount named, and the layer names below are three
/// distinct labels, so that check can never fire here — supplying disjoint
/// directories is this caller's obligation, not something the mount re-checks.
/// A layer that is not a directory IS refused, when it is resolved.
/// # C: O(1)
pub fn volatile_over(lower: InodeRef, upper: InodeRef, work: InodeRef)
    -> Result<Arc<OverlayFs>, Errno> {
    let resolve = |name: &str| -> Result<InodeRef, Errno> {
        match name {
            LOWER => Ok(lower.clone()),
            UPPER => Ok(upper.clone()),
            WORK => Ok(work.clone()),
            _ => Err(Errno::Enoent),
        }
    };
    OverlayFs::open(VOLATILE_DATA, &resolve, true)
}

#[cfg(test)]
#[path = "volatile/tests.rs"]
mod tests;
