//! Changing which blocks a file OWNS, without going through its bytes.
//!
//! Five requests share one entry point and almost nothing else. Two of them
//! give a file blocks it did not have — one keeping the size, one growing it.
//! One takes blocks away and leaves a hole. Two move every block after a point,
//! which changes what byte offset each block answers to and is the only pair
//! that can lose data if the move is interrupted.
//!
//! Every one of them is refused in states an ordinary write is not, and the
//! refusals are the part worth reading twice. A PINNED file's addresses have
//! been handed to something outside the filesystem — a swap area, a device
//! mapper — so a partial truncation of one hands that caller a block that is
//! now somebody else's. A compressed file's blocks are a cluster's image and
//! not an index, so punching one block out of a cluster leaves an image that
//! cannot be decompressed. An encrypted file's contents are keyed to their
//! block index, so moving a block to a different index makes it decrypt to
//! nothing.
//!
//! Module manifest:
//! - `uapi`:     the mode bits, which are the ABI.
//! - `gate`:     the refusal ladder, as a decision with no volume behind it.
//! - `hole`:     dropping the blocks of one index range.
//! - `punch`:    `PUNCH_HOLE`.
//! - `zero`:     `ZERO_RANGE`.
//! - `exchange`: moving a run of blocks from one index to another.
//! - `collapse`: `COLLAPSE_RANGE`.
//! - `insert`:   `INSERT_RANGE`.
//! - `expand`:   the plain allocation, with and without `KEEP_SIZE`.

pub mod uapi;
pub mod gate;
pub mod hole;
pub mod punch;
pub mod zero;
pub mod exchange;
pub mod collapse;
pub mod insert;
pub mod expand;

pub use gate::{check, Gate};
pub use uapi::{FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE, FALLOC_FL_KEEP_SIZE,
               FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, FALLOC_FL_SUPPORTED};

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::dnode::{put32, put64};
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Serve one `fallocate` on `ino`.
    ///
    /// The ladder runs before any of the five, and the dispatch after it is
    /// by the FIRST mode bit that names an operation — `KEEP_SIZE` alone names
    /// none of them and falls through to the plain allocation, which is what
    /// makes `KEEP_SIZE` a modifier rather than a sixth request.
    /// # C: O(blocks the range covers)
    pub fn fallocate(&mut self, ino: u32, mode: u32, offset: u64, len: u64)
        -> Result<(), Errno> {
        self.writable_or_err()?;
        self.dquot_initialize(ino)?;
        // Every buffered write of this file has to be on the medium before
        // its addresses are read: a page not yet placed has no address, and
        // this operation is about to rearrange the ones that exist.
        self.flush_data_pages(ino)?;
        let inode = self.read_inode(ino)?;
        check(&self.gate_for(ino, &inode)?, mode)?;
        if len == 0 { return Ok(()); }
        offset.checked_add(len).ok_or(Errno::Efbig)?;
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            // Punching past the end has nothing to punch, and is not an error:
            // the range the caller named is already a hole.
            if offset >= inode.size { return Ok(()); }
            self.punch_hole(ino, offset, len)?;
        } else if mode & FALLOC_FL_COLLAPSE_RANGE != 0 {
            self.collapse_range(ino, offset, len)?;
        } else if mode & FALLOC_FL_ZERO_RANGE != 0 {
            self.zero_range(ino, offset, len, mode)?;
        } else if mode & FALLOC_FL_INSERT_RANGE != 0 {
            self.insert_range(ino, offset, len)?;
        } else {
            self.expand_inode_data(ino, offset, len, mode)?;
        }
        self.refresh_extent(ino)
    }

    /// Record that `ino`'s contents changed at `now`.
    ///
    /// Both stamps move together, and both are STORED rather than only cached:
    /// the reference sets the modification time to the change time it has just
    /// taken and then marks the inode dirty, so a mount after a crash reports
    /// the allocation as a modification. Giving a file blocks is a
    /// modification even under `KEEP_SIZE`, where the length does not move —
    /// which is why this is not folded into the size write.
    /// # C: O(1 block)
    pub(crate) fn stamp_modified(&mut self, ino: u32, now: (u64, u32))
        -> Result<(), Errno> {
        self.stamp_inode(ino, |b| {
            put64(b, crate::uapi::I_MTIME, now.0);
            put32(b, crate::uapi::I_MTIME_NSEC, now.1);
            put64(b, crate::uapi::I_CTIME, now.0);
            put32(b, crate::uapi::I_CTIME_NSEC, now.1);
        })
    }

    /// Gather what the ladder reads, for one file. # C: O(1)
    pub(crate) fn gate_for(&self, _ino: u32, inode: &crate::node::Inode)
        -> Result<Gate, Errno> {
        Ok(Gate {
            cp_error: self.cp.flags & crate::flags::CP_ERROR_FLAG != 0,
            // A volume that cannot checkpoint still serves, so long as it is
            // not ALSO out of room; testing only the switch would refuse every
            // allocation on a deliberately checkpoint-disabled mount.
            checkpoint_ready: self.cp.flags & crate::flags::CP_DISABLED_FLAG == 0
                || self.space().free > 0,
            compress_backend_ready: true,
            // A volume carrying the alias feature is refused at mount, so no
            // mounted inode can be one.
            device_aliasing: false,
            regular: crate::mode::file_type(inode.mode) == vfs::FileType::Regular,
            encrypted: inode.encrypted(),
            compressed: inode.compressed(),
            pinned: crate::pin::state::is_pinned(inode),
        })
    }

    /// One past the highest byte offset a file on this volume can reach.
    /// # C: O(1 block)
    pub(crate) fn max_file_bytes(&self, ino: u32) -> Result<u64, Errno> {
        let inode = self.read_inode(ino)?;
        Ok(crate::node::path::max_block(inode.addrs_per_inode())
            .saturating_mul(crate::uapi::BLKSIZE as u64))
    }

    /// Whether a file may grow to `end`. # C: O(1 block)
    pub(crate) fn newsize_ok(&self, ino: u32, end: u64) -> Result<(), Errno> {
        if end > self.max_file_bytes(ino)? { return Err(Errno::Efbig); }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/fallocate/mod.rs"]
mod tests;
