//! Whether the request may be served at all.
//!
//! A pure decision over eight bits of state, because the failure this guards
//! against is a request served in a condition that forbade it — which produces
//! no error at the time and a file that decrypts to nothing, or a swap area
//! pointing at somebody else's block, later.
//!
//! Order is the contract: a call that trips several rungs reports the first,
//! so the errno a caller sees does not move when an unrelated rung is added.

use syscall::errno::Errno;

use super::uapi::*;

/// Everything the ladder reads, gathered once.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Gate {
    /// The last checkpoint failed, so nothing about this volume's state can be
    /// relied on.
    pub cp_error: bool,
    /// Whether a checkpoint could be written if this call needed one.
    pub checkpoint_ready: bool,
    /// Whether the codec a compressed file on this volume needs is present.
    pub compress_backend_ready: bool,
    /// Whether the inode is a window onto another device rather than a file.
    pub device_aliasing: bool,
    pub regular: bool,
    pub encrypted: bool,
    pub compressed: bool,
    pub pinned: bool,
}

impl Gate {
    /// An ordinary writable regular file, which every case below breaks in one
    /// place. # C: O(1)
    pub fn ordinary() -> Self {
        Self { cp_error: false, checkpoint_ready: true, compress_backend_ready: true,
               device_aliasing: false, regular: true, encrypted: false, compressed: false,
               pinned: false }
    }
}

/// Whether `mode` may be served in state `g`.
/// # C: O(1)
pub fn check(g: &Gate, mode: u32) -> Result<(), Errno> {
    if g.cp_error { return Err(Errno::Eio); }
    // Allocating needs a checkpoint's worth of room to be sure the allocation
    // can be made durable; a volume that cannot write one would take the
    // blocks and be unable to record that it had.
    if !g.checkpoint_ready { return Err(Errno::Enospc); }
    if !g.compress_backend_ready || g.device_aliasing { return Err(Errno::Eopnotsupp); }
    // A directory's blocks are its entries and a device node has none, so
    // there is nothing for any of the five to do.
    if !g.regular { return Err(Errno::Einval); }
    // Contents are keyed to the block index they sit at, so a block that moves
    // to a different index decrypts to nothing.
    if g.encrypted && mode & FALLOC_FL_MOVES != 0 { return Err(Errno::Eopnotsupp); }
    if mode & !FALLOC_FL_SUPPORTED != 0 { return Err(Errno::Eopnotsupp); }
    // A pinned file's addresses are held by something outside the filesystem,
    // and a compressed file's blocks are one image rather than one block per
    // block. Neither can have part of its range taken away or moved.
    if (g.compressed || g.pinned) && mode & FALLOC_FL_PARTIAL != 0 {
        return Err(Errno::Eopnotsupp);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/fallocate/gate.rs"]
mod tests;
