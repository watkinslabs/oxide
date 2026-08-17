//! Who may pin a file, and what happens when the cleaner meets a pinned one.
//!
//! Pure decisions over stated facts: every refusal here is an errno a caller
//! sees, and the ORDER they are asked in is part of the contract — a file that
//! is both atomic and already has blocks reports the atomic refusal, not the
//! size one.

use syscall::errno::Errno;

/// The most failures a file may accumulate before pinning is given up on.
///
/// A pinned file the cleaner keeps colliding with is a file whose pinning is
/// costing the volume more than it is worth, so the mark comes off rather than
/// the section staying uncleanable forever.
pub const GC_PIN_FILE_THRESHOLD: u16 = 2048;
/// The widest the counter can be set to, which is what the field holds.
pub const MAX_GC_FAILED_PINNED_FILES: u16 = u16::MAX;

/// What the caller's handle and the mount allow, before the inode is read.
///
/// Separate from the inode's own facts because these come from the file
/// description and the mount, which this crate never sees.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SetPinGate {
    /// The stored type is a regular file.
    pub is_reg: bool,
    /// The mount refuses writes.
    pub ro_mount: bool,
    /// The inode is an alias for a whole device rather than a file.
    pub device_alias: bool,
}

/// Everything the pin decision reads off the inode and the volume.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct PinFacts {
    /// The file is inside an atomic-write span.
    pub atomic: bool,
    /// The mark is already set.
    pub already_pinned: bool,
    /// The file owns blocks beyond its own inode block.
    pub has_blocks: bool,
    /// The volume's segments are dictated by the drive's zones.
    pub blkzoned: bool,
    /// Something about the file forces every write out of place, which is
    /// exactly what a pinned file may not do.
    pub update_outplace: bool,
    /// Failures already recorded against the file.
    pub gc_failures: u16,
    /// Failures at which pinning is given up on.
    pub threshold: u16,
}

/// What a set-pin request resolves to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PinAction {
    /// Take the mark off and reset the counter.
    Unpin,
    /// Nothing to do; report the counter as it stands.
    AlreadyPinned,
    /// Put the mark on.
    Pin,
}

/// Whether `pin` may be applied, and what applying it means.
///
/// The ladder is the reference's, in its order. The size refusal is `EFBIG`
/// rather than `EINVAL` because it is a statement about the file: pinning is
/// a promise about where blocks will be put, and blocks that already exist
/// were put wherever the allocator felt like.
/// # C: O(1)
pub fn set_pin_file(g: &SetPinGate, f: &PinFacts, pin: u32) -> Result<PinAction, Errno> {
    if !g.is_reg { return Err(Errno::Einval); }
    if g.ro_mount { return Err(Errno::Erofs); }
    // Unpinning a device alias would leave an inode that names a whole device
    // and is free to be relocated, which is not a state the format has.
    if pin == 0 && g.device_alias { return Err(Errno::Eopnotsupp); }
    if f.atomic { return Err(Errno::Einval); }
    if pin == 0 { return Ok(PinAction::Unpin); }
    if f.already_pinned { return Ok(PinAction::AlreadyPinned); }
    if f.has_blocks { return Err(Errno::Efbig); }
    // A zoned volume writes every block out of place by construction, so the
    // out-of-place test says nothing there and pinning is allowed anyway.
    if !f.blkzoned && f.update_outplace { return Err(Errno::Einval); }
    pin_file_control(f.gc_failures, f.threshold, false)?;
    Ok(PinAction::Pin)
}

/// The last gate, asked after the file has been taken out of its inode.
///
/// A compressed file reads a whole cluster at a time out of blocks whose
/// count depends on how well the cluster compressed, so its addresses are not
/// a run anything outside the filesystem can use. Compression comes off if the
/// file has no compressed blocks yet, and the pin is refused if it does.
/// # C: O(1)
pub fn pin_compression(compressed_undisableable: bool) -> Result<(), Errno> {
    if compressed_undisableable { return Err(Errno::Eopnotsupp); }
    Ok(())
}

/// The failure counter's own rule: refuse once the file has cost too much.
///
/// `Err` means the caller must ALSO clear the mark — the file is no longer
/// pinned, whether the caller was asking to pin it or merely recording a
/// collision. Returning the count rather than writing it keeps the decision
/// separate from the inode it lands in.
/// # C: O(1)
pub fn pin_file_control(gc_failures: u16, threshold: u16, inc: bool) -> Result<u16, Errno> {
    if gc_failures >= threshold { return Err(Errno::Eagain); }
    Ok(if inc { gc_failures.saturating_add(1) } else { gc_failures })
}

/// What the cleaner does when a victim block belongs to a pinned file.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GcPinned {
    /// Not pinned; clean it.
    Proceed,
    /// Pinned, and the cleaner was only cleaning ahead of demand — leave it.
    Busy,
    /// Pinned, and the cleaner needs the space now: the block still stays
    /// where it is, and the collision is recorded against the file.
    Blocked,
}

/// Whether a pinned file's block may be moved. It may not; only the answer
/// the caller reports differs with why it was asking.
/// # C: O(1)
pub fn gc_pinned_control(pinned: bool, foreground: bool) -> GcPinned {
    if !pinned { return GcPinned::Proceed; }
    if !foreground { return GcPinned::Busy; }
    GcPinned::Blocked
}

/// Whether a pinned file may be resized to `new_size`.
///
/// Shrinking to something that is not a whole number of sections would leave
/// part of a pinned section free while the rest stays pinned, which is a
/// section the cleaner can neither use nor reclaim. Growing is unrestricted:
/// the new tail is a hole until something allocates it, and that allocation
/// goes through the pinned log like any other.
/// # C: O(1)
pub fn truncate(pinned: bool, cur_size: u64, new_size: u64, sec_bytes: u64) -> Result<(), Errno> {
    if !pinned || new_size > cur_size || sec_bytes == 0 { return Ok(()); }
    if new_size % sec_bytes != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Whether a write to a pinned file is allowed at all.
///
/// Only an overwrite is: a pinned file's blocks are allocated in whole
/// sections ahead of time, and a write that would have to allocate one would
/// take it from wherever the allocator was, which is the promise broken.
/// # C: O(1)
pub fn write_allowed(pinned: bool, overwrite: bool) -> Result<(), Errno> {
    if pinned && !overwrite { return Err(Errno::Eio); }
    Ok(())
}
