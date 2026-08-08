// UFFDIO_MOVE: the mode word, the two range checks, and the compatibility
// ladder two VMAs must pass before pages may be relocated between them.

use syscall::errno::Errno;

use crate::userfaultfd::uapi::*;

/// The decoded `uffdio_move.mode` word.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MoveMode {
    /// Skip source pages that are absent instead of failing on them.
    pub allow_src_holes: bool,
    /// Suppress the wake of faulters blocked on the destination.
    pub dontwake: bool,
}

/// # C: O(1)
pub fn check_move_mode(mode: u64) -> Result<MoveMode, Errno> {
    if mode & !(UFFDIO_MOVE_MODE_DONTWAKE | UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES) != 0 {
        return Err(Errno::Einval);
    }
    Ok(MoveMode {
        allow_src_holes: mode & UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES != 0,
        dontwake:        mode & UFFDIO_MOVE_MODE_DONTWAKE != 0,
    })
}

/// The facts the move ladder needs about the source or destination VMA.
#[derive(Copy, Clone, Debug, Default)]
pub struct MoveVma {
    pub start: u64,
    pub end: u64,
    /// The mapping's current protection bits, compared for equality between
    /// the two VMAs.
    pub prot: u8,
    /// The mapping is writable now.
    pub write: bool,
    /// The mapping is shared.
    pub shared: bool,
    /// The mapping's pages are locked in memory.
    pub locked: bool,
    /// Private anonymous memory.
    pub anonymous: bool,
    /// The VMA is registered to the userfaultfd performing the move.
    pub registered_by_this_ctx: bool,
}

/// Both ranges must lie wholly inside their VMA and neither may be shared.
/// Every failure is EINVAL — the VMAs were found, so this is about the request
/// not fitting them.
/// # C: O(1)
pub fn check_move_ranges(dst_start: u64, src_start: u64, len: u64,
                         src: &MoveVma, dst: &MoveVma) -> Result<(), Errno> {
    if src.shared { return Err(Errno::Einval); }
    if src_start + len > src.end { return Err(Errno::Einval); }
    if dst.shared { return Err(Errno::Einval); }
    if dst_start + len > dst.end { return Err(Errno::Einval); }
    Ok(())
}

/// The compatibility ladder, in order:
///
/// ```text
/// different access rights or protection → EINVAL
/// one locked and the other not          → EINVAL
/// the source is not writable            → EINVAL
/// the destination is not registered to THIS userfaultfd → EINVAL
/// either side is not anonymous          → EINVAL
/// ```
///
/// A moved page keeps its contents and its identity and simply changes address,
/// so anything that would have to be re-decided by the move — permissions,
/// residency guarantees, who owns the pages — must already match. The
/// destination check is by IDENTITY, not merely "some context": a move
/// publishes pages at an address a monitor is responsible for, so it must be
/// the monitor asking.
/// # C: O(1)
pub fn check_move_areas(src: &MoveVma, dst: &MoveVma) -> Result<(), Errno> {
    if src.prot != dst.prot { return Err(Errno::Einval); }
    if src.locked != dst.locked { return Err(Errno::Einval); }
    if !src.write { return Err(Errno::Einval); }
    if !dst.registered_by_this_ctx { return Err(Errno::Einval); }
    if !src.anonymous || !dst.anonymous { return Err(Errno::Einval); }
    Ok(())
}
