//! Whether one page's write lands back on the block it came from.
//!
//! Overwriting where a block lies is the one thing the format's recovery model
//! does not get for free: the previous checkpoint still names that block, so a
//! crash after the overwrite leaves the checkpoint describing bytes that have
//! changed under it. The volume accepts that for DATA — a roll-forward replay
//! reconstructs the file's own tail, and nothing else pointed at those bytes —
//! and never for a node, a directory, a quota file or an atomic span, where the
//! stale copy is the only thing that makes the mount readable at all.
//!
//! Two ladders, in this order, and the order is the contract:
//!
//! - [`should_update_outplace`] is the REFUSALS. It answers for the states in
//!   which no policy may put a write back in place, and it is asked first, so
//!   an armed policy cannot reach a file whose shape forbids it.
//! - [`should_update_inplace`] is the REASONS: the states that ask for it
//!   whatever is armed, and then the armed set itself.
//!
//! The armed set is evaluated in the reference's own order because the answers
//! cost different amounts: the two that consult the allocator's pressure are
//! behind a closure, so a mount with neither armed never counts a section.

use super::bits;

/// Everything the two ladders read, for one page of one file.
///
/// One record rather than a dozen arguments: every field is a state some arm
/// consults, and a caller that gathered eleven of the twelve would compile.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Facts {
    /// The mount never overwrites in place, whatever is armed.
    pub lfs: bool,
    /// The volume is already known to need checking.
    pub need_fsck: bool,
    /// Checkpointing is off for this mount.
    pub cp_disabled: bool,
    /// The old block is one the last checkpoint still names.
    pub checkpointed: bool,
    /// A write is actually being submitted, as against a caller ASKING what
    /// the policy would do to one. The states that depend on a block address
    /// or on a request's urgency have no answer without one.
    pub have_io: bool,
    /// The file is a directory, a quota file, inside an atomic span, or the
    /// nameless inode collecting one.
    pub dir: bool,
    pub quota: bool,
    pub atomic: bool,
    /// The file's clusters may be compressed, so a member block of one may not
    /// be rewritten alone.
    pub compressed: bool,
    /// The file's blocks may not move.
    pub pinned: bool,
    /// The file has been marked cold, so its blocks are expected to stay where
    /// they are put.
    pub cold: bool,
    /// The file has asked for its writes to be placed out of line, and the
    /// caller is honouring that (`HONOR_OPU_WRITE`).
    pub opu_write: bool,
    /// A migration is moving the file's blocks into whole-section alignment,
    /// which is the one caller that must not have them rewritten under it.
    pub aligned_write: bool,
    /// The page is being moved by the cleaner.
    pub gcing: bool,
    /// An `fsync` of this file is in progress and asked for in-place writes.
    pub need_ipu: bool,
    /// The file's contents are enciphered.
    pub encrypted: bool,
    /// Nothing is waiting on this write.
    pub async_write: bool,
    /// The armed set, and what the utilisation arm compares against.
    pub policy: u32,
    pub util: u32,
    pub min_ipu_util: u32,
}

/// Whether the write MUST go out of place, whatever is armed.
///
/// A pinned file leaves here immediately rather than falling through the rest:
/// its blocks may not move, so the states below — which are reasons to move a
/// block — cannot apply to it, and the reasons ladder answers for it instead.
/// # C: O(1)
pub fn should_update_outplace(f: &Facts) -> bool {
    if f.pinned { return false; }
    if f.have_io && f.need_fsck { return true; }
    if f.lfs { return true; }
    if f.dir { return true; }
    if f.quota { return true; }
    if f.atomic { return true; }
    // A compressed cluster is written as a unit by the writer that knows its
    // shape, and a member block of one rewritten alone leaves the cluster
    // describing bytes that are no longer there.
    if f.compressed { return true; }
    if f.aligned_write { return true; }
    if f.opu_write { return true; }
    if !f.have_io { return false; }
    if f.gcing { return true; }
    // With checkpointing off the previous checkpoint is the only one there
    // will be, so a block it names may not be overwritten at all.
    if f.cp_disabled && f.checkpointed { return true; }
    false
}

/// Whether the write may land back where it was.
///
/// Asked only after [`should_update_outplace`] has answered no.
/// # C: O(1), plus one call of `need_ssr` when a pressure arm is armed
pub fn should_update_inplace(f: &Facts, need_ssr: impl FnMut() -> bool) -> bool {
    if f.aligned_write { return false; }
    if f.pinned { return true; }
    // A cold file's blocks are expected to stay put, so rewriting them
    // elsewhere is the fragmentation the mark was set to avoid — unless the
    // file has since asked for out-of-place writes, which is the stronger
    // statement of the two.
    if f.cold && !f.opu_write { return true; }
    check_policy(f, need_ssr)
}

/// The armed set, arm by arm.
/// # C: O(1), plus one call of `need_ssr` when a pressure arm is armed
pub fn check_policy(f: &Facts, mut need_ssr: impl FnMut() -> bool) -> bool {
    let p = f.policy;
    if bits::armed(p, bits::HONOR_OPU_WRITE) && f.opu_write { return false; }
    if bits::armed(p, bits::FORCE) { return true; }
    let over_util = f.util > f.min_ipu_util;
    if bits::armed(p, bits::SSR) && need_ssr() { return true; }
    if bits::armed(p, bits::UTIL) && over_util { return true; }
    if bits::armed(p, bits::SSR_UTIL) && over_util && need_ssr() { return true; }
    // A write nothing is waiting on can afford the in-place cost, which is
    // paid by whoever reads the block next rather than by this caller. Never
    // for an enciphered file: its ciphertext is bound to the file and offset
    // rather than to the address, and this arm is the one place the reference
    // declines to reason about that.
    if bits::armed(p, bits::ASYNC) && f.have_io && f.async_write && !f.encrypted { return true; }
    if bits::armed(p, bits::FSYNC) && f.need_ipu { return true; }
    // The mirror of the refusal above: with checkpointing off, a block the
    // last checkpoint does NOT name is unreachable from it, so overwriting it
    // costs nothing and saves the volume space it cannot spare.
    if f.have_io && f.cp_disabled && !f.checkpointed { return true; }
    false
}

/// Whether this write goes in place: no refusal, and a reason.
/// # C: O(1), plus one call of `need_ssr` when a pressure arm is armed
pub fn need_inplace_update(f: &Facts, need_ssr: impl FnMut() -> bool) -> bool {
    if should_update_outplace(f) { return false; }
    should_update_inplace(f, need_ssr)
}

/// The set a mount arms itself with, before anything tunes it.
///
/// A volume that never overwrites in place arms nothing. A SMALL volume arms
/// the whole of it — it has no room to keep an out-of-place writer ahead of the
/// cleaner — and honours a file that has asked for out-of-place writes anyway,
/// which is the one exemption that survives the tuning. Everything else arms
/// the `fsync` arm alone: the writes a caller is waiting on, and no others.
/// # C: O(1)
pub fn mount_policy(lfs: bool, main_segments: u32) -> u32 {
    if lfs { return bits::DISABLE; }
    if main_segments <= super::limits::SMALL_VOLUME_SEGMENTS {
        return bits::bit(bits::FORCE) | bits::bit(bits::HONOR_OPU_WRITE);
    }
    bits::bit(bits::FSYNC)
}

/// The set a mount may be RETUNED to, checked before it takes effect.
///
/// Two refusals. A word with a bit above the highest policy names a policy that
/// does not exist, and accepting it would arm nothing while reporting something.
/// A mount that never overwrites in place may only be told how to SUBMIT an
/// in-place write it will never make — the one bit that is about the request
/// rather than about the decision — so every other bit is refused rather than
/// silently dropped.
/// # C: O(1)
pub fn store_policy(word: u32, lfs: bool) -> Result<u32, syscall::errno::Errno> {
    if word >= bits::bit(bits::MAX) { return Err(syscall::errno::Errno::Einval); }
    if lfs && word & !bits::bit(bits::NOCACHE) != 0 {
        return Err(syscall::errno::Errno::Einval);
    }
    Ok(word)
}

/// Whether an `fsync` asks for its file's pages to be rewritten in place.
///
/// A data-only sync always does: it promises the bytes and nothing about the
/// metadata around them, so the node blocks an out-of-place write would also
/// rewrite are work the caller did not ask for. A full sync does so only for a
/// short tail, where the same reasoning holds by volume.
/// # C: O(1)
pub fn fsync_wants_ipu(datasync: bool, dirty_pages: usize, min_fsync_blocks: u32) -> bool {
    datasync || dirty_pages as u64 <= u64::from(min_fsync_blocks)
}
