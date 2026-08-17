//! When this filesystem asks a device to empty its write cache, and which
//! device it asks.
//!
//! Every write this filesystem makes is out of place, so the medium always
//! holds two states: the one the last checkpoint describes and the one this
//! mount is building. A device with a volatile write cache breaks that
//! arrangement on its own — it acknowledges a write while the bytes are still
//! in the cache, and it is free to move them to the medium in any order it
//! likes. Two promises then become false at once unless something fences them:
//!
//! - `fsync` returns having written a chain of node blocks a later mount can
//!   replay. If the chain is still in the cache when the power goes, the file
//!   loses writes the caller was told were safe.
//! - A checkpoint names blocks. If the checkpoint's commit block reaches the
//!   medium before the blocks it names, the next mount reads a pack that looks
//!   whole and follows it into blocks that were never written — which is worse
//!   than losing the checkpoint, because nothing detects it.
//!
//! Both are fixed by ordering rather than by writing more: a barrier before the
//! commit block, and the commit block itself written through the cache. What
//! this module holds is the DECISIONS — whether a barrier is owed, which member
//! of a multi-device volume owes one, and what to do when one fails — as
//! functions over state, so each is checkable without a device.
//!
//! A mount that asked for `nobarrier` has said it accepts the losses above. It
//! is the only thing that may turn them off, and it turns them off everywhere:
//! a barrier issued on one path and skipped on another is worse than either.

use block::Durability;

use crate::opts::FsyncMode;

/// How many times a failed member barrier is retried before this filesystem
/// stops checkpointing.
///
/// A barrier is a whole-cache operation, so a transient refusal is worth
/// retrying rather than escalating on. What is not survivable is a member that
/// keeps refusing: the checkpoint about to be written names blocks on it, and
/// writing the pack anyway records a state the medium does not hold.
pub const FLUSH_RETRIES: u32 = 8;

/// Whether an `fsync` that took the CHAIN path owes the device a barrier.
///
/// Three states, and only the first is the common one:
///
/// - The mount asked for no barriers: nothing is owed anywhere, by the mount's
///   own choice.
/// - `fsync_mode=nobarrier`: the mount asked for exactly this call to skip it.
///   Narrower than the mount option — a checkpoint still barriers — and it
///   exists because a caller doing its own ordering pays twice otherwise.
/// - An ATOMIC write's commit: the chain is written in an order the replay can
///   follow whatever the device does with it, so the barrier buys nothing that
///   the chain does not already promise.
///
/// The CHECKPOINT path is deliberately not a case here: a checkpoint's own
/// commit block carries the promise, so an `fsync` that wrote one has already
/// been fenced and a second barrier would be pure cost.
/// # C: O(1)
pub fn fsync_needs_flush(barrier: bool, mode: FsyncMode, atomic: bool) -> bool {
    barrier && mode != FsyncMode::Nobarrier && !atomic
}

/// What one `fsync` owes, once what changed about the file is known.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SyncWork {
    /// Nothing: the file is exactly as the last checkpoint left it, and no
    /// write of this mount is waiting in a device cache on its account.
    Nothing,
    /// A barrier, and NO recovery chain.
    BarrierOnly,
    /// The whole ladder — a chain or a checkpoint, and then a barrier.
    Full,
}

/// Which of the three an `fsync` has in front of it.
///
/// `BarrierOnly` is the case a build without it silently gets wrong. A page
/// rewritten IN PLACE lands on the block the file's slot ALREADY names and the
/// block the last checkpoint ALREADY counted, so nothing about the file's
/// recorded shape changes and it compares identical to its checkpointed
/// generation — there is nothing for a recovery chain to say, and a build that
/// keys the whole call on "did anything change" therefore writes nothing and
/// returns. But the bytes DID change, and on a device with a volatile cache
/// they are sitting in it: the caller was told they were durable and a power
/// cut loses them. What the file needs is precisely the half a chain cannot
/// give it — the barrier — which is why this is a case of its own rather than
/// a branch of the other two.
/// # C: O(1)
pub fn sync_work(dirty_needs_sync: bool, unfenced_inplace: bool) -> SyncWork {
    if dirty_needs_sync { return SyncWork::Full; }
    if unfenced_inplace { return SyncWork::BarrierOnly; }
    SyncWork::Nothing
}

/// The files whose bytes were rewritten IN PLACE and not yet fenced.
///
/// Held per volume and keyed by inode number because that is what the caller
/// asks about: `fsync` names one file and must know whether THAT file has a
/// rewrite waiting in a cache. A single flag for the whole mount would make
/// every file's `fsync` pay for every other file's rewrite.
///
/// An entry is removed only by a barrier that was actually issued. Clearing it
/// on the write itself, or on a barrier that was skipped, would drop the record
/// of the one thing it exists to remember.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateWrites {
    inos: alloc::collections::BTreeSet<u32>,
}

impl UpdateWrites {
    /// Nothing rewritten yet. # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Note that a page of `ino` was rewritten where it lay. # C: O(log n)
    pub fn record(&mut self, ino: u32) { self.inos.insert(ino); }

    /// Whether `ino` has a rewrite no barrier has reached. # C: O(log n)
    pub fn owed(&self, ino: u32) -> bool { self.inos.contains(&ino) }

    /// Forget one file's, after a barrier that was issued. # C: O(log n)
    pub fn fenced(&mut self, ino: u32) { self.inos.remove(&ino); }

    /// Forget every file's, after something that fenced them all. # C: O(n)
    pub fn fenced_all(&mut self) { self.inos.clear(); }

    /// How many files are owed one. # C: O(1)
    pub fn len(&self) -> usize { self.inos.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.inos.is_empty() }
}

/// The promise the checkpoint's COMMIT BLOCK is written under.
///
/// The pack's last block is the one that makes the whole pack current: until it
/// lands the pack reads as torn and the previous one stays in force. So it is
/// the single point where both halves of the promise are needed — everything
/// the pack refers to must be on the medium BEFORE it (the pre-flush), and it
/// must be on the medium itself when the write returns (forced unit access), or
/// a mount could find a complete pack whose contents are older than it claims.
///
/// A mount that asked for no barriers gets an ordinary write, which is exactly
/// what that option means.
/// # C: O(1)
pub fn commit_block_durability(barrier: bool) -> Durability {
    if barrier { block::durability::PREFLUSH | block::durability::FUA } else { Durability::NONE }
}

/// Which members a volume owes a barrier before its checkpoint commits.
///
/// Member zero is excluded deliberately, and not because it needs no barrier:
/// it carries the pack, so its ordering is the commit block's own business and
/// flushing it here would cost a second barrier for the same guarantee. Members
/// nothing has written to are excluded because there is nothing in their caches
/// this checkpoint depends on.
///
/// A single-member volume owes nothing at all here — the commit block is the
/// whole of its ordering.
/// # C: O(devices)
pub fn checkpoint_flush_targets(barrier: bool, members: usize, dirty: u64) -> Members {
    if !barrier || members < 2 { return Members { mask: 0 }; }
    let all = if members >= 64 { u64::MAX } else { (1u64 << members) - 1 };
    Members { mask: dirty & all & !1 }
}

/// A set of member indexes, as the bit per member the volume tracks them by.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Members {
    mask: u64,
}

impl Members {
    /// Whether member `i` is in the set. # C: O(1)
    pub fn contains(self, i: usize) -> bool { i < 64 && self.mask & (1 << i) != 0 }

    /// Whether the set is empty. # C: O(1)
    pub fn is_empty(self) -> bool { self.mask == 0 }

    /// The members, lowest index first. # C: O(64)
    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..64usize).filter(move |i| self.mask & (1 << i) != 0)
    }
}

/// Which members hold writes this mount has not fenced.
///
/// Tracked because a barrier is expensive and most members of most volumes are
/// idle between two checkpoints: without this the checkpoint pays one barrier
/// per member every time, including for members it never wrote to. A bit is
/// raised where a write lands and lowered only by a barrier that succeeded — a
/// bit cleared on a failed barrier would let the next checkpoint commit over
/// data still sitting in a cache.
///
/// A volume with more than 64 members cannot be represented, and the answer for
/// one is that every member is dirty: the fallback costs barriers and cannot
/// lose one. The reference has the same 64-member ceiling for the same reason.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct DirtyDevices {
    mask: u64,
}

impl DirtyDevices {
    /// Nothing written yet. # C: O(1)
    pub const fn new() -> Self { Self { mask: 0 } }

    /// Note that a write landed on member `i`. # C: O(1)
    pub fn mark(&mut self, i: usize) {
        if i < 64 { self.mask |= 1 << i; } else { self.mask = u64::MAX; }
    }

    /// Note that member `i`'s cache is now on the medium. # C: O(1)
    pub fn clear(&mut self, i: usize) { if i < 64 { self.mask &= !(1 << i); } }

    /// The raw set, for the target decision above. # C: O(1)
    pub const fn mask(self) -> u64 { self.mask }

    /// Whether member `i` holds unfenced writes. # C: O(1)
    pub const fn is_dirty(self, i: usize) -> bool { i < 64 && self.mask & (1 << i) != 0 }
}

/// Which members hold writes of ONE FILE that no barrier has reached.
///
/// The volume-wide set next door answers a checkpoint's question — which members
/// does the pack about to be written depend on — and cannot answer an `fsync`'s,
/// which is about one file: on a volume of six members, a file whose blocks all
/// landed on one of them owes one barrier, and the volume-wide set would charge
/// it six. A barrier is a whole-cache operation, so those five are not a rounding
/// error.
///
/// An entry is dropped by the barrier that emptied the caches it named, and every
/// entry by a checkpoint, which fences everything at once. A file with NO entry is
/// owed nothing — nothing of it has been written since it was last made durable —
/// but a caller that cannot tell "nothing written" from "not recorded" must flush
/// every member rather than none: a barrier too many costs time, and one too few
/// loses data the caller was promised.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirtyInoDevices {
    inos: alloc::collections::BTreeMap<u32, u64>,
}

impl DirtyInoDevices {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Note that a block of `ino` landed on member `i`. # C: O(log files)
    pub fn mark(&mut self, ino: u32, i: usize) {
        let bit = if i < 64 { 1u64 << i } else { u64::MAX };
        *self.inos.entry(ino).or_insert(0) |= bit;
    }

    /// The members `ino` has unfenced writes on. # C: O(log files)
    pub fn mask(&self, ino: u32) -> u64 { self.inos.get(&ino).copied().unwrap_or(0) }

    /// Forget one file's, after a barrier that reached those members.
    /// # C: O(log files)
    pub fn forget(&mut self, ino: u32) { self.inos.remove(&ino); }

    /// Forget every file's, after something that fenced them all. # C: O(files)
    pub fn clear(&mut self) { self.inos.clear(); }

    /// How many files have unfenced writes recorded. # C: O(1)
    pub fn len(&self) -> usize { self.inos.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.inos.is_empty() }
}

/// Which members one file's `fsync` must fence.
///
/// A single-member volume fences its one member whatever is recorded: it carries
/// everything, so there is nothing to narrow. A multi-member volume fences the
/// members the file's own blocks landed on — and every member when nothing is
/// recorded for it, because a caller that cannot tell "nothing written" from "not
/// recorded" must not skip a barrier it may owe.
/// # C: O(1)
pub fn fsync_flush_targets(members: usize, ino_mask: u64) -> Members {
    let all = if members >= 64 { u64::MAX } else { (1u64 << members) - 1 };
    if members < 2 || ino_mask == 0 { return Members { mask: all }; }
    Members { mask: ino_mask & all }
}

#[cfg(test)]
#[path = "../tests/barrier.rs"]
mod tests;
