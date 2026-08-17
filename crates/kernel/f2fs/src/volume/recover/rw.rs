//! Making a read-only mount writable for the length of a repair.
//!
//! A mount asked for read-only still has to put a crashed volume back
//! together. The orphan list has to be reclaimed and the node chain replayed,
//! and BOTH write — to the tree, and to the quota files that account for it.
//! A mount that skipped them because the caller said read-only would hand
//! back a filesystem missing writes an `fsync` promised, with nothing saying
//! so; the next clean unmount then retires the chain and the loss is
//! permanent.
//!
//! So the mount lifts its own read-only for exactly that window and puts it
//! back afterwards, and raises the mark that says it did. The mark is what
//! makes the difference visible: the same repair on a read-only mount and on
//! a writable one are materially different events, and a reporting surface
//! that could not tell them apart would describe a read-only filesystem that
//! wrote to its medium as an ordinary mount.
//!
//! Two things bound it, and only two:
//!
//! - The DEVICE. A medium that refuses writes cannot be repaired at all, and
//!   nothing here pretends otherwise.
//! - Whether there is anything to repair. A clean volume is not made writable
//!   for a repair it does not need.
//!
//! The volume's read-only FEATURE is deliberately not among them. The feature
//! describes what a mount may offer its users, not whether the filesystem may
//! finish work a crash interrupted, and a volume left mid-repair because its
//! feature word said read-only is a volume no read-only mount can ever fix.

/// What decides whether a repair is owed.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Facts {
    /// Whether the checkpoint says orphan inodes are still to be reclaimed.
    pub orphans_present: bool,
    /// Whether this mount is allowed to replay a node chain at all.
    pub replays: bool,
    /// Whether the checkpoint was written by a clean unmount.
    pub clean_umount: bool,
}

/// Whether this mount has a repair to run.
///
/// The orphan list comes first and is unconditional: it is owed whatever the
/// mount asked about roll-forward, because the inodes it names are already
/// unlinked and their blocks are already unreachable. Only the chain half is
/// the caller's to decline, and after a clean unmount there is no chain.
/// # C: O(1)
pub fn need_recovery(f: Facts) -> bool {
    if f.orphans_present { return true; }
    if !f.replays { return false; }
    !f.clean_umount
}

/// Whether the mount must lift its own read-only to run that repair.
///
/// `hw_writable` is the medium's answer and `mount_writable` the caller's. A
/// mount that may already write has nothing to lift and nothing to restore,
/// which is why this is false there rather than true — the mark it would
/// raise says "a read-only mount is writing anyway", and raising it on a
/// writable mount would be a false statement that the thaw side would then
/// act on by making the mount read-only.
/// # C: O(1)
pub fn lift_read_only(need: bool, hw_writable: bool, mount_writable: bool) -> bool {
    need && hw_writable && !mount_writable
}

#[cfg(test)]
#[path = "../../tests/recover/rw.rs"]
mod tests;
