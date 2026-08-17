//! Whether one file can be made durable by writing its nodes, or whether
//! nothing short of a whole checkpoint will do.
//!
//! The fast path writes the file's node blocks with a mark and a forward
//! pointer and stops there. That is only honest while the next mount can put
//! the file back from those blocks ALONE — and there are states in which it
//! cannot, because what the file depends on is itself only in memory. A file
//! whose directory entry has not been checkpointed is the plain case: replay
//! would restore the blocks and leave them unreachable, so the fsync would
//! have reported durability for a file with no name.
//!
//! Each state below is a reason to write a checkpoint instead. The decision is
//! a pure function of them, deliberately, so the ladder can be tested without
//! a volume — the failure mode being guarded against is a fast path taken in a
//! state that needed the slow one, which produces no error at the time and
//! loses the file at the next crash.

/// Why one `fsync` cannot take the node-chain path.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CpReason {
    /// The fast path is available.
    None,
    /// Not a regular file: a directory's nodes are not in the chain the walk
    /// follows, so nothing would replay them.
    NonRegular,
    /// A compressed file's blocks are a cluster, not an index.
    Compressed,
    /// More than one name reaches the inode, and replay restores one file, not
    /// a link count.
    Hardlink,
    /// The volume as a whole is owed a checkpoint, whatever this file's state.
    ///
    /// One thing raises it: a strict mount rewriting a directory's attributes,
    /// which such a mount answers volume-wide rather than per directory.
    SbNeedCp,
    /// The recorded parent is known to be stale, so no entry can be restored.
    WrongPino,
    /// Replaying would need more blocks than the volume has left.
    NoSpaceRollForward,
    /// The parent directory's node has not been checkpointed, so the file's
    /// own directory entry is not durable yet.
    ParentNotCheckpointed,
    /// The mount asked to skip the work that only makes LATER mounts faster.
    ///
    /// The chain is exactly that work moved to the next mount: it leaves blocks
    /// the next mount has to go looking for. A mount that said it does not want
    /// a replay to happen therefore pays for the checkpoint now instead.
    Fastboot,
    /// Two logs put file nodes where the walk does not look.
    SpecLogNum,
    /// Strict mode, and the parent lost or gained an entry this epoch.
    RecoverDir,
    /// The parent's attributes were rewritten this epoch.
    XattrDir,
}

impl CpReason {
    /// Whether a checkpoint has to be written. # C: O(1)
    pub fn needed(self) -> bool { self != CpReason::None }
}

/// Everything the decision reads, gathered once.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SyncState {
    pub regular: bool,
    pub compressed: bool,
    /// Names reaching the inode. Anything but one takes the checkpoint.
    pub links: u32,
    /// Whether the volume as a whole is owed a checkpoint.
    pub sb_need_cp: bool,
    /// Whether the recorded parent number is still trustworthy.
    pub pino_ok: bool,
    pub space_for_roll_forward: bool,
    /// Whether the parent directory's node reached the last checkpoint.
    pub parent_checkpointed: bool,
    /// Whether the mount asked to leave nothing for the next mount to replay.
    pub fastboot: bool,
    pub active_logs: u8,
    pub strict: bool,
    /// Whether this inode's own entry may still need restoring.
    pub need_dentry_mark: bool,
    /// Whether the parent lost or gained an entry since the last checkpoint,
    /// under a strict mount. This is an EVENT the mount recorded, not a state
    /// the parent's blocks show: an ordinary write to a directory rewrites its
    /// node too, and reading that as this reason makes almost every strict
    /// `fsync` write a whole checkpoint.
    pub parent_in_trans_dir: bool,
    /// Whether the parent's attributes were rewritten since the last
    /// checkpoint, recorded the same way and for the same reason.
    pub parent_in_xattr_dir: bool,
}

/// The number of logs at which file nodes stop having a log of their own.
const SPEC_LOG_NUM: u8 = 2;

/// Which reason, if any, forces a checkpoint.
///
/// Order is the contract, not a detail: the first matching reason is the one
/// reported, and a state matching several must report the earliest so the
/// answer does not drift when an unrelated condition changes.
/// # C: O(1)
pub fn need_checkpoint(s: &SyncState) -> CpReason {
    if !s.regular { return CpReason::NonRegular; }
    if s.compressed { return CpReason::Compressed; }
    if s.links != 1 { return CpReason::Hardlink; }
    if s.sb_need_cp { return CpReason::SbNeedCp; }
    if !s.pino_ok { return CpReason::WrongPino; }
    if !s.space_for_roll_forward { return CpReason::NoSpaceRollForward; }
    if !s.parent_checkpointed { return CpReason::ParentNotCheckpointed; }
    if s.fastboot { return CpReason::Fastboot; }
    if s.active_logs == SPEC_LOG_NUM { return CpReason::SpecLogNum; }
    if s.strict && s.need_dentry_mark && s.parent_in_trans_dir { return CpReason::RecoverDir; }
    if s.parent_in_xattr_dir { return CpReason::XattrDir; }
    CpReason::None
}

#[cfg(test)]
#[path = "../../tests/fsync/reason.rs"]
mod tests;

/// The two parent-directory rungs, driven through the operations that record
/// them rather than through the decision alone.
#[cfg(test)]
#[path = "../../tests/fsync/inolists.rs"]
mod inolist_tests;
