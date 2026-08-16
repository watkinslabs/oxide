//! What one mount was asked for, and what it reports back.
//!
//! Module manifest:
//! - `parse`: one `-o` string into an option set.
//! - `show`:  an option set back into the string the mount table carries.

pub mod parse;
pub mod show;

pub use parse::parse;
pub use show::show;

/// How a segment is picked for the next write.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AllocMode {
    /// Reuse space inside a partly-used segment when one is available.
    Reuse,
    /// Always append to a fresh segment.
    Default,
}

/// How much of a write must reach the medium before it is durable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FsyncMode {
    Posix,
    Strict,
    Nobarrier,
}

/// The smallest span the volume will tell the device it no longer needs.
///
/// Telling a device about single blocks is precise but chatty; telling it only
/// about whole segments or sections is what flash controllers actually want,
/// because a partial erase block cannot be erased at all.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DiscardUnit {
    Block,
    Segment,
    Section,
}

/// How much memory the mount may spend on caches.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MemoryMode {
    Normal,
    Low,
}

/// Whether a lookup in a case-folding directory rescans without the hash when
/// the hash-directed pass misses.
///
/// A volume written before its encoding changed holds entries hashed under the
/// old rules, so the bucket a fold picks today can be the wrong one for an
/// entry written yesterday. The rescan finds those; skipping it is faster and
/// correct only for a volume that asserts it has none.
pub use crate::casefold::LookupMode;

/// What a mount does when it finds the volume inconsistent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Errors {
    Continue,
    RemountRo,
    Panic,
}

/// Which log a write goes to, and how many logs there are.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Reuse obsolete space; the default.
    Adaptive,
    /// Never overwrite in place.
    Lfs,
    /// Reuse only within a segment already open for the same kind of data.
    Fragment(Fragment),
}

/// Which axis fragmenting mode fragments along.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fragment {
    Segment,
    Block,
}

/// Everything one mount was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Options {
    /// Whether the cleaner runs, and how eagerly.
    pub background_gc: BackgroundGc,
    /// Whether a crash's tail is replayed at mount.
    pub recovery: bool,
    /// Whether freed blocks are announced to the device as no longer needed.
    pub discard: bool,
    /// The smallest span worth announcing.
    pub discard_unit: DiscardUnit,
    /// How much memory the mount may spend.
    pub memory: MemoryMode,
    /// Whether extended attributes and access control are honoured.
    pub user_xattr: bool,
    pub acl: bool,
    /// Logs the volume writes through: two, four or six.
    pub active_logs: u8,
    /// Whether a new file's placement is decided by its name's extension.
    pub ext_identify: bool,
    /// Whether new files may keep attributes, data and entries inline.
    pub inline_xattr: bool,
    pub inline_xattr_size: Option<u16>,
    pub inline_data: bool,
    pub inline_dentry: bool,
    /// Whether writes are merged before the device sees them, and whether a
    /// barrier is issued at all.
    pub flush_merge: bool,
    pub barrier: bool,
    /// Whether dirty data is pushed out at each checkpoint.
    pub data_flush: bool,
    /// Whether the read extent cache is maintained.
    pub extent_cache: bool,
    pub age_extent_cache: bool,
    /// Blocks and identity reserved for the privileged caller.
    pub reserve_root: u32,
    pub resuid: u32,
    pub resgid: u32,
    pub mode: Mode,
    pub alloc_mode: AllocMode,
    pub fsync_mode: FsyncMode,
    pub errors: Errors,
    /// Whether checkpoints happen at all; disabling one makes the mount
    /// read-mostly and is why it is recorded rather than ignored.
    pub checkpoint_disabled: bool,
    pub checkpoint_merge: bool,
    /// Whether timestamps may lag the medium.
    pub lazytime: bool,
    /// Whether the free-node bitmap saved beside the checkpoint is used.
    pub nat_bits: bool,
    /// Whether the cleaner and the checkpoint share a thread.
    pub gc_merge: bool,
    /// Whether the age-threshold cleaner runs.
    pub atgc: bool,
    /// How a lookup in a folding directory handles a hash miss.
    pub lookup_mode: LookupMode,
    /// Whether quota accounting is on, per kind.
    pub usrquota: bool,
    pub grpquota: bool,
    pub prjquota: bool,
}

/// How eagerly the cleaner runs.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BackgroundGc {
    On,
    Off,
    Sync,
}

impl Options {
    /// What a mount that named nothing gets. # C: O(1)
    pub fn defaults() -> Self {
        Self {
            background_gc: BackgroundGc::On,
            recovery: true,
            discard: true,
            discard_unit: DiscardUnit::Block,
            memory: MemoryMode::Normal,
            user_xattr: true,
            acl: true,
            active_logs: 6,
            ext_identify: true,
            inline_xattr: true,
            inline_xattr_size: None,
            inline_data: true,
            inline_dentry: true,
            flush_merge: false,
            barrier: true,
            data_flush: false,
            extent_cache: true,
            age_extent_cache: false,
            reserve_root: 0,
            resuid: 0,
            resgid: 0,
            mode: Mode::Adaptive,
            alloc_mode: AllocMode::Default,
            fsync_mode: FsyncMode::Posix,
            errors: Errors::Continue,
            checkpoint_disabled: false,
            checkpoint_merge: false,
            lazytime: false,
            nat_bits: true,
            gc_merge: false,
            atgc: false,
            lookup_mode: crate::casefold::DEFAULT_LOOKUP_MODE,
            usrquota: false,
            grpquota: false,
            prjquota: false,
        }
    }
}
