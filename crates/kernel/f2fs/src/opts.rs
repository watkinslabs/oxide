//! What one mount was asked for, and what it reports back.
//!
//! Module manifest:
//! - `parse`:  one `-o` string into an option set.
//! - `show`:   an option set back into the string the mount table carries.
//! - `bounds`: the range each valued option's argument must fall in.
//! - `crypt`:  the dummy policy, and where encryption happens.
//! - `jquota`: quota files named on the mount line, and their format.
//! - `spec`:   which keys the line actually named, as against their values.
//! - `facts`:  the defaults the volume's own shape dictates.
//! - `compress`: the six names that decide what a new file is compressed with.

pub mod parse;
pub mod show;
pub mod bounds;
pub mod crypt;
pub mod jquota;
pub mod spec;
pub mod facts;
pub mod compress;

pub use parse::{parse, parse_spec};
pub use spec::Spec;
pub use facts::Facts;
pub use compress::{Compress, ExtList};
pub use show::show;
pub use crypt::DummyPolicy;
pub use jquota::{JqFmt, Jquota, QKind, QfName};

#[cfg(test)]
#[path = "tests/opts/mod.rs"]
mod tests;

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
    /// Whether the line said `norecovery` specifically, as against
    /// `disable_roll_forward`.
    ///
    /// Both stop the replay, and only one of them demands a read-only mount:
    /// skipping the replay on a mount that then WRITES leaves the chain the
    /// crash left behind unreachable and its blocks allocatable, so the next
    /// mount replays a chain that has been overwritten. The two spellings must
    /// therefore stay distinguishable after parsing.
    pub norecovery: bool,
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
    /// Whether the mount skips the work that only makes LATER mounts faster.
    ///
    /// A volume mounted this way is correct and slower to mount next time; the
    /// option exists for a device that is about to be powered off anyway.
    pub fastboot: bool,
    /// Blocks and identity reserved for the privileged caller.
    pub reserve_root: u32,
    /// Node slots reserved for the same caller. A volume can exhaust either
    /// axis, so reserving only blocks leaves the privileged caller unable to
    /// create the file it needed the reserve for.
    pub reserve_node: u32,
    pub resuid: u32,
    pub resgid: u32,
    pub mode: Mode,
    pub alloc_mode: AllocMode,
    pub fsync_mode: FsyncMode,
    pub errors: Errors,
    /// Whether checkpoints happen at all; disabling one makes the mount
    /// read-mostly and is why it is recorded rather than ignored.
    pub checkpoint_disabled: bool,
    /// How much space the mount may leave unusable while checkpoints are off,
    /// as an absolute number of blocks and as a percentage of the volume.
    ///
    /// Two fields, not one, because the mount line spells them differently and
    /// a percentage cannot be resolved to blocks until the volume's size is
    /// known — which is not here.
    pub unusable_cap: u32,
    pub unusable_cap_perc: u32,
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
    /// Quota files named on the mount line, and the format they are in. The
    /// other arrangement entirely: records in ordinary root files rather than
    /// in the hidden inodes the superblock names.
    pub jquota: Jquota,
    /// How often, and at which sites, an operation is failed on purpose.
    pub fault: crate::fault::Cfg,
    /// The policy every new file is created under when the mount asked for the
    /// well-known test key.
    pub dummy_policy: Option<DummyPolicy>,
    /// Whether encryption is asked to happen on the way to the device rather
    /// than in the filesystem. Same ciphertext either way; different place.
    pub inlinecrypt: bool,
    /// What a new file is created compressed with, and which files are.
    ///
    /// One group rather than seven fields beside each other, because a volume
    /// whose feature set cannot record compression drops the whole group at
    /// once: leaving one of them behind would mean a mount reporting a codec
    /// for files that can never carry one.
    pub compress: Compress,
    /// Whether the mount keeps the compressed blocks it reads, so a second
    /// read of the same cluster does not go back to the medium.
    ///
    /// Beside the group rather than inside it because it is not a property of
    /// files being created: it changes what THIS mount does with what it
    /// reads, and it is the one compression name a remount may not change.
    pub compress_cache: bool,
}

/// Who compresses a compressible file's clusters.
///
/// Not a preference: it decides whether the two rewrite commands mean anything
/// at all. Where the mount compresses, a file is written in its final shape and
/// a caller asking for it to be compressed is asking for what already happened;
/// where the caller does, a file is written plain and stays plain until one of
/// those commands is issued, so refusing them would leave the mount unable to
/// compress anything.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CompressMode {
    /// The mount compresses as it writes; the default.
    Fs,
    /// The caller compresses, through the rewrite commands.
    User,
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
            norecovery: false,
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
            fastboot: false,
            reserve_root: 0,
            reserve_node: 0,
            resuid: 0,
            resgid: 0,
            mode: Mode::Adaptive,
            alloc_mode: AllocMode::Default,
            fsync_mode: FsyncMode::Posix,
            errors: Errors::Continue,
            checkpoint_disabled: false,
            unusable_cap: 0,
            unusable_cap_perc: 0,
            checkpoint_merge: true,
            lazytime: true,
            nat_bits: false,
            gc_merge: false,
            atgc: false,
            lookup_mode: crate::casefold::DEFAULT_LOOKUP_MODE,
            usrquota: false,
            grpquota: false,
            prjquota: false,
            jquota: Jquota { names: [None; jquota::QKINDS], fmt: None },
            fault: crate::fault::Cfg { rate: None, types: None },
            dummy_policy: None,
            inlinecrypt: false,
            compress: Compress::defaults(),
            compress_cache: false,
        }
    }
}
