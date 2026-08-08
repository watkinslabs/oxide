// The non-quota half of an ext4 mount's option state: the options that change
// how the filesystem BEHAVES rather than who it accounts to.
//
// Every value here has one home — the mounted filesystem's option state — and
// a consumer that reads it from there. An option parsed into a field nothing
// reads would be the same defect this module exists to remove: `-o
// errors=remount-ro` that does not remount read-only is worse than a mount
// that refuses the option, because the administrator believes it took.
//
// Module manifest:
// - parse: option token names + the table that turns one token into a change.

mod parse;

pub use parse::{OPT_BARRIER, OPT_BLOCK_VALIDITY, OPT_COMMIT, OPT_DATA, OPT_DAX, OPT_DELALLOC,
                OPT_DISCARD, OPT_ERRORS, OPT_INIT_ITABLE, OPT_JOURNAL_IOPRIO,
                OPT_MAX_DIR_SIZE_KB, OPT_MB_OPTIMIZE_SCAN, OPT_NOBARRIER,
                OPT_NOBLOCK_VALIDITY, OPT_NODELALLOC, OPT_NODISCARD, OPT_NOINIT_ITABLE,
                OPT_NOLOAD, OPT_NORECOVERY, OPT_NOWARN_ON_ERROR, OPT_RESGID, OPT_RESUID,
                OPT_STRIPE, OPT_WARN_ON_ERROR};

/// What the filesystem does when it finds its own on-disk state wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorsPolicy {
    /// Keep going and let the caller see the error.
    Continue,
    /// Stop accepting writes.
    RemountRo,
    /// Take the machine down rather than risk further damage.
    Panic,
}

/// How file data is ordered against the metadata journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataMode {
    /// Data goes through the journal with the metadata.
    Journal,
    /// Data is written before the metadata that references it commits.
    Ordered,
    /// Data is not ordered against metadata at all.
    Writeback,
}

const ERRORS_CONTINUE: &str = "continue";
const ERRORS_PANIC: &str = "panic";
const ERRORS_REMOUNT_RO: &str = "remount-ro";

const DATA_JOURNAL: &str = "journal";
const DATA_ORDERED: &str = "ordered";
const DATA_WRITEBACK: &str = "writeback";

/// On-disk `s_errors` values.
pub const SB_ERRORS_CONTINUE: u16 = 1;
pub const SB_ERRORS_RO: u16 = 2;
pub const SB_ERRORS_PANIC: u16 = 3;

/// Journal commit interval a mount that names none gets, in seconds.
pub const DEFAULT_COMMIT_SECS: u32 = 5;
/// Largest commit interval that still fits the kernel's tick arithmetic.
pub const MAX_COMMIT_SECS: u32 = (i32::MAX as u32) / TICKS_PER_SEC;
/// Ticks per second the commit interval is stored in.
const TICKS_PER_SEC: u32 = 1000;

/// Journal writeback I/O priority level a mount that names none gets.
pub const DEFAULT_JOURNAL_IOPRIO: u32 = 3;
/// Highest I/O priority LEVEL there is; the option is a level, not a class.
pub const MAX_JOURNAL_IOPRIO: u32 = 7;

/// `max_dir_size_kb=0` means no ceiling.
pub const NO_DIR_SIZE_LIMIT: u32 = 0;
/// Bytes per kilobyte, for turning the directory ceiling into a size.
pub const BYTES_PER_KB: u64 = 1024;
/// Shift from bytes to kilobytes, which is how the directory ceiling is
/// compared: the ceiling is written in kB and the size held in bytes.
pub const KB_SHIFT: u32 = 10;

/// Wait multiplier a bare `init_itable` selects.
pub const DEFAULT_LI_WAIT_MULT: u32 = 10;

/// `resuid=`/`resgid=` of a mount that names neither: the reserved blocks
/// belong to root.
pub const DEFAULT_RESUID: u32 = 0;
pub const DEFAULT_RESGID: u32 = 0;

/// `stripe=0` means the allocator aligns to nothing.
pub const NO_STRIPE: u32 = 0;

impl ErrorsPolicy {
    /// Written `errors=` value → policy. # C: O(1)
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            ERRORS_CONTINUE => Some(Self::Continue),
            ERRORS_PANIC => Some(Self::Panic),
            ERRORS_REMOUNT_RO => Some(Self::RemountRo),
            _ => None,
        }
    }
    /// The `errors=` name `/proc/mounts` shows. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            Self::Continue => ERRORS_CONTINUE,
            Self::Panic => ERRORS_PANIC,
            Self::RemountRo => ERRORS_REMOUNT_RO,
        }
    }
    /// The policy an on-disk `s_errors` asks for. A superblock that names
    /// nothing recognisable gets the conservative answer: stop writing.
    /// # C: O(1)
    pub fn from_sb_errors(s_errors: u16) -> Self {
        match s_errors {
            SB_ERRORS_PANIC => Self::Panic,
            SB_ERRORS_CONTINUE => Self::Continue,
            _ => Self::RemountRo,
        }
    }
}

impl DataMode {
    /// Written `data=` value → mode. # C: O(1)
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            DATA_JOURNAL => Some(Self::Journal),
            DATA_ORDERED => Some(Self::Ordered),
            DATA_WRITEBACK => Some(Self::Writeback),
            _ => None,
        }
    }
    /// The `data=` name `/proc/mounts` shows. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            Self::Journal => DATA_JOURNAL,
            Self::Ordered => DATA_ORDERED,
            Self::Writeback => DATA_WRITEBACK,
        }
    }
    /// True when a file data block must go through the journal with the
    /// metadata that references it. # C: O(1)
    pub fn journals_data(self) -> bool { matches!(self, Self::Journal) }
    /// True when file data must be on the device BEFORE the metadata that
    /// references it commits — the guarantee that stops a crash exposing a
    /// freshly-allocated block's previous contents through a committed extent.
    /// # C: O(1)
    pub fn orders_data(self) -> bool { matches!(self, Self::Ordered) }
}

/// The behavioural options in force on one mounted filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4Behaviour {
    /// `errors=` — what a discovered on-disk inconsistency does.
    pub errors: ErrorsPolicy,
    /// `data=` — data/metadata journal ordering.
    pub data: DataMode,
    /// `commit=` — journal commit interval, in seconds.
    pub commit_secs: u32,
    /// `journal_ioprio=` — I/O priority level of journal writeback.
    pub journal_ioprio: u32,
    /// `max_dir_size_kb=` — ceiling on a directory's size; 0 is no ceiling.
    pub max_dir_size_kb: u32,
    /// `stripe=` — RAID stripe width, in filesystem blocks, the allocator
    /// aligns a full-stripe allocation to; 0 is no alignment.
    pub stripe: u32,
    /// `resuid=` — the user who may consume the superblock's reserved blocks.
    pub resuid: u32,
    /// `resgid=` — the group whose members may consume them.
    pub resgid: u32,
    /// `init_itable=`/`noinit_itable` — lazy inode-table initialisation, and
    /// the wait multiplier it paces itself by; `None` = turned off.
    pub li_wait_mult: Option<u32>,
    /// `mb_optimize_scan=` — whether the block allocator scans groups in
    /// free-space order rather than in group order. `None` = the mount named
    /// no preference, so the filesystem's own size decides.
    pub mb_optimize_scan: Option<bool>,
    /// `barrier`/`nobarrier` — whether durability points take a device flush.
    pub barrier: bool,
    /// `discard`/`nodiscard` — whether freed blocks are handed back to the
    /// device.
    pub discard: bool,
    /// `delalloc`/`nodelalloc` — whether allocation is deferred to writeback.
    pub delalloc: bool,
    /// `block_validity`/`noblock_validity` — whether block ranges are checked
    /// against the filesystem's own metadata before use.
    pub block_validity: bool,
    /// `noload`/`norecovery` — skip journal replay at mount.
    pub noload: bool,
    /// `warn_on_error` — announce a filesystem error loudly.
    pub warn_on_error: bool,
}

impl Default for Ext4Behaviour {
    /// The answers a mount that names no options gets. # C: O(1)
    fn default() -> Self {
        Self {
            errors: ErrorsPolicy::RemountRo,
            data: DataMode::Ordered,
            commit_secs: DEFAULT_COMMIT_SECS,
            journal_ioprio: DEFAULT_JOURNAL_IOPRIO,
            max_dir_size_kb: NO_DIR_SIZE_LIMIT,
            stripe: NO_STRIPE,
            resuid: DEFAULT_RESUID,
            resgid: DEFAULT_RESGID,
            li_wait_mult: Some(DEFAULT_LI_WAIT_MULT),
            mb_optimize_scan: None,
            barrier: true,
            discard: false,
            delalloc: true,
            block_validity: true,
            noload: false,
            warn_on_error: false,
        }
    }
}

impl Ext4Behaviour {
    /// The defaults of a filesystem whose superblock names its own error
    /// policy. `errors=` on the command line still overrides it. # C: O(1)
    pub fn for_sb_errors(s_errors: u16) -> Self {
        Self { errors: ErrorsPolicy::from_sb_errors(s_errors), ..Self::default() }
    }

    /// The size a directory may not grow past, in bytes; `None` when the
    /// mount set no ceiling. # C: O(1)
    pub fn max_dir_size_bytes(&self) -> Option<u64> {
        if self.max_dir_size_kb == NO_DIR_SIZE_LIMIT { return None; }
        Some(self.max_dir_size_kb as u64 * BYTES_PER_KB)
    }

    /// Whether a directory currently `size` bytes long may be GROWN by another
    /// block. The comparison is the ceiling's own unit — the directory's size
    /// in whole kilobytes against the written kB ceiling — and it is `>=`, so a
    /// directory that has exactly reached the ceiling may not grow again.
    /// # C: O(1)
    pub fn dir_may_grow(&self, size: u64) -> bool {
        if self.max_dir_size_kb == NO_DIR_SIZE_LIMIT { return true; }
        (size >> KB_SHIFT) < self.max_dir_size_kb as u64
    }

    /// Whether `uid`/`gids` may consume the superblock's reserved blocks.
    /// The group half is only consulted for a NON-root `resgid=`: a mount that
    /// left it at the default reserves for root alone, and treating that
    /// default as "every member of group 0" would hand the reserve to a whole
    /// class of processes the option never named.
    /// # C: O(len(gids))
    pub fn may_use_reserved(&self, uid: u32, gids: &[u32]) -> bool {
        if uid == self.resuid { return true; }
        self.resgid != DEFAULT_RESGID && gids.contains(&self.resgid)
    }
}
