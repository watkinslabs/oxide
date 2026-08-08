// The non-quota half of an ext4 mount's option state: the options that change
// how the filesystem BEHAVES rather than who it accounts to.
//
// Every value here has one home — the mounted filesystem's option state — and
// a consumer that reads it from there. An option parsed into a field nothing
// reads would be the same defect this module exists to remove: `-o
// errors=remount-ro` that does not remount read-only is worse than a mount
// that refuses the option, because the administrator believes it took.

use vfs::{KResult, VfsError};

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

pub const OPT_ERRORS: &str = "errors";
pub const OPT_DATA: &str = "data";
pub const OPT_COMMIT: &str = "commit";
pub const OPT_JOURNAL_IOPRIO: &str = "journal_ioprio";
pub const OPT_MAX_DIR_SIZE_KB: &str = "max_dir_size_kb";
pub const OPT_BARRIER: &str = "barrier";
pub const OPT_NOBARRIER: &str = "nobarrier";
pub const OPT_DISCARD: &str = "discard";
pub const OPT_NODISCARD: &str = "nodiscard";
pub const OPT_DELALLOC: &str = "delalloc";
pub const OPT_NODELALLOC: &str = "nodelalloc";
pub const OPT_BLOCK_VALIDITY: &str = "block_validity";
pub const OPT_NOBLOCK_VALIDITY: &str = "noblock_validity";
pub const OPT_NOLOAD: &str = "noload";
pub const OPT_NORECOVERY: &str = "norecovery";
pub const OPT_WARN_ON_ERROR: &str = "warn_on_error";
pub const OPT_NOWARN_ON_ERROR: &str = "nowarn_on_error";

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

    /// Consume one behavioural option. `Ok(false)` = not one of these keys.
    ///
    /// A value that is not one of the values the option takes is refused. It
    /// used to be swallowed, which made `-o errors=remount-rw` — a typo with
    /// no such value — mount silently with the default policy.
    /// # C: O(len(val))
    pub fn parse_one(&mut self, key: &str, val: Option<&str>) -> KResult<bool> {
        match key {
            OPT_ERRORS => self.errors = ErrorsPolicy::from_name(value(val)?).ok_or(VfsError::Einval)?,
            OPT_DATA => self.data = DataMode::from_name(value(val)?).ok_or(VfsError::Einval)?,
            OPT_COMMIT => {
                let n = number(value(val)?)?;
                // Zero does not mean "never commit"; it means "the default".
                if n == 0 { self.commit_secs = DEFAULT_COMMIT_SECS; }
                else if n > MAX_COMMIT_SECS { return Err(VfsError::Einval); }
                else { self.commit_secs = n; }
            }
            OPT_JOURNAL_IOPRIO => {
                let n = number(value(val)?)?;
                if n > MAX_JOURNAL_IOPRIO { return Err(VfsError::Einval); }
                self.journal_ioprio = n;
            }
            OPT_MAX_DIR_SIZE_KB => self.max_dir_size_kb = number(value(val)?)?,
            // `barrier` carries a value in its other spelling, where a zero
            // turns it OFF — the same answer `nobarrier` gives.
            OPT_BARRIER => self.barrier = match val {
                None => true,
                Some(v) => number(v)? != 0,
            },
            OPT_NOBARRIER => { flag(val)?; self.barrier = false; }
            OPT_DISCARD => { flag(val)?; self.discard = true; }
            OPT_NODISCARD => { flag(val)?; self.discard = false; }
            OPT_DELALLOC => { flag(val)?; self.delalloc = true; }
            OPT_NODELALLOC => { flag(val)?; self.delalloc = false; }
            OPT_BLOCK_VALIDITY => { flag(val)?; self.block_validity = true; }
            OPT_NOBLOCK_VALIDITY => { flag(val)?; self.block_validity = false; }
            // Two spellings of one answer: do not replay the journal.
            OPT_NOLOAD | OPT_NORECOVERY => { flag(val)?; self.noload = true; }
            OPT_WARN_ON_ERROR => { flag(val)?; self.warn_on_error = true; }
            OPT_NOWARN_ON_ERROR => { flag(val)?; self.warn_on_error = false; }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// The value of a key that requires one. # C: O(1)
fn value(val: Option<&str>) -> KResult<&str> { val.ok_or(VfsError::Einval) }

/// Refuse a value on a key that takes none. # C: O(1)
fn flag(val: Option<&str>) -> KResult<()> {
    if val.is_some() { return Err(VfsError::Einval); }
    Ok(())
}

/// A plain unsigned decimal value, with nothing else in it. # C: O(len)
fn number(val: &str) -> KResult<u32> {
    if val.is_empty() { return Err(VfsError::Einval); }
    val.parse::<u32>().map_err(|_| VfsError::Einval)
}
