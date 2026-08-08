// Token names of the behavioural (non-quota) mount options, and the table that
// turns one written token into a change to `Ext4Behaviour`.
//
// Splitting the table off `behaviour.rs` keeps the option CONTRACT (what each
// name is called, what shape of value it takes) in one file and the state it
// produces in another.

use vfs::{KResult, VfsError};

use super::{DataMode, ErrorsPolicy, Ext4Behaviour, DEFAULT_COMMIT_SECS, DEFAULT_LI_WAIT_MULT,
            MAX_COMMIT_SECS, MAX_JOURNAL_IOPRIO};

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
pub const OPT_STRIPE: &str = "stripe";
pub const OPT_RESUID: &str = "resuid";
pub const OPT_RESGID: &str = "resgid";
pub const OPT_DAX: &str = "dax";
pub const OPT_INIT_ITABLE: &str = "init_itable";
pub const OPT_NOINIT_ITABLE: &str = "noinit_itable";
pub const OPT_MB_OPTIMIZE_SCAN: &str = "mb_optimize_scan";

/// `mb_optimize_scan=` takes exactly these two values.
const MB_OPTIMIZE_OFF: u32 = 0;
const MB_OPTIMIZE_ON: u32 = 1;

impl Ext4Behaviour {
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
            OPT_STRIPE => self.stripe = number(value(val)?)?,
            OPT_RESUID => self.resuid = number(value(val)?)?,
            OPT_RESGID => self.resgid = number(value(val)?)?,
            // Lazy inode-table initialisation. The bare word selects the
            // default wait multiplier; the valued spelling names its own.
            OPT_INIT_ITABLE => self.li_wait_mult = Some(match val {
                None => DEFAULT_LI_WAIT_MULT,
                Some(v) => number(v)?,
            }),
            OPT_NOINIT_ITABLE => { flag(val)?; self.li_wait_mult = None; }
            OPT_MB_OPTIMIZE_SCAN => self.mb_optimize_scan = Some(match number(value(val)?)? {
                MB_OPTIMIZE_OFF => false,
                MB_OPTIMIZE_ON => true,
                _ => return Err(VfsError::Einval),
            }),
            // Direct-access mappings require a block device that can be mapped
            // without a page cache. There is no such device class here, and the
            // build that has none refuses the option rather than mounting a
            // filesystem whose files would silently not be DAX.
            OPT_DAX => return Err(VfsError::Einval),
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
