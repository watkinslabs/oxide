// Numeric contract of the tmpfs mount-option surface: the ceilings a value is
// refused above, and the bookkeeping unit the inode ceiling is expressed in.
// Contract-owned; no parsing or policy here.

/// Bookkeeping size charged per inode. The inode ceiling is stored as a byte
/// budget in these units, so `nr_inodes=` is refused above the count whose
/// budget would overflow the counter.
pub(crate) const BOGO_INODE_SIZE: u64 = 1024;

/// Largest `nr_inodes=` a mount may ask for: the count whose bookkeeping
/// budget still fits an unsigned long.
pub(crate) const MAX_NR_INODES: u64 = u64::MAX / BOGO_INODE_SIZE;

/// Largest `nr_blocks=` a mount may ask for. The block count is a signed long
/// on the kernel side, so a value above its maximum is refused rather than
/// wrapped negative.
pub(crate) const MAX_NR_BLOCKS: u64 = i64::MAX as u64;

/// Largest quota BLOCK hardlimit (`{usr,grp}quota_block_hardlimit=`).
pub(crate) const QUOTA_MAX_SPC_LIMIT: u64 = i64::MAX as u64;

/// Largest quota INODE hardlimit (`{usr,grp}quota_inode_hardlimit=`).
pub(crate) const QUOTA_MAX_INO_LIMIT: u64 = i64::MAX as u64;

/// Permission/setid bits `mode=` is masked to.
pub(crate) const MODE_MASK: u32 = 0o7777;

/// Percent divisor for a `size=<n>%` value.
pub(crate) const PERCENT: u64 = 100;

/// Separator between mount-data options.
pub(crate) const OPT_SEP: char = ',';
/// Separator between an option key and its value.
pub(crate) const OPT_ASSIGN: char = '=';
/// Suffix that turns a `size=` value into a percentage of RAM.
pub(crate) const PERCENT_SUFFIX: char = '%';

/// The prefix a `casefold=<version>` value must carry.
pub(crate) const CASEFOLD_UTF8_PREFIX: &str = "utf8-";

/// Inode number no object may be given: `0` is the "no inode" sentinel every
/// caller of `stat(2)` reads as absent.
pub(crate) const ZERO_INO: u64 = 0;
