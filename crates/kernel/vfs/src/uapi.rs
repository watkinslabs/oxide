/// Linux TMPFS_MAGIC shared by tmpfs and devtmpfs (`linux/magic.h`).
pub const TMPFS_SUPER_MAGIC: u64 = 0x0102_1994;

// `FALLOC_FL_*` (Linux `include/uapi/linux/falloc.h`) plus the
// `FALLOC_FL_MODE_MASK` composite (`include/linux/falloc.h`). Shared UAPI: the
// `vfs_fallocate` ladder and EVERY filesystem backend decode the same `mode`
// word, exactly as both sides of Linux include the same header.

/// `FALLOC_FL_ALLOCATE_RANGE` — "allocate range", encoded as NO bit set, which
/// is why a mode test is a masked-value comparison and not a bit test.
pub const FALLOC_FL_ALLOCATE_RANGE: u32 = 0x00;
/// `FALLOC_FL_KEEP_SIZE` — the one FLAG in the namespace; every other value is
/// a MODE, and the modes are mutually exclusive.
pub const FALLOC_FL_KEEP_SIZE:      u32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE:     u32 = 0x02;
/// `FALLOC_FL_NO_HIDE_STALE` — reserved codepoint, deliberately absent from
/// [`FALLOC_FL_MODE_MASK`], so it is always `EOPNOTSUPP`.
pub const FALLOC_FL_NO_HIDE_STALE:  u32 = 0x04;
pub const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
pub const FALLOC_FL_ZERO_RANGE:     u32 = 0x10;
pub const FALLOC_FL_INSERT_RANGE:   u32 = 0x20;
pub const FALLOC_FL_UNSHARE_RANGE:  u32 = 0x40;
pub const FALLOC_FL_WRITE_ZEROES:   u32 = 0x80;

/// `FALLOC_FL_MODE_MASK` — every mode bit, which is NOT every defined bit:
/// `FALLOC_FL_KEEP_SIZE` is a flag and `FALLOC_FL_NO_HIDE_STALE` is an
/// unimplemented reserved codepoint.
pub const FALLOC_FL_MODE_MASK: u32 = FALLOC_FL_ALLOCATE_RANGE | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_WRITE_ZEROES;
