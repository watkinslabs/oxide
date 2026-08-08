// ext4 on-disk timestamp contract: the `(i_*time, i_*time_extra)` field pair,
// the `EXT4_FITS_IN_INODE` presence predicate that decides whether the extra
// word exists at all, and the superblock time-range advertisement.
//
// The extra-time encode/decode functions, the presence-predicate macro, the
// timestamp-range limits, superblock time-range field selection, and the
// inode read path's `i_extra_isize` handling are all on-disk ABI Linux
// defines and this module mirrors.
//
// The seconds field is SIGNED: `EXT4_TIMESTAMP_MIN` is `S32_MIN`
// (1901-12-13), so pre-1970 times are in range for ext4 and must sign-extend
// on decode. A zero-extending decode reads a 1901 mtime back as year 2106.

use vfs::timespec::NSEC_PER_SEC;
use vfs::Timespec64;

use crate::csum::EXT4_GOOD_OLD_INODE_SIZE;
use crate::layout::I_EXTRA_ISIZE;

#[cfg(test)]
mod tests;

/// Width of the epoch-high field packed into the low bits of `i_*time_extra`
/// (Linux `EXT4_EPOCH_BITS`). # C: O(1)
pub const EXT4_EPOCH_BITS: u32 = 2;

/// Mask selecting the epoch-high bits of `i_*time_extra` (Linux
/// `EXT4_EPOCH_MASK`). # C: O(1)
pub const EXT4_EPOCH_MASK: u32 = (1 << EXT4_EPOCH_BITS) - 1;

/// Mask selecting the nanosecond bits of `i_*time_extra` (Linux
/// `EXT4_NSEC_MASK`, `~0UL << EXT4_EPOCH_BITS`). # C: O(1)
pub const EXT4_NSEC_MASK: u32 = !0u32 << EXT4_EPOCH_BITS;

/// Earliest second ext4 can store — `S32_MIN`, 1901-12-13 (Linux
/// `EXT4_TIMESTAMP_MIN`). Holds for BOTH the extra and non-extra layouts:
/// the base field is a signed 32-bit second count in either case. # C: O(1)
pub const EXT4_TIMESTAMP_MIN: i64 = i32::MIN as i64;

/// Latest second an inode WITH `i_*time_extra` can store — 34 bits of range
/// biased by `S32_MIN`, year 2446 (Linux `EXT4_EXTRA_TIMESTAMP_MAX`). Beyond a
/// 64-bit nanosecond scalar, which is why the VFS model is a split pair.
/// # C: O(1)
pub const EXT4_EXTRA_TIMESTAMP_MAX: i64 = ((1i64 << 34) - 1) + EXT4_TIMESTAMP_MIN;

/// Latest second an inode WITHOUT `i_*time_extra` can store — `S32_MAX`,
/// 2038-01-19 (Linux `EXT4_NON_EXTRA_TIMESTAMP_MAX`). # C: O(1)
pub const EXT4_NON_EXTRA_TIMESTAMP_MAX: i64 = i32::MAX as i64;

/// `sizeof(struct ext4_inode) - EXT4_GOOD_OLD_INODE_SIZE` — the extra-region
/// width the inode read path substitutes when the on-disk
/// `i_extra_isize` is 0 but the inode is larger than 128 bytes ("the extra
/// space is currently unused, use it"). # C: O(1)
pub const EXT4_INODE_EXTRA_ISIZE_DEFAULT: usize = 32;

// `struct ext4_inode` timestamp field byte offsets. Sole owner: every reader
// and writer of an ext4 timestamp takes them from here.
/// `i_atime`. # C: O(1)
pub(crate) const I_ATIME: usize = 0x08;
/// `i_ctime`. # C: O(1)
pub(crate) const I_CTIME: usize = 0x0C;
/// `i_mtime`. # C: O(1)
pub(crate) const I_MTIME: usize = 0x10;
/// `i_ctime_extra`. # C: O(1)
pub(crate) const I_CTIME_EXTRA: usize = 0x84;
/// `i_mtime_extra`. # C: O(1)
pub(crate) const I_MTIME_EXTRA: usize = 0x88;
/// `i_atime_extra`. # C: O(1)
pub(crate) const I_ATIME_EXTRA: usize = 0x8C;
/// `i_crtime` (birth time). # C: O(1)
pub(crate) const I_CRTIME: usize = 0x90;
/// `i_crtime_extra`. # C: O(1)
pub(crate) const I_CRTIME_EXTRA: usize = 0x94;

/// Width of every one of those fields. # C: O(1)
pub(crate) const TIME_FIELD_LEN: usize = 4;

#[inline]
fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn wr32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + TIME_FIELD_LEN].copy_from_slice(&v.to_le_bytes());
}

/// `ei->i_extra_isize` as the inode read path computes it: 0 for a
/// 128-byte inode; otherwise the on-disk `i_extra_isize`, with 0 upgraded to
/// [`EXT4_INODE_EXTRA_ISIZE_DEFAULT`] because Linux claims the unused extra
/// region on first use. Bounded by the slot so a corrupt value cannot make
/// [`fits_in_inode`] admit an out-of-slot read (Linux rejects the inode
/// outright with `-EFSCORRUPTED`; a parser has no error channel here).
/// # C: O(1)
pub fn inode_extra_isize(raw: &[u8], inode_size: usize) -> usize {
    if inode_size <= EXT4_GOOD_OLD_INODE_SIZE { return 0; }
    if raw.len() < I_EXTRA_ISIZE + 2 { return 0; }
    let on_disk = u16::from_le_bytes([raw[I_EXTRA_ISIZE], raw[I_EXTRA_ISIZE + 1]]) as usize;
    let claimed = if on_disk == 0 { EXT4_INODE_EXTRA_ISIZE_DEFAULT } else { on_disk };
    core::cmp::min(claimed, inode_size - EXT4_GOOD_OLD_INODE_SIZE)
}

/// `EXT4_FITS_IN_INODE` — true iff the field ENDING at
/// `field_end` lies inside `EXT4_GOOD_OLD_INODE_SIZE + i_extra_isize`. This is
/// the presence test for every extended field, not a size comparison against
/// the slot: a 256-byte inode formatted by an old kernel may carry no extra
/// region at all. # C: O(1)
pub fn fits_in_inode(raw: &[u8], inode_size: usize, field_end: usize) -> bool {
    field_end <= EXT4_GOOD_OLD_INODE_SIZE + inode_extra_isize(raw, inode_size)
        && field_end <= inode_size
        && field_end <= raw.len()
}

/// `ext4_encode_extra_time`: pack the seconds ABOVE the
/// signed 32-bit base field (2 bits) with the nanoseconds (30 bits).
///
/// `sec - (sec as i32 as i64)` is C's `ts.tv_sec - (s32)ts.tv_sec` — what the
/// base field's wrapping truncation loses — arithmetic-shifted down 32 and
/// masked to the epoch width. `nsec` is `< NSEC_PER_SEC` by the `Timespec64`
/// invariant, so `nsec << 2` never exceeds 32 bits. # C: O(1)
pub fn encode_extra_time(ts: Timespec64) -> u32 {
    let epoch = (((ts.sec - (ts.sec as i32 as i64)) >> 32) & EXT4_EPOCH_MASK as i64) as u32;
    epoch | (ts.nsec << EXT4_EPOCH_BITS)
}

/// Base `i_*time` word for an inode that HAS the extra field: `cpu_to_le32(
/// (ts).tv_sec)`, i.e. the low 32 bits of the signed second, wrapping.
/// [`encode_extra_time`] carries the bits this drops. # C: O(1)
pub fn encode_base(ts: Timespec64) -> u32 { ts.sec as u32 }

/// Base `i_*time` word for an inode WITHOUT the extra field
/// (`EXT4_INODE_SET_XTIME_VAL` else-branch): `clamp_t(int32_t, tv_sec, S32_MIN,
/// S32_MAX)`. A CLAMP, not a wrap — an out-of-range second pins to the
/// representable boundary instead of aliasing to an unrelated year. # C: O(1)
pub fn encode_base_clamped(ts: Timespec64) -> u32 {
    let sec = if ts.sec > EXT4_NON_EXTRA_TIMESTAMP_MAX { EXT4_NON_EXTRA_TIMESTAMP_MAX }
              else if ts.sec < EXT4_TIMESTAMP_MIN { EXT4_TIMESTAMP_MIN }
              else { ts.sec };
    sec as i32 as u32
}

/// `ext4_decode_extra_time`. The base word is SIGN-extended
/// (`(signed)le32_to_cpu(base)`) — zero-extending it is the pre-1970 read bug
/// that turns a 1901 timestamp into year 2106 — then the epoch-high bits are
/// added as a positive `<< 32` bias per the ext4.h encoding table.
///
/// A corrupt `extra` can carry a nanosecond field at or above `NSEC_PER_SEC`
/// (the field holds 30 bits); [`Timespec64::new`] folds the excess into the
/// seconds rather than storing a value that would break the ordering
/// invariant. # C: O(1)
pub fn decode_extra_time(base: u32, extra: u32) -> Timespec64 {
    let mut sec = base as i32 as i64;
    let epoch = extra & EXT4_EPOCH_MASK;
    if epoch != 0 { sec += (epoch as i64) << 32; }
    Timespec64::new(sec, (extra & EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS)
}

/// `EXT4_INODE_GET_XTIME_VAL` fallback branch — an inode with no extra field
/// carries only `(signed)le32_to_cpu(xtime)` seconds and no sub-second part.
/// # C: O(1)
pub fn decode_base_only(base: u32) -> Timespec64 { Timespec64::from_secs(base as i32 as i64) }

/// `EXT4_INODE_GET_XTIME_VAL`: decode the `(base, extra)` pair
/// at those offsets, falling back to seconds-only when the extra word is
/// outside the inode's extra region. # C: O(1)
pub(crate) fn get_xtime(raw: &[u8], inode_size: usize, base_off: usize, extra_off: usize)
    -> Timespec64
{
    let base = rd32(raw, base_off);
    if fits_in_inode(raw, inode_size, extra_off + TIME_FIELD_LEN) {
        decode_extra_time(base, rd32(raw, extra_off))
    } else {
        decode_base_only(base)
    }
}

/// `EXT4_EINODE_GET_XTIME(i_crtime, ...)`: the birth time
/// exists only when the `i_crtime` field itself lies in the extra region —
/// the same predicate Linux `statx(2)` uses to decide whether to set
/// `STATX_BTIME` in the result mask. `None` means "this inode
/// stores no creation time", which is distinct from a creation time of the
/// epoch second. # C: O(1)
pub(crate) fn get_crtime(raw: &[u8], inode_size: usize) -> Option<Timespec64> {
    if !fits_in_inode(raw, inode_size, I_CRTIME + TIME_FIELD_LEN) { return None; }
    Some(get_xtime(raw, inode_size, I_CRTIME, I_CRTIME_EXTRA))
}

/// `EXT4_INODE_SET_XTIME_VAL`: write the `(base, extra)` pair
/// when the extra field is present, else the CLAMPED seconds-only base.
/// # C: O(1)
pub(crate) fn set_xtime(raw: &mut [u8], inode_size: usize, base_off: usize, extra_off: usize,
                        ts: Timespec64)
{
    if fits_in_inode(raw, inode_size, extra_off + TIME_FIELD_LEN) {
        wr32(raw, base_off, encode_base(ts));
        wr32(raw, extra_off, encode_extra_time(ts));
    } else {
        wr32(raw, base_off, encode_base_clamped(ts));
    }
}

/// `EXT4_EINODE_SET_XTIME(i_crtime, ...)` — no-op when the inode has no room
/// for a birth time. # C: O(1)
pub(crate) fn set_crtime(raw: &mut [u8], inode_size: usize, ts: Timespec64) {
    if !fits_in_inode(raw, inode_size, I_CRTIME + TIME_FIELD_LEN) { return; }
    set_xtime(raw, inode_size, I_CRTIME, I_CRTIME_EXTRA, ts);
}

/// The four timestamps an ext4 inode carries into the VFS inode
/// (`ext4_iget` → `inode_set_{a,m,c}time_to_ts` + `ei->i_crtime`). `btime` is
/// `Option` because "this inode has no creation time" is a distinct state from
/// "created at the epoch" — see [`get_crtime`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeTimes {
    pub atime: Timespec64,
    pub mtime: Timespec64,
    pub ctime: Timespec64,
    pub btime: Option<Timespec64>,
}

/// The superblock time window ext4 advertises for `inode_size`:
/// `(s_time_gran, s_time_min,
/// s_time_max)`. `i_atime_extra` is the LAST of the three `[acm]time` extras
/// in the inode, so room for it implies room for all three — Linux tests
/// exactly that field. Without it the fs stores whole seconds only, capped at
/// 2038. # C: O(1)
pub fn time_range_for_inode_size(inode_size: usize) -> (u32, i64, i64) {
    if inode_size >= I_ATIME_EXTRA + TIME_FIELD_LEN {
        (1, EXT4_TIMESTAMP_MIN, EXT4_EXTRA_TIMESTAMP_MAX)
    } else {
        (NSEC_PER_SEC, EXT4_TIMESTAMP_MIN, EXT4_NON_EXTRA_TIMESTAMP_MAX)
    }
}
