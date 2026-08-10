// ABI offsets and payload-size bounds the ioctl stage's caller copies use.

use syscall::errno::Errno;

use crate::ioctl_uapi::{DEDUPE_INFO_BYTES, DEDUPE_RANGE_BYTES, PAGE_BYTES};

const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);
const ENOMEM: i64 = -(Errno::Enomem.as_i32() as i64);

/// TIOCLINUX subcode byte: `*(char *)arg`.
pub(crate) const TIOCL_SUBCODE: u64 = 0;

/// TIOCLINUX byte-addressed parameter block: `(void *)arg + 1`. The selection
/// rectangle, the VESA blank interval and the kmsg-redirect target all live
/// here, so every one of them is UNALIGNED by one byte.
pub(crate) const TIOCL_PARAM: u64 = 1;

/// TIOCLINUX word-addressed parameter block: `(u32 *)arg + 1`. The word-select
/// LUT and the scroll-lines delta live here, four bytes in — NOT at
/// [`TIOCL_PARAM`].
pub(crate) const TIOCL_PARAM32: u64 = 4;

/// `struct fiemap_extent`.
pub(crate) const FIEMAP_EXTENT_BYTES: u64 = 56;

/// KDFONTOP glyph-buffer stride: 32 bytes per glyph.
pub(crate) const FONT_GLYPH_STRIDE: usize = 32;

/// KDFONTOP glyph ceiling.
pub(crate) const FONT_MAX_GLYPHS: u32 = 512;

/// `struct unipair` — `{ u16 unicode; u16 fontpos; }`.
pub(crate) const UNIMAP_PAIR_BYTES: u64 = 4;

/// PIO_UNIMAP entry-count ceiling.
pub(crate) const UNIMAP_MAX_ENTRIES: usize = 8192;

/// Single-request dedupe ceiling (1 GiB).
pub(crate) const DEDUPE_MAX_LEN: u64 = 1 << 30;

/// Byte offset of field `i` (`xs`,`ys`,`xe`,`ye`,`sel_mode`) of the TIOCLINUX
/// selection rectangle. The struct starts at the BYTE-addressed parameter
/// block, so field 0 sits at `arg + 1` and every field is misaligned.
/// # C: O(1)
pub(crate) fn tiocl_sel_field(i: u64) -> u64 { TIOCL_PARAM + i * 2 }

/// Byte span of a caller's `fm_extents[]`, or `EINVAL` when the requested count
/// cannot be expressed in the ABI's `u32` byte count. # C: O(1)
pub(crate) fn fiemap_extent_span(count: u32) -> Result<u64, i64> {
    let max = u32::MAX / FIEMAP_EXTENT_BYTES as u32;
    if count > max { return Err(EINVAL); }
    Ok(count as u64 * FIEMAP_EXTENT_BYTES)
}

/// Total `struct file_dedupe_range` payload for `count` destinations, or
/// `ENOMEM` when it exceeds one page. # C: O(1)
pub(crate) fn dedupe_payload_bytes(count: u16) -> Result<u64, i64> {
    let size = DEDUPE_RANGE_BYTES + count as u64 * DEDUPE_INFO_BYTES;
    if size > PAGE_BYTES { return Err(ENOMEM); }
    Ok(size)
}

/// Glyph-buffer byte span for a KDFONTOP set/get, or `EINVAL` for an empty or
/// over-large character count. # C: O(1)
pub(crate) fn font_glyph_bytes(charcount: u32) -> Result<usize, i64> {
    if charcount == 0 || charcount > FONT_MAX_GLYPHS { return Err(EINVAL); }
    Ok(charcount as usize * FONT_GLYPH_STRIDE)
}

/// Byte span of a `struct unipair[]`, or `EINVAL` past the entry ceiling.
/// # C: O(1)
pub(crate) fn unimap_span(ct: usize) -> Result<u64, i64> {
    if ct > UNIMAP_MAX_ENTRIES { return Err(EINVAL); }
    Ok(ct as u64 * UNIMAP_PAIR_BYTES)
}
