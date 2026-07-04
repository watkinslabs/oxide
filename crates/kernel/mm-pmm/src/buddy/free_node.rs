// ---------------------------------------------------------------------------
// FreeNode header r/w — page-content layout per `10§5.2`.
// ---------------------------------------------------------------------------
//
// Layout: 32 bytes at offset 0 of the freed page's first page.
//   poison: u64    @ 0
//   order:  u8     @ 8
//   _pad:  [u8;7]  @ 9..16
//   next:  u64     @ 16
//   prev:  u64     @ 24
//
// On secondary pages of an order-o block we only stamp the first 16
// bytes (poison + order). Alloc verifies poison on every page.

pub(super) const OFF_POISON: usize = 0;
pub(super) const OFF_ORDER: usize = 8;
pub(super) const OFF_NEXT: usize = 16;
pub(super) const OFF_PREV: usize = 24;

#[inline]
pub(super) unsafe fn write_u64(base: *mut u8, off: usize, v: u64) {
    // SAFETY: `base + off` is in the 32-byte FreeNode header at the start
    // of a PMM-owned page; alignment-agnostic via write_unaligned.
    unsafe { core::ptr::write_unaligned(base.add(off) as *mut u64, v) }
}

#[inline]
pub(super) unsafe fn read_u64(base: *const u8, off: usize) -> u64 {
    // SAFETY: `base + off` is in the 32-byte FreeNode header at the start
    // of a PMM-owned page; alignment-agnostic read.
    unsafe { core::ptr::read_unaligned(base.add(off) as *const u64) }
}

#[inline]
pub(super) unsafe fn write_u8(base: *mut u8, off: usize, v: u8) {
    // SAFETY: `base + off` is inside a PMM-owned 4 KiB page at call site.
    unsafe { core::ptr::write(base.add(off), v) }
}

