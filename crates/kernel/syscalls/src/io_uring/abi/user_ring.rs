// `IORING_SETUP_NO_MMAP` / `IORING_SETUP_REGISTERED_FD_ONLY`: a ring whose
// memory the CALLER supplies, and a ring that is never given a descriptor.
//
// Ordinarily the kernel allocates both regions and userspace reaches them
// through `mmap` on the ring descriptor. `NO_MMAP` inverts that: the caller
// allocates the memory — typically a huge page, which is the point, since the
// kernel's own regions are ordinary pages — and hands its address in
// `p->cq_off.user_addr` for the rings region and `p->sq_off.user_addr` for the
// SQEs region. The kernel pins those pages for the ring's whole life and uses
// them in place.
//
// Such a ring is NOT mappable from its descriptor. The pages are already in
// the caller's address space; handing back a second mapping of them would put
// two independent reference schemes on one frame, and the caller does not need
// one — it has the address it supplied.
//
// `REGISTERED_FD_ONLY` follows from that: with nothing left to `mmap`, the
// descriptor's only remaining job is to be passed to `io_uring_enter` and
// `io_uring_register`, and both take a registered-ring index instead. The ring
// is installed straight into the calling task's registered-ring array and the
// index is what `io_uring_setup` returns, so no descriptor number is ever
// spent. It is only meaningful with `NO_MMAP` and is refused without it.
//
// A caller-supplied region is discontiguous in physical memory — it is
// whatever backed the caller's mapping — so every access into it resolves one
// page at a time. That is safe exactly because no ring object straddles a page
// boundary, which `spans_one_page` states and the geometry tests check.

use syscall::errno::Errno;

use super::uapi::{IORING_SETUP_NO_MMAP, IORING_SETUP_REGISTERED_FD_ONLY};

/// Whether this ring's memory comes from the caller. # C: O(1)
pub fn caller_supplied(flags: u32) -> bool { flags & IORING_SETUP_NO_MMAP != 0 }

/// Whether this ring is reachable only as a registered-ring index, never as a
/// descriptor number. # C: O(1)
pub fn registered_only(flags: u32) -> bool {
    flags & IORING_SETUP_REGISTERED_FD_ONLY != 0
}

/// Whether a region built for this ring may be mapped from its descriptor.
/// A caller-supplied region may not. # C: O(1)
pub fn mappable(flags: u32) -> bool { !caller_supplied(flags) }

/// Admit one caller-supplied region address.
///
/// The address must be page-aligned, because the region is pinned and read a
/// page at a time and an offset one would make every object's page resolution
/// wrong. It must be non-null, and the range must not wrap. `bytes` is the
/// region size the geometry produced, already page-aligned.
/// # C: O(1)
pub fn admit_addr(addr: u64, bytes: u64, page: u64) -> Result<(), Errno> {
    if addr == 0 { return Err(Errno::Efault); }
    if addr & (page - 1) != 0 { return Err(Errno::Einval); }
    if bytes == 0 { return Err(Errno::Einval); }
    addr.checked_add(bytes).ok_or(Errno::Efault)?;
    Ok(())
}

/// Whether an object of `len` bytes at region offset `off` lies inside one
/// page.
///
/// The invariant every direct access into a caller-supplied region rests on.
/// It holds for the whole ring layout by construction: the header words sit in
/// the first 64 bytes, the completion array starts at a 64-byte offset and
/// strides at 16 or 32, the submission-index array strides at 4, and the
/// submission array starts at offset zero and strides at 64 or 128. Every one
/// of those strides divides a page and every offset is a multiple of its own
/// stride, so no object can begin in one page and end in the next.
/// # C: O(1)
pub fn spans_one_page(off: u64, len: u64, page: u64) -> bool {
    len != 0 && (off & (page - 1)) + len <= page
}

#[cfg(test)]
#[path = "user_ring/tests.rs"]
mod tests;
