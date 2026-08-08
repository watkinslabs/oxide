// UFFDIO_WRITEPROTECT: arm or resolve the write barrier over a range.

use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::userfaultfd::policy::{self, WpVma};
use crate::userfaultfd::{uapi::*, work, UfData};

use super::structs::{err, read_req, UffdioWriteprotect};

/// Unlike the fill ioctls this one has NO reply field: it either applied to
/// the whole range or it failed. A partially-applied barrier would be a
/// barrier a monitor could not reason about.
/// # C: O(N_vmas) + O(len/PAGE)
pub fn ioc_writeprotect(ufd: &UfData, arg: u64) -> i64 {
    // Having no reply field puts the in-flight-change refusal FIRST, ahead of
    // the request object itself: nothing has to be written back for it, so
    // EAGAIN wins over the EFAULT an unreadable object would produce. Every
    // other range op has to write its reply word, which puts EFAULT first.
    if let Err(e) = policy::check_mmap_changing(ufd.changes_in_flight()) { return err(e); }
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_WRITEPROTECT_SIZE, 1) { return rv; }
    // SAFETY: arg validated for the full uffdio_writeprotect object.
    let w: UffdioWriteprotect = unsafe { read_req(arg) };
    if let Err(e) = policy::validate_range(w.range.start, w.range.len) { return err(e); }
    let mode = match policy::check_wp_mode(w.mode) { Ok(m) => m, Err(e) => return err(e) };
    let Some(mm) = ufd.mm() else { return err(Errno::Esrch) };
    let start = w.range.start;
    let end   = start + w.range.len;
    let wp_unpopulated =
        policy::wp_unpopulated(ufd.features.load(core::sync::atomic::Ordering::Acquire));
    let vmas: alloc::vec::Vec<WpVma> = mm.uffd_vmas_in(start, end).iter()
        .map(|v| WpVma {
            start: v.start, end: v.end,
            uffd_wp: v.ctx.is_some() && v.modes.contains(vmm::VmaFlags::UFFD_WP),
            anonymous: v.anonymous,
            wp_unpopulated,
        })
        .collect();
    if let Err(e) = policy::check_wp_vma(start, end, &vmas) { return err(e); }
    // Walked per VMA, because whether an address with no page carries the
    // barrier is a per-VMA answer: a range spanning anonymous memory and a file
    // mapping gets markers over the second and not the first.
    for v in &vmas {
        let (s, e) = (v.start.max(start), v.end.min(end));
        if s < e { work::wp_range(&mm, s, e, mode.protect, policy::wp_use_markers(v)); }
    }
    // Resolving the barrier releases the threads it stopped; arming it has
    // nobody to release, and asking for both at once was already refused.
    if !mode.protect && !mode.dontwake { ufd.wake_faulters(); }
    0
}
