// UFFDIO_WRITEPROTECT: the mode word and the per-VMA ladder of the walk that
// arms and disarms the per-page write-protect marker.

use syscall::errno::Errno;

use crate::userfaultfd::uapi::*;

/// The decoded `uffdio_writeprotect.mode` word.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WpMode {
    /// Arm the protection (clear = resolve it).
    pub protect: bool,
    /// Suppress the wake that a resolve otherwise performs.
    pub dontwake: bool,
}

/// The mode ladder. The two bits are assigned the OPPOSITE way round from
/// every fill ioctl (WP is bit 0 here, DONTWAKE bit 1), and arming the
/// protection while suppressing the wake is refused outright: there are no
/// faulters to wake when protection is being ARMED, so the combination can
/// only mean the caller misread the interface.
/// # C: O(1)
pub fn check_wp_mode(mode: u64) -> Result<WpMode, Errno> {
    if mode & !(UFFDIO_WRITEPROTECT_MODE_WP | UFFDIO_WRITEPROTECT_MODE_DONTWAKE) != 0 {
        return Err(Errno::Einval);
    }
    let m = WpMode {
        protect:  mode & UFFDIO_WRITEPROTECT_MODE_WP != 0,
        dontwake: mode & UFFDIO_WRITEPROTECT_MODE_DONTWAKE != 0,
    };
    if m.protect && m.dontwake { return Err(Errno::Einval); }
    Ok(m)
}

/// The facts the per-VMA ladder needs about one VMA overlapping the range.
#[derive(Copy, Clone, Debug, Default)]
pub struct WpVma {
    pub start: u64,
    pub end: u64,
    /// The VMA is registered for write-protect mode.
    pub uffd_wp: bool,
    /// Private anonymous memory.
    pub anonymous: bool,
    /// The monitor asked the barrier to cover addresses with no page.
    pub wp_unpopulated: bool,
}

/// Whether the barrier over this VMA is carried by an entry of its OWN at an
/// address with no resident page, rather than only by the permissions of the
/// pages that already exist.
///
/// Anything but private anonymous memory needs one unconditionally: the page a
/// write would land on can be sitting in the backing while the page table has
/// nothing, so "no entry" is not "no page", and leaving the address alone lets
/// that write through unseen.
///
/// Private anonymous memory has nothing behind it — an address with no entry
/// has no contents anywhere — so there the coverage is the monitor's to ask
/// for, and it costs page tables for addresses that may never be touched.
/// # C: O(1)
pub fn wp_use_markers(v: &WpVma) -> bool {
    if !v.uffd_wp { return false; }
    !v.anonymous || v.wp_unpopulated
}

/// Every VMA overlapping the range must be WP-registered, and the range must
/// be covered by at least one VMA. Both failures are ENOENT: a write-protect
/// of a range the monitor never registered for WP is not a bad argument, it is
/// a request about memory this context does not own.
///
/// A hole is ENOENT too, and for the same reason the empty case is: the walk
/// starts from "nothing was protected" and only a covered, registered VMA
/// moves it off that answer.
/// # C: O(N_vmas)
pub fn check_wp_vma(start: u64, end: u64, vmas: &[WpVma]) -> Result<(), Errno> {
    let mut cursor = start;
    for v in vmas {
        if v.start > cursor { return Err(Errno::Enoent); }
        if !v.uffd_wp { return Err(Errno::Enoent); }
        cursor = cursor.max(v.end);
        if cursor >= end { return Ok(()); }
    }
    Err(Errno::Enoent)
}
