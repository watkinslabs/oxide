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
