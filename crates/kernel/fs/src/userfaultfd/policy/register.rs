// UFFDIO_REGISTER: which modes exist, which VMAs each mode is legal on, and
// the ioctls bitmap the registration promises.

use syscall::errno::Errno;
use vmm::VmaFlags;

use crate::userfaultfd::uapi::*;

/// The per-VMA flag set a `uffdio_register.mode` word arms. The mode word and
/// the flags are converted in exactly one place so a mode can never be
/// recorded on a VMA without the fault path recognising it.
/// # C: O(1)
pub fn modes_of(mode: u64) -> VmaFlags {
    let mut f = VmaFlags::empty();
    if mode & UFFDIO_REGISTER_MODE_MISSING != 0 { f |= VmaFlags::UFFD_MISSING; }
    if mode & UFFDIO_REGISTER_MODE_WP      != 0 { f |= VmaFlags::UFFD_WP; }
    if mode & UFFDIO_REGISTER_MODE_MINOR   != 0 { f |= VmaFlags::UFFD_MINOR; }
    f
}

/// The mode ladder, which runs BEFORE the range is validated: an empty mode
/// word is EINVAL, and so is any bit outside the defined set.
/// # C: O(1)
pub fn check_register_mode(mode: u64) -> Result<VmaFlags, Errno> {
    if mode == 0 { return Err(Errno::Einval); }
    if mode & !UFFD_API_REGISTER_MODES != 0 { return Err(Errno::Einval); }
    Ok(modes_of(mode))
}

/// The facts [`check_register_vma`] needs about one VMA overlapping the range.
#[derive(Copy, Clone, Debug, Default)]
pub struct RegVma {
    /// Private anonymous memory.
    pub anonymous: bool,
    /// Memory-backed shared storage whose pages ARE the object.
    pub shmem: bool,
    /// A file object stands behind the mapping — as opposed to a device range
    /// or a kernel-owned frame, whose leaves name memory this kernel does not
    /// own the lifetime of.
    pub file_backed: bool,
    /// The mapping may become writable.
    pub may_write: bool,
    /// The VMA already belongs to a DIFFERENT userfaultfd.
    pub owned_by_other_uffd: bool,
}

/// Which VMAs a given mode set may be armed on. `wp_async` is the monitor's
/// negotiated "resolve write faults instead of reporting them".
///
/// - A mode that REPORTS a fault requires a backing this kernel can intercept
///   for: anonymous memory, or memory-backed shared storage. A device range or
///   a kernel-owned frame has no such interception point.
/// - MINOR requires shared storage. A minor fault means "the backing already
///   holds this page, only the page table is missing it", which cannot arise
///   for anonymous memory: there is no backing to hold it.
/// - WP no longer requires anonymous memory: the protection now has a
///   page-table entry of its own for an address with no resident page, so it no
///   longer depends on the page being there to carry it.
/// - WP ALONE, for a monitor that resolves its own write faults, needs no
///   interception point at all — nothing is reported and nothing blocks — so it
///   is admitted over anything backed by a page this kernel accounts, an
///   ordinary file mapping included. A device range still is not: the write it
///   would catch lands in memory whose lifetime this kernel does not own.
/// # C: O(1)
pub fn vma_can_userfault(v: &RegVma, modes: VmaFlags, wp_async: bool) -> bool {
    if wp_async && modes == VmaFlags::UFFD_WP {
        return v.anonymous || v.shmem || v.file_backed;
    }
    if !(v.anonymous || v.shmem) { return false; }
    if modes.contains(VmaFlags::UFFD_MINOR) && !v.shmem { return false; }
    true
}

/// The per-VMA registration scan, in order:
///
/// ```text
/// EINVAL: the mode set is not legal on this VMA
/// EPERM:  the mapping can never be written
/// EBUSY:  the VMA already belongs to another userfaultfd
/// ```
///
/// The EPERM arm is a real permission gate, not bookkeeping: a fill installs
/// pages even without write permission on the mapping, so registration is
/// where write permission on the backing must be proven. The EBUSY arm is what
/// makes "the VMA carries a uffd context" a usable authorisation fact for the
/// fill ladder — two fds can never own one VMA.
/// # C: O(1)
pub fn check_register_vma(v: &RegVma, modes: VmaFlags, wp_async: bool) -> Result<(), Errno> {
    if !vma_can_userfault(v, modes, wp_async) { return Err(Errno::Einval); }
    if !v.may_write { return Err(Errno::Eperm); }
    if v.owned_by_other_uffd { return Err(Errno::Ebusy); }
    Ok(())
}

/// The `uffdio_register.ioctls` reply for an accepted `mode`: every range op,
/// minus the two whose mode was not requested. The reply is a PROMISE that the
/// listed ops will succeed on this range, so a mode-specific op must not
/// appear without its mode.
/// # C: O(1)
pub fn register_ioctls(mode: u64) -> u64 {
    let mut out = UFFD_API_RANGE_IOCTLS;
    if mode & UFFDIO_REGISTER_MODE_WP == 0 { out &= !(1u64 << slot::WRITEPROTECT); }
    if mode & UFFDIO_REGISTER_MODE_MINOR == 0 { out &= !(1u64 << slot::CONTINUE); }
    out
}
