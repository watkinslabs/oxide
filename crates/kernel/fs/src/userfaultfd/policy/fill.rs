// The destination ladder shared by every op that writes into the target
// address space (COPY, ZEROPAGE, CONTINUE, POISON), their mode words, and the
// short-fill return protocol they all report through.

use syscall::errno::Errno;

use crate::userfaultfd::uapi::*;

/// Which fill an ioctl is performing. The destination ladder is shared; only
/// the two mode-specific arms below differ, so a new fill cannot acquire its
/// own copy of the authorisation checks.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FillKind { Copy, Zeropage, Continue, Poison }

/// The destination VMA facts the ladder needs, lifted out so it is testable
/// without an address space.
#[derive(Copy, Clone, Debug, Default)]
pub struct DstVma {
    /// The VMA's end.
    pub end: u64,
    /// The VMA carries a userfaultfd context.
    pub uffd_registered: bool,
    /// The VMA is registered for write-protect mode.
    pub uffd_wp: bool,
    /// Private anonymous memory.
    pub anonymous: bool,
    /// Memory-backed shared storage.
    pub shmem: bool,
}

/// THE security ladder for every fill:
///
/// ```text
/// no VMA covers dst              → ENOENT
/// the range leaves the VMA       → ENOENT
/// the VMA is not uffd-registered → ENOENT
/// write-protect fill without a WP registration → EINVAL
/// CONTINUE on a VMA with no backing to continue from → EINVAL
/// a backing this kernel cannot fill → EINVAL
/// ```
///
/// Without the first three, a fill installed a fresh writable frame at ANY
/// page-aligned user address — an arbitrary-address kernel-assisted memory
/// write reachable from any process holding a uffd fd. The check is for a
/// context being present, not for a specific one, because registration already
/// refuses a VMA owned by a different uffd with EBUSY.
///
/// `want_wp`'s check runs AFTER the lookup, so a write-protect fill at an
/// unmapped address reports ENOENT, not EINVAL. That order is observable.
/// # C: O(1)
pub fn check_dst_vma(dst_end: u64, vma: Option<DstVma>, want_wp: bool, kind: FillKind)
    -> Result<(), Errno> {
    let Some(v) = vma else { return Err(Errno::Enoent) };
    if dst_end > v.end { return Err(Errno::Enoent); }
    if !v.uffd_registered { return Err(Errno::Enoent); }
    if want_wp && !v.uffd_wp { return Err(Errno::Einval); }
    if kind == FillKind::Continue && !v.shmem { return Err(Errno::Einval); }
    if !(v.anonymous || v.shmem) { return Err(Errno::Einval); }
    Ok(())
}

/// COPY accepts DONTWAKE and WP; anything else is EINVAL. The "the VMA must be
/// WP-registered" half of MODE_WP is [`check_dst_vma`]'s `want_wp`, because it
/// runs after the destination lookup.
/// # C: O(1)
pub fn check_copy_mode(mode: u64) -> Result<(), Errno> {
    if mode & !(UFFDIO_COPY_MODE_DONTWAKE | UFFDIO_COPY_MODE_WP) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// ZEROPAGE accepts DONTWAKE only.
/// # C: O(1)
pub fn check_zeropage_mode(mode: u64) -> Result<(), Errno> {
    if mode & !UFFDIO_ZEROPAGE_MODE_DONTWAKE != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// CONTINUE accepts DONTWAKE and WP.
/// # C: O(1)
pub fn check_continue_mode(mode: u64) -> Result<(), Errno> {
    if mode & !(UFFDIO_CONTINUE_MODE_DONTWAKE | UFFDIO_CONTINUE_MODE_WP) != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// POISON accepts DONTWAKE only.
/// # C: O(1)
pub fn check_poison_mode(mode: u64) -> Result<(), Errno> {
    if mode & !UFFDIO_POISON_MODE_DONTWAKE != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// The fill return protocol: the trailing reply field carries the byte count
/// (or the negative errno when nothing was installed), and the ioctl itself
/// returns 0 when the whole range was filled and EAGAIN when it was short.
/// Note EAGAIN — a short fill is a retryable partial result, not ENOMEM.
/// # C: O(1)
pub fn fill_retval(installed: u64, requested: u64, err: Option<Errno>) -> (i64, i64) {
    if installed == 0 {
        if let Some(e) = err { let rv = -(e.as_i32() as i64); return (rv, rv); }
    }
    let rv = if installed == requested { 0 } else { -(Errno::Eagain.as_i32() as i64) };
    (rv, installed as i64)
}

/// Whether a fill should wake blocked faulters: everything except DONTWAKE,
/// and only when at least one page landed. DONTWAKE is bit 0 for every fill
/// ioctl — but NOT for write-protect, which is why that one has its own mode
/// decoder.
/// # C: O(1)
pub fn should_wake(mode: u64, installed: u64) -> bool {
    installed != 0 && mode & UFFDIO_COPY_MODE_DONTWAKE == 0
}
