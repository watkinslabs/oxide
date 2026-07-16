// mount_common — shared helpers for the mount-family syscalls
// (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn enoent() -> i64 { -(Errno::Enoent.as_i32() as i64) }

/// `debug-mount`: log a mount-family syscall outcome (op label + path + rv) so
/// 226/NAMESPACE sandbox failures show the exact failing op + errno. Mount ops
/// are rare → low-volume even when enabled. No-op without the feature.
/// # C: O(len) emit when enabled
pub(crate) fn mnt_log(_op: &str, _path: &str, _rv: i64) {
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[mnt] ");
        klog::write_raw(_op.as_bytes());
        klog::write_raw(b" ns=");
        klog::write_dec_u64(sched::live::current_mount_ns());
        klog::write_raw(b" path=");
        klog::write_raw(_path.as_bytes());
        klog::write_raw(b" rv=");
        if _rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-_rv) as u64); }
        else { klog::write_dec_u64(_rv as u64); }
        klog::write_raw(b"\n");
    }
}

/// As `mnt_log`, plus a hex value (flags) appended after `path` and before rv.
/// # C: O(len) emit when enabled
pub(crate) fn mnt_log_hex(_op: &str, _path: &str, _flags: u64, _rv: i64) {
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[mnt] ");
        klog::write_raw(_op.as_bytes());
        klog::write_raw(b" ns=");
        klog::write_dec_u64(sched::live::current_mount_ns());
        klog::write_raw(b" path=");
        klog::write_raw(_path.as_bytes());
        klog::write_hex_u64(_flags);
        klog::write_raw(b" rv=");
        if _rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-_rv) as u64); }
        else { klog::write_dec_u64(_rv as u64); }
        klog::write_raw(b"\n");
    }
}

/// Read a NUL-terminated user-space C string at `p` (bounded by `max`)
/// into an owned `String`. Faults map to EFAULT, invalid UTF-8 to EINVAL.
/// # C: O(max)
pub(crate) fn read_user_cstr_owned(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= hal::USER_VA_END { return Err(efault()); }
    let cur = sched::live::current().ok_or_else(efault)?;
    // SAFETY: syscall context; the running task owns this mm slot.
    let mm = unsafe { cur.mm_ref() }.ok_or_else(efault)?;
    let mut out = Vec::with_capacity(max.min(256));
    let mut checked_page = u64::MAX;
    for i in 0..max {
        let addr = p.checked_add(i as u64).ok_or_else(efault)?;
        if addr >= hal::USER_VA_END { return Err(efault()); }
        let page = addr & !PAGE_MASK;
        if page != checked_page {
            let uva = hal::UserVirtAddr::new(page).ok_or_else(efault)?;
            match mm.find_vma(uva) {
                Some(vma) if vma.prot.contains(vmm::VmaProt::READ) => {}
                _ => return Err(efault()),
            }
            checked_page = page;
        }
        // SAFETY: addr is below USER_VA_END and its containing VMA permits read.
        // Not-present pages are demand-faulted by the active user address space.
        let b = unsafe { core::ptr::read_volatile(addr as *const u8) };
        if b == 0 { break; }
        out.push(b);
    }
    String::from_utf8(out).map_err(|_| einval())
}

/// Read a user pathname. Linux pathnames are byte strings, not UTF-8 text; the
/// VFS path codec preserves invalid UTF-8 bytes reversibly. # C: O(PATH_MAX)
pub(crate) fn read_user_path_allow_empty(p: u64) -> Result<String, i64> {
    let b = read_user_cstr_bytes(p, vfs::path::PATH_MAX)?;
    let path = vfs::path_from_bytes(&b);
    if !path.is_empty() {
        vfs::path::check_path_len(&path).map_err(crate::namei_common::errno_from_vfs)?;
    }
    Ok(path)
}

/// Read a required pathname. Empty string is a valid C string but not a valid
/// mount-family path operand. # C: O(PATH_MAX)
pub(crate) fn read_user_path_required(p: u64) -> Result<String, i64> {
    let path = read_user_path_allow_empty(p)?;
    if path.is_empty() { Err(enoent()) } else { Ok(path) }
}

/// Read an optional user pathname; NULL is absence, non-NULL bad pointers still
/// return `EFAULT`. # C: O(PATH_MAX)
pub(crate) fn read_optional_user_path(p: u64) -> Result<Option<String>, i64> {
    if p == 0 { Ok(None) } else { read_user_path_allow_empty(p).map(Some) }
}

fn read_user_cstr_bytes(p: u64, max: usize) -> Result<Vec<u8>, i64> {
    if p == 0 || p >= hal::USER_VA_END { return Err(efault()); }
    let cur = sched::live::current().ok_or_else(efault)?;
    // SAFETY: syscall context; the running task owns this mm slot.
    let mm = unsafe { cur.mm_ref() }.ok_or_else(efault)?;
    let mut out = Vec::with_capacity(max.min(256));
    let mut checked_page = u64::MAX;
    for i in 0..max {
        let addr = p.checked_add(i as u64).ok_or_else(efault)?;
        if addr >= hal::USER_VA_END { return Err(efault()); }
        let page = addr & !PAGE_MASK;
        if page != checked_page {
            let uva = hal::UserVirtAddr::new(page).ok_or_else(efault)?;
            match mm.find_vma(uva) {
                Some(vma) if vma.prot.contains(vmm::VmaProt::READ) => {}
                _ => return Err(efault()),
            }
            checked_page = page;
        }
        // SAFETY: addr is below USER_VA_END and its containing VMA permits read.
        // Not-present pages are demand-faulted by the active user address space.
        let b = unsafe { core::ptr::read_volatile(addr as *const u8) };
        if b == 0 { return Ok(out); }
        out.push(b);
    }
    Err(crate::namei_common::errno_from_vfs(vfs::VfsError::Enametoolong))
}
