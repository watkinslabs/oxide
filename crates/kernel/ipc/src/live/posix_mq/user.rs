// User-memory access and current-task snapshots shared by the mqueue slots.
// Kept out of the slot bodies so each of them reads as the Linux function it
// mirrors (`docs/53`).

use core::sync::atomic::Ordering;

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

/// Negative-errno syscall return. # C: O(1)
pub fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `current_cred()` for the VFS DAC checks; the snapshot layout is
/// owned by `sched::Creds::to_vfs_cred`. # C: O(1)
pub fn current_cred() -> vfs::Cred {
    let Some(c) = sched::current() else { return vfs::Cred::root(); };
    let effective = c.creds.cap_effective.load(Ordering::Acquire);
    c.creds.to_vfs_cred(c.creds.fsuid.load(Ordering::Acquire),
                        c.creds.fsgid.load(Ordering::Acquire), effective)
}

/// The caller's IPC namespace — Linux `current->nsproxy->ipc_ns`, which is
/// what makes a queue name private to that namespace. # C: O(1)
pub fn ipc_ns() -> Result<NamespaceId, Errno> {
    crate::ipc_namespace::current().map(|o| o.key()).map_err(|_| Errno::Einval)
}

/// Linux `task_tgid(current)` — mq notifications are per-PROCESS. # C: O(1)
pub fn current_tgid() -> Option<u32> {
    sched::live::current().map(|c| c.tgid.load(Ordering::Acquire))
}

/// # C: O(1)
pub fn read_user_i64(uptr: u64) -> Result<i64, Errno> {
    if uptr >= hal::USER_VA_END
        || uptr.checked_add(8).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+8) validated below USER_VA_END; an 8-byte read through the caller's active address space at CPL=0.
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const i64) })
}

/// # C: O(1)
pub fn write_user_i64(uptr: u64, v: i64) -> Result<(), Errno> {
    if uptr >= hal::USER_VA_END
        || uptr.checked_add(8).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+8) validated below USER_VA_END; an 8-byte write through the caller's active address space at CPL=0.
    unsafe { core::ptr::write_unaligned(uptr as *mut i64, v) };
    Ok(())
}

/// # C: O(1)
pub fn read_user_i32(uptr: u64) -> Result<i32, Errno> {
    if uptr >= hal::USER_VA_END
        || uptr.checked_add(4).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+4) validated below USER_VA_END; a 4-byte read through the caller's active address space at CPL=0.
    Ok(unsafe { core::ptr::read_unaligned(uptr as *const i32) })
}

/// # C: O(len)
pub fn read_user_bytes(uptr: u64, out: &mut [u8]) -> Result<(), Errno> {
    if out.is_empty() { return Ok(()); }
    if uptr == 0 || uptr >= hal::USER_VA_END
        || uptr.checked_add(out.len() as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+out.len()) validated below USER_VA_END; a byte copy out of the caller's active address space at CPL=0.
    unsafe { core::ptr::copy_nonoverlapping(uptr as *const u8, out.as_mut_ptr(), out.len()) };
    Ok(())
}

/// # C: O(len)
pub fn write_user_bytes(uptr: u64, src: &[u8]) -> Result<(), Errno> {
    if src.is_empty() { return Ok(()); }
    if uptr == 0 || uptr >= hal::USER_VA_END
        || uptr.checked_add(src.len() as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+src.len()) validated below USER_VA_END; a byte copy into the caller's active address space at CPL=0.
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, src.len()) };
    Ok(())
}

/// # C: O(1)
pub fn write_user_u32(uptr: u64, v: u32) -> Result<(), Errno> {
    if uptr >= hal::USER_VA_END
        || uptr.checked_add(4).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    // SAFETY: [uptr, uptr+4) validated below USER_VA_END; a 4-byte write through the caller's active address space at CPL=0.
    unsafe { core::ptr::write_unaligned(uptr as *mut u32, v) };
    Ok(())
}
