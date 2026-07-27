//! Bounded user-buffer access for the SysV ctl/op paths.
//!
//! On the kernel target every access is gated by a VMA walk with the required
//! protection, so a bad pointer is `EFAULT` instead of a kernel fault. Under
//! `cargo test` there is no address space to validate against and the "user"
//! pointer is a host buffer supplied by the test, so only the NULL check
//! applies — the same arrangement `sysv_shm::shmctl` already uses.

use syscall::errno::Errno;

#[cfg(target_os = "oxide-kernel")]
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

/// Reject a user range that is NULL, wraps, or is not mapped with the access
/// the caller needs. # C: O(len / PAGE_SIZE)
pub fn validate(ptr: u64, len: usize, write: bool) -> Result<(), Errno> {
    let _ = write;
    if ptr == 0 { return Err(Errno::Efault); }
    let end = ptr.checked_add(len as u64).ok_or(Errno::Efault)?;
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::UserVirtAddr;
        use vmm::VmaProt;
        if end > hal::USER_VA_END { return Err(Errno::Efault); }
        if len == 0 { return Ok(()); }
        let cur = sched::current().ok_or(Errno::Efault)?;
        // SAFETY: the current task's mm slot has a single mutator per `13§5` and cannot be replaced while this task is executing its own syscall, so cloning the reference here observes a live address space.
        let mm = unsafe { cur.mm_ref() }.ok_or(Errno::Efault)?.clone();
        let want = if write { VmaProt::WRITE } else { VmaProt::READ };
        let mut va = ptr & PAGE_MASK;
        let last = (end - 1) & PAGE_MASK;
        while va <= last {
            let uva = UserVirtAddr::new(va).ok_or(Errno::Efault)?;
            match mm.find_vma(uva) {
                Some(v) if v.prot.contains(want) => {}
                _ => return Err(Errno::Efault),
            }
            va = va.checked_add(hal::PAGE_SIZE_BYTES).ok_or(Errno::Efault)?;
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = end;
    Ok(())
}

/// # C: O(len)
pub fn read_bytes(ptr: u64, dst: &mut [u8]) -> Result<(), Errno> {
    validate(ptr, dst.len(), false)?;
    // SAFETY: `validate` proved the whole range readable in the caller's address space (or, hosted, that the test buffer is non-NULL); byte-granular unaligned loads impose no alignment requirement on the user pointer.
    unsafe { for (i, b) in dst.iter_mut().enumerate() { *b = core::ptr::read_unaligned((ptr + i as u64) as *const u8); } }
    Ok(())
}

/// # C: O(len)
pub fn write_bytes(ptr: u64, src: &[u8]) -> Result<(), Errno> {
    validate(ptr, src.len(), true)?;
    // SAFETY: `validate` proved the whole range writable in the caller's address space (or, hosted, that the test buffer is non-NULL); byte-granular unaligned stores impose no alignment requirement on the user pointer.
    unsafe { for (i, b) in src.iter().enumerate() { core::ptr::write_unaligned((ptr + i as u64) as *mut u8, *b); } }
    Ok(())
}

/// # C: O(1)
pub fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
