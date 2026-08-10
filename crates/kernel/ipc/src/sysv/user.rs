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
    // The VMA scan above proves the range is mapped readable at this instant;
    // the copy still goes through the exception table, because the mapping can
    // be torn down between the scan and the access. Linux `copy_from_user`.
    uaccess::copy_from_user(dst, ptr)
}

/// # C: O(len)
pub fn write_bytes(ptr: u64, src: &[u8]) -> Result<(), Errno> {
    validate(ptr, src.len(), true)?;
    // Same reason as `read_bytes`: the scan is a permission check, the copy is
    // what recovers from a page that went away. Linux `copy_to_user`.
    uaccess::copy_to_user(ptr, src)
}

/// # C: O(1)
pub fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[cfg(test)]
mod tests {
    use super::*;

    /// The lowest address in the kernel half. On the kernel target the VMA scan
    /// refuses it; hosted, the copy's own range check does — either way the
    /// converted helper answers EFAULT instead of dereferencing it.
    const KERNEL_SIDE: u64 = hal::USER_VA_END;

    #[test]
    fn a_buffer_round_trips_through_the_copy() {
        let mut dst = [0u8; 4];
        write_bytes(dst.as_mut_ptr() as u64, &[9, 8, 7, 6]).expect("out");
        assert_eq!(dst, [9, 8, 7, 6]);
        let mut back = [0u8; 4];
        read_bytes(dst.as_ptr() as u64, &mut back).expect("in");
        assert_eq!(back, [9, 8, 7, 6]);
    }

    #[test]
    fn an_address_the_copy_cannot_reach_is_efault() {
        let mut one = [0u8; 1];
        assert_eq!(read_bytes(KERNEL_SIDE, &mut one), Err(Errno::Efault));
        assert_eq!(write_bytes(KERNEL_SIDE, &[0u8]), Err(Errno::Efault));
        assert_eq!(read_bytes(0, &mut one), Err(Errno::Efault));
        assert_eq!(write_bytes(0, &[0u8]), Err(Errno::Efault));
    }

    /// A failed copy-in leaves the destination zeroed rather than holding
    /// whatever the kernel buffer carried before.
    #[test]
    fn a_failed_copy_in_zeroes_the_destination() {
        let mut dst = [0xccu8; 4];
        assert_eq!(read_bytes(KERNEL_SIDE, &mut dst), Err(Errno::Efault));
        assert_eq!(dst, [0u8; 4]);
    }
}
