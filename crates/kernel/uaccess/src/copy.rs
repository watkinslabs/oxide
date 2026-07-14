use syscall::errno::Errno;

use crate::access_ok;

/// Raw copy from user, returning the number of bytes not copied. # C: O(len + page faults)
pub unsafe fn raw_copy_from_user(dst: *mut u8, src: u64, len: usize) -> usize {
    if !access_ok(src, len) { return len; }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller owns dst; selected HAL routine recovers user faults through the exception table.
        unsafe { hal_x86_64::raw_copy_from_user(dst, src as *const u8, len) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: caller owns dst; selected HAL routine recovers user faults through the exception table.
        unsafe { hal_aarch64::raw_copy_from_user(dst, src as *const u8, len) }
    }
}

/// Raw copy to user, returning the number of bytes not copied. # C: O(len + page faults)
pub unsafe fn raw_copy_to_user(dst: u64, src: *const u8, len: usize) -> usize {
    if !access_ok(dst, len) { return len; }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller owns src; selected HAL routine recovers user faults through the exception table.
        unsafe { hal_x86_64::raw_copy_to_user(dst as *mut u8, src, len) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: caller owns src; selected HAL routine recovers user faults through the exception table.
        unsafe { hal_aarch64::raw_copy_to_user(dst as *mut u8, src, len) }
    }
}

/// Copy from user, zeroing the uncopied destination tail on fault. # C: O(len + page faults)
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), Errno> {
    // SAFETY: dst is live and writable for its full length.
    let left = unsafe { raw_copy_from_user(dst.as_mut_ptr(), src, dst.len()) };
    if left == 0 { return Ok(()); }
    let copied = dst.len() - left;
    dst[copied..].fill(0);
    Err(Errno::Efault)
}

/// Copy to user, returning EFAULT for any uncopied suffix. # C: O(len + page faults)
pub fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), Errno> {
    // SAFETY: src is live and readable for its full length.
    let left = unsafe { raw_copy_to_user(dst, src.as_ptr(), src.len()) };
    if left == 0 { Ok(()) } else { Err(Errno::Efault) }
}
