use core::mem::MaybeUninit;
use syscall::errno::Errno;

use crate::access_ok;

const OK: u32 = 0;
const U32_BYTES: usize = core::mem::size_of::<u32>();
const U64_BYTES: usize = core::mem::size_of::<u64>();

/// Read one user u32 through the typed exception-table load. # C: O(1)
pub fn get_user_u32(addr: u64) -> Result<u32, Errno> {
    if !access_ok(addr, U32_BYTES) { return Err(Errno::Efault); }
    let mut out = MaybeUninit::<u32>::uninit();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range is checked; the HAL load either initializes `out` or reports a fixup fault.
    let status = unsafe { hal_x86_64::raw_get_user_u32(addr as *const u32, out.as_mut_ptr()) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: range is checked; the HAL load either initializes `out` or reports a fixup fault.
    let status = unsafe { hal_aarch64::raw_get_user_u32(addr as *const u32, out.as_mut_ptr()) };
    if status != OK { return Err(Errno::Efault); }
    // SAFETY: both HAL implementations initialize `out` on the success status.
    Ok(unsafe { out.assume_init() })
}

/// Read one user u64 through the typed exception-table load. # C: O(1)
pub fn get_user_u64(addr: u64) -> Result<u64, Errno> {
    if !access_ok(addr, U64_BYTES) { return Err(Errno::Efault); }
    let mut out = MaybeUninit::<u64>::uninit();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range is checked; the HAL load either initializes `out` or reports a fixup fault.
    let status = unsafe { hal_x86_64::raw_get_user_u64(addr as *const u64, out.as_mut_ptr()) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: range is checked; the HAL load either initializes `out` or reports a fixup fault.
    let status = unsafe { hal_aarch64::raw_get_user_u64(addr as *const u64, out.as_mut_ptr()) };
    if status != OK { return Err(Errno::Efault); }
    // SAFETY: both HAL implementations initialize `out` on the success status.
    Ok(unsafe { out.assume_init() })
}

/// Write one user u32 through the typed exception-table store. # C: O(1)
pub fn put_user_u32(addr: u64, value: u32) -> Result<(), Errno> {
    if !access_ok(addr, U32_BYTES) { return Err(Errno::Efault); }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range is checked; the HAL store recovers a user fault through its exception table.
    let status = unsafe { hal_x86_64::raw_put_user_u32(addr as *mut u32, value) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: range is checked; the HAL store recovers a user fault through its exception table.
    let status = unsafe { hal_aarch64::raw_put_user_u32(addr as *mut u32, value) };
    if status == OK { Ok(()) } else { Err(Errno::Efault) }
}

/// Write one user u64 through the typed exception-table store. # C: O(1)
pub fn put_user_u64(addr: u64, value: u64) -> Result<(), Errno> {
    if !access_ok(addr, U64_BYTES) { return Err(Errno::Efault); }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range is checked; the HAL store recovers a user fault through its exception table.
    let status = unsafe { hal_x86_64::raw_put_user_u64(addr as *mut u64, value) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: range is checked; the HAL store recovers a user fault through its exception table.
    let status = unsafe { hal_aarch64::raw_put_user_u64(addr as *mut u64, value) };
    if status == OK { Ok(()) } else { Err(Errno::Efault) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_loads_and_stores_touch_one_scalar_without_a_bounce_buffer() {
        let mut word = 0u32;
        let addr = (&mut word as *mut u32) as u64;
        assert_eq!(get_user_u32(addr), Ok(0));
        put_user_u32(addr, 0xdead_beef).unwrap();
        assert_eq!(get_user_u32(addr), Ok(0xdead_beef));
        let mut wide = 0u64;
        let wide_addr = (&mut wide as *mut u64) as u64;
        put_user_u64(wide_addr, 0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(get_user_u64(wide_addr), Ok(0x0123_4567_89ab_cdef));
    }

    #[test]
    fn typed_accesses_reject_a_range_before_the_arch_load_or_store() {
        assert_eq!(get_user_u32(0), Err(Errno::Efault));
        assert_eq!(put_user_u32(hal::USER_VA_END, 1), Err(Errno::Efault));
        assert_eq!(get_user_u64(hal::USER_VA_END - 7), Err(Errno::Efault));
        assert_eq!(put_user_u64(hal::USER_VA_END - 7, 1), Err(Errno::Efault));
    }
}
