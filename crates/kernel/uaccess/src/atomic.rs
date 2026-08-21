use core::mem::MaybeUninit;

use syscall::errno::Errno;

use crate::access_ok;

const U32_BYTES: usize = core::mem::size_of::<u32>();
const U32_ALIGN_MASK: u64 = (core::mem::align_of::<u32>() - 1) as u64;
const ATOMIC_OK: u32 = 0;
const ATOMIC_FAULT: u32 = 1;
const ATOMIC_RETRY: u32 = 2;

/// Atomically replace a user word if it equals `old`, returning the word seen.
/// # C: O(page faults)
pub fn cmpxchg_user_u32(uaddr: u64, old: u32, new: u32) -> Result<u32, Errno> {
    if !access_ok(uaddr, U32_BYTES) || uaddr & U32_ALIGN_MASK != 0 { return Err(Errno::Efault); }
    let mut seen = MaybeUninit::<u32>::uninit();
    #[cfg(target_arch = "x86_64")]
    // SAFETY: range and alignment are checked; HAL recovers a fault before the output is observed.
    let status = unsafe { hal_x86_64::raw_cmpxchg_user_u32(uaddr as *mut u32, old, new, seen.as_mut_ptr()) };
    #[cfg(target_arch = "aarch64")]
    // SAFETY: range and alignment are checked; HAL recovers both exclusive-access fault sites.
    let status = unsafe { hal_aarch64::raw_cmpxchg_user_u32(uaddr as *mut u32, old, new, seen.as_mut_ptr()) };
    match status {
        ATOMIC_OK => {
            // SAFETY: both HALs initialize `seen` before returning ATOMIC_OK.
            Ok(unsafe { seen.assume_init() })
        }
        ATOMIC_FAULT => Err(Errno::Efault),
        ATOMIC_RETRY => Err(Errno::Eagain),
        _ => Err(Errno::Efault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmpxchg_returns_the_observed_word_and_only_swaps_on_match() {
        let mut word = 7u32;
        let addr = (&mut word as *mut u32) as u64;
        assert_eq!(cmpxchg_user_u32(addr, 6, 9), Ok(7));
        assert_eq!(word, 7);
        assert_eq!(cmpxchg_user_u32(addr, 7, 9), Ok(7));
        assert_eq!(word, 9);
    }

    #[test]
    fn cmpxchg_refuses_addresses_the_arch_primitive_must_not_touch() {
        assert_eq!(cmpxchg_user_u32(0, 0, 1), Err(Errno::Efault));
        assert_eq!(cmpxchg_user_u32(hal::USER_VA_END, 0, 1), Err(Errno::Efault));
        assert_eq!(cmpxchg_user_u32(hal::USER_VA_END - 3, 0, 1), Err(Errno::Efault));
        assert_eq!(cmpxchg_user_u32(3, 0, 1), Err(Errno::Efault));
    }
}
