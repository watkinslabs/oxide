// User-memory access for the `bpf(2)` attr path.
//
// All actual access uses the exception-table-backed `uaccess` copies.
// Pure range arithmetic stays here so hosted tests can cover boundary
// decisions without deliberately faulting the test process.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::attr::{self, Attr};
use super::uapi;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CommonAttr {
    pub log_buf: u64,
    pub log_size: u32,
    pub log_level: u32,
    pub true_size_ptr: Option<u64>,
}

/// `-EFAULT` unless `[ptr, ptr+len)` lies entirely in user VA.
/// # C: O(1)
pub fn range_ok(ptr: u64, len: usize) -> Result<(), Errno> {
    if uaccess::access_ok(ptr, len) { Ok(()) } else { Err(Errno::Efault) }
}

fn checked_user_add(ptr: u64, offset: usize) -> Result<u64, Errno> {
    let next = ptr.checked_add(offset as u64).ok_or(Errno::Efault)?;
    range_ok(next, 0)?;
    Ok(next)
}

/// # C: O(len)
pub fn read_bytes(ptr: u64, out: &mut [u8]) -> Result<(), Errno> {
    range_ok(ptr, out.len())?;
    uaccess::copy_from_user(out, ptr)
}

/// # C: O(len)
pub fn write_bytes(ptr: u64, src: &[u8]) -> Result<(), Errno> {
    range_ok(ptr, src.len())?;
    uaccess::copy_to_user(ptr, src)
}

/// `check_zeroed_user()` — faulting is `-EFAULT`, a non-zero byte is
/// reported to the caller so it can raise `-E2BIG`. # C: O(len)
pub fn all_zero(ptr: u64, len: usize) -> Result<bool, Errno> {
    range_ok(ptr, len)?;
    let mut scratch = [0u8; 256];
    let mut done = 0usize;
    while done < len {
        let take = core::cmp::min(scratch.len(), len - done);
        read_bytes(checked_user_add(ptr, done)?, &mut scratch[..take])?;
        if scratch[..take].iter().any(|byte| *byte != 0) { return Ok(false); }
        done += take;
    }
    Ok(true)
}

/// # C: O(len)
pub fn read_vec(ptr: u64, len: usize) -> Result<Vec<u8>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Errno::Enomem)?;
    v.resize(len, 0);
    read_bytes(ptr, &mut v)?;
    Ok(v)
}

/// The syscall prologue checks the user tail, zeroes its staging value,
/// then copies the provided prefix. Ordering is load-bearing — E2BIG for a
/// silly-large or non-zero-tail size beats every per-command errno,
/// including the unknown-command EINVAL. # C: O(size)
pub fn fetch_attr(ptr: u64, size: u32) -> Result<Attr, Errno> {
    let (copy, tail) = attr::size_protocol(size)?;
    if tail != 0 {
        let tail_ptr = checked_user_add(ptr, uapi::ATTR_SIZE)?;
        attr::tail_verdict(all_zero(tail_ptr, tail)?)?;
    }
    let mut a = Attr::zeroed();
    read_bytes(ptr, &mut a.bytes[..copy])?;
    Ok(a)
}

/// `BPF_COMMON_ATTRS` half of `__sys_bpf()`: the same tail-zero
/// protocol against `offsetofend(struct bpf_common_attr, log_true_size)`.
/// The log buffer itself is a verifier-log sink this kernel has no
/// verifier text for, so only the ABI contract is enforced.
/// # C: O(size_common)
pub fn fetch_common_attr(ptr: u64, size: u32) -> Result<CommonAttr, Errno> {
    let actual = size as usize;
    if actual > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    if actual > uapi::COMMON_ATTR_SIZE {
        let extra = actual - uapi::COMMON_ATTR_SIZE;
        let tail_ptr = checked_user_add(ptr, uapi::COMMON_ATTR_SIZE)?;
        attr::tail_verdict(all_zero(tail_ptr, extra)?)?;
    }
    let copied = core::cmp::min(actual, uapi::COMMON_ATTR_SIZE);
    let mut bytes = [0u8; uapi::COMMON_ATTR_SIZE];
    read_bytes(ptr, &mut bytes[..copied])?;
    Ok(CommonAttr {
        log_buf: u64::from_ne_bytes(bytes[uapi::off_common::LOG_BUF..uapi::off_common::LOG_BUF + 8]
            .try_into().unwrap()),
        log_size: u32::from_ne_bytes(bytes[uapi::off_common::LOG_SIZE..uapi::off_common::LOG_SIZE + 4]
            .try_into().unwrap()),
        log_level: u32::from_ne_bytes(bytes[uapi::off_common::LOG_LEVEL..uapi::off_common::LOG_LEVEL + 4]
            .try_into().unwrap()),
        true_size_ptr: (actual >= uapi::COMMON_ATTR_SIZE).then(|| {
            ptr + uapi::off_common::LOG_TRUE_SIZE as u64
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_range_decisions_reject_wrap_and_kernel_addresses() {
        assert_eq!(range_ok(0, 1), Err(Errno::Efault));
        assert_eq!(range_ok(u64::MAX - 3, 8), Err(Errno::Efault));
        assert_eq!(range_ok(hal::USER_VA_END, 1), Err(Errno::Efault));
        assert_eq!(range_ok(hal::USER_VA_END, 0), Ok(()));
    }

    #[test]
    fn checked_tail_pointer_never_wraps_or_crosses_user_boundary() {
        assert_eq!(checked_user_add(u64::MAX, 1), Err(Errno::Efault));
        assert_eq!(
            checked_user_add(hal::USER_VA_END - uapi::ATTR_SIZE as u64, uapi::ATTR_SIZE),
            Ok(hal::USER_VA_END),
        );
        assert_eq!(
            checked_user_add(hal::USER_VA_END - uapi::ATTR_SIZE as u64 + 1, uapi::ATTR_SIZE),
            Err(Errno::Efault),
        );
    }

    #[test]
    fn hosted_copies_use_valid_process_memory() {
        let source = [1u8, 2, 3, 4];
        let mut copied = [0u8; 4];
        read_bytes(source.as_ptr() as u64, &mut copied).unwrap();
        assert_eq!(copied, source);
        let mut destination = [0u8; 4];
        write_bytes(destination.as_mut_ptr() as u64, &source).unwrap();
        assert_eq!(destination, source);
    }

    #[test]
    fn common_attr_uses_the_twenty_byte_extensible_boundary() {
        let mut bytes = [0u8; uapi::COMMON_ATTR_SIZE + 1];
        bytes[uapi::off_common::LOG_BUF..uapi::off_common::LOG_BUF + 8]
            .copy_from_slice(&7u64.to_ne_bytes());
        bytes[uapi::off_common::LOG_SIZE..uapi::off_common::LOG_SIZE + 4]
            .copy_from_slice(&11u32.to_ne_bytes());
        bytes[uapi::off_common::LOG_LEVEL..uapi::off_common::LOG_LEVEL + 4]
            .copy_from_slice(&3u32.to_ne_bytes());
        let common = fetch_common_attr(
            bytes.as_ptr() as u64,
            uapi::COMMON_ATTR_SIZE as u32,
        ).unwrap();
        assert_eq!(common.log_buf, 7);
        assert_eq!(common.log_size, 11);
        assert_eq!(common.log_level, 3);
        assert_eq!(
            common.true_size_ptr,
            Some(bytes.as_ptr() as u64 + uapi::off_common::LOG_TRUE_SIZE as u64),
        );

        bytes[uapi::COMMON_ATTR_SIZE] = 1;
        assert_eq!(
            fetch_common_attr(bytes.as_ptr() as u64, bytes.len() as u32),
            Err(Errno::E2big),
        );
    }
}
