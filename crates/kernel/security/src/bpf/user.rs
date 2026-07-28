// User-memory access for the `bpf(2)` attr path.
//
// The `security` crate carries no `uaccess` dependency, so range
// validation against `USER_VA_END` plus volatile byte access is the
// crate-local idiom (same shape the seccomp and map paths already use).
// Everything that decides an errno lives in `attr.rs`; this file only
// moves bytes.

extern crate alloc;
use alloc::vec::Vec;

use hal::USER_VA_END;
use syscall::errno::Errno;

use super::attr::{self, Attr};
use super::uapi;

/// `-EFAULT` unless `[ptr, ptr+len)` lies entirely in user VA. A
/// zero-length range is always fine — `copy_from_bpfptr(.., 0)`
/// succeeds in Linux even for a NULL `uattr`. # C: O(1)
pub fn range_ok(ptr: u64, len: usize) -> Result<(), Errno> {
    if len == 0 { return Ok(()); }
    if ptr == 0 { return Err(Errno::Efault); }
    match ptr.checked_add(len as u64) {
        Some(end) if end <= USER_VA_END => Ok(()),
        _ => Err(Errno::Efault),
    }
}

/// # C: O(len)
pub fn read_bytes(ptr: u64, out: &mut [u8]) -> Result<(), Errno> {
    range_ok(ptr, out.len())?;
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: range_ok proved ptr..ptr+len is user VA under the caller's address space; single-byte volatile read on the syscall path.
        *slot = unsafe { core::ptr::read_volatile((ptr + i as u64) as *const u8) };
    }
    Ok(())
}

/// # C: O(len)
pub fn write_bytes(ptr: u64, src: &[u8]) -> Result<(), Errno> {
    range_ok(ptr, src.len())?;
    for (i, b) in src.iter().copied().enumerate() {
        // SAFETY: range_ok proved ptr..ptr+len is user VA under the caller's address space; single-byte volatile write on the syscall path.
        unsafe { core::ptr::write_volatile((ptr + i as u64) as *mut u8, b); }
    }
    Ok(())
}

/// `check_zeroed_user()` — faulting is `-EFAULT`, a non-zero byte is
/// reported to the caller so it can raise `-E2BIG`. # C: O(len)
pub fn all_zero(ptr: u64, len: usize) -> Result<bool, Errno> {
    range_ok(ptr, len)?;
    for i in 0..len as u64 {
        // SAFETY: range_ok proved ptr..ptr+len is user VA under the caller's address space; single-byte volatile read on the syscall path.
        if unsafe { core::ptr::read_volatile((ptr + i) as *const u8) } != 0 { return Ok(false); }
    }
    Ok(true)
}

/// # C: O(len)
pub fn read_vec(ptr: u64, len: usize) -> Result<Vec<u8>, Errno> {
    let mut v: Vec<u8> = alloc::vec![0u8; len];
    read_bytes(ptr, &mut v)?;
    Ok(v)
}

/// `__sys_bpf()`'s prologue: `bpf_check_uarg_tail_zero()` then
/// `memset(&attr, 0, sizeof(attr))` + `copy_from_bpfptr(&attr, uattr,
/// min(size, sizeof(attr)))`. Ordering is load-bearing — E2BIG for a
/// silly-large or non-zero-tail size beats every per-command errno,
/// including the unknown-command EINVAL. # C: O(size)
pub fn fetch_attr(ptr: u64, size: u32) -> Result<Attr, Errno> {
    let (copy, tail) = attr::size_protocol(size)?;
    if tail != 0 {
        attr::tail_verdict(all_zero(ptr + uapi::ATTR_SIZE as u64, tail)?)?;
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
pub fn check_common_attr(ptr: u64, size: u32) -> Result<(), Errno> {
    let actual = size as usize;
    if actual > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    if actual > uapi::COMMON_ATTR_SIZE {
        let extra = actual - uapi::COMMON_ATTR_SIZE;
        attr::tail_verdict(all_zero(ptr + uapi::COMMON_ATTR_SIZE as u64, extra)?)?;
    }
    range_ok(ptr, if actual < uapi::COMMON_ATTR_SIZE { actual } else { uapi::COMMON_ATTR_SIZE })
}
