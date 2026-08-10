// The one owner of every user-memory transfer this crate makes.
//
// All of it goes through `uaccess`, whose hand-written copy routines are the
// only accesses carrying an `__ex_table` fixup. The rule the callers used to
// follow — range-check the address, then dereference it — proves the number is
// inside the user half and nothing at all about a page being under it, so an
// in-range address a user had just unmapped faulted the KERNEL where Linux
// `get_user`/`copy_from_user` answer EFAULT.
//
// Non-gated on purpose: `live` is `cfg(target_os = "oxide-kernel")`, so a test
// written beside its callers compiles to nothing and reports ok. The decision
// worth testing — which addresses are refused, and which bytes are which field
// — lives here, where a test can fail.

use syscall::errno::Errno;

/// # C: O(1)
pub fn read_u32(uptr: u64) -> Result<u32, Errno> {
    let mut raw = [0u8; 4];
    uaccess::copy_from_user(&mut raw, uptr)?;
    Ok(u32::from_ne_bytes(raw))
}

/// # C: O(1)
pub fn write_u32(uptr: u64, v: u32) -> Result<(), Errno> {
    uaccess::copy_to_user(uptr, &v.to_ne_bytes())
}

/// # C: O(1)
pub fn read_i32(uptr: u64) -> Result<i32, Errno> {
    read_u32(uptr).map(|v| v as i32)
}

/// # C: O(1)
pub fn read_u64(uptr: u64) -> Result<u64, Errno> {
    let mut raw = [0u8; 8];
    uaccess::copy_from_user(&mut raw, uptr)?;
    Ok(u64::from_ne_bytes(raw))
}

/// # C: O(1)
pub fn read_i64(uptr: u64) -> Result<i64, Errno> {
    read_u64(uptr).map(|v| v as i64)
}

/// # C: O(1)
pub fn write_i64(uptr: u64, v: i64) -> Result<(), Errno> {
    uaccess::copy_to_user(uptr, &v.to_ne_bytes())
}

/// A zero-length transfer never looks at the pointer, matching Linux's
/// skip-the-copy-entirely behaviour for an empty buffer. # C: O(len)
pub fn read_bytes(uptr: u64, out: &mut [u8]) -> Result<(), Errno> {
    if out.is_empty() { return Ok(()); }
    uaccess::copy_from_user(out, uptr)
}

/// # C: O(len)
pub fn write_bytes(uptr: u64, src: &[u8]) -> Result<(), Errno> {
    if src.is_empty() { return Ok(()); }
    uaccess::copy_to_user(uptr, src)
}

/// `struct __kernel_timespec` — two `__kernel_time64_t`, 16 bytes on both
/// arches. `get_timespec64` copies BOTH words, so the whole struct has to be
/// reachable, not merely its first byte. # C: O(1)
pub const TIMESPEC_BYTES: u64 = 16;

/// Read one user `timespec` as `(tv_sec, tv_nsec)`. # C: O(1)
pub fn read_timespec(uptr: u64) -> Result<(i64, i64), Errno> {
    let mut raw = [0u8; TIMESPEC_BYTES as usize];
    uaccess::copy_from_user(&mut raw, uptr)?;
    let word = |i: usize| i64::from_ne_bytes(raw[i * 8..i * 8 + 8].try_into().expect("8 of 16"));
    Ok((word(0), word(1)))
}

#[cfg(test)]
#[path = "useraccess_tests.rs"]
mod tests;
