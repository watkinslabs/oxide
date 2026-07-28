// User-buffer validation helpers. Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use hal::USER_VA_END;

/// Linux `MAX_RW_COUNT`: cap one read/write transfer below `INT_MAX` and on a
/// page boundary (`include/linux/fs.h`). Applied after access_ok/rw_verify_area
/// and before the file op sees the userspace buffer. # C: O(1)
pub(crate) use uaccess::MAX_RW_COUNT;

/// Clamp a single read/write byte count to Linux `MAX_RW_COUNT`. # C: O(1)
pub(crate) fn clamp_rw_count(n: usize) -> usize {
    core::cmp::min(n, MAX_RW_COUNT)
}

/// Validate that a user buffer `[ptr, ptr + len)` lies entirely
/// below `USER_VA_END` and is `align`-byte aligned at `ptr`.
/// Returns Ok(()) or Err(-EFAULT-as-i64) ready to return from a
/// glue handler.
/// # C: O(1)
pub(crate) fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{clamp_rw_count, MAX_RW_COUNT};

    #[test]
    fn clamp_rw_count_matches_linux_max_rw_count() {
        assert_eq!(clamp_rw_count(0), 0);
        assert_eq!(clamp_rw_count(MAX_RW_COUNT - 1), MAX_RW_COUNT - 1);
        assert_eq!(clamp_rw_count(MAX_RW_COUNT), MAX_RW_COUNT);
        assert_eq!(clamp_rw_count(MAX_RW_COUNT + 1), MAX_RW_COUNT);
        assert_eq!(clamp_rw_count(usize::MAX), MAX_RW_COUNT);
    }
}

/// Same as `validate_user_buf` but also confirms every page in
/// the range belongs to a VMA carrying `VmaProt::WRITE`. Used by
/// syscalls that perform kernel-side writes into user buffers
/// (getcwd / read / readv / readlinkat / uname / ...). Without
/// this, a userspace caller passing a pointer into its own
/// .rodata or .text segment would trigger a #PF in CPL=0 when
/// CR0.WP=1 — the kernel doesn't have an extable, so the fault
/// halts the whole system. Pre-validating returns -EFAULT to the
/// syscall caller, which is what the user expected anyway.
/// # C: O(N_vmas spanning the range)
pub(crate) fn validate_user_buf_writable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    use vmm::VmaProt;
    validate_user_buf(ptr, len, align)?;
    covered_by(ptr, len, VmaProt::WRITE)
}

/// Copy an `int[2]` fd pair to userspace with Linux `copy_to_user` fault shape.
/// # C: O(1)
pub(crate) fn write_i32_pair(ptr: u64, a: i32, b: i32) -> Result<(), i64> {
    validate_user_buf_writable(ptr, 8, 4)?;
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&a.to_ne_bytes());
    bytes[4..].copy_from_slice(&b.to_ne_bytes());
    uaccess::copy_to_user(ptr, &bytes).map_err(|_| -(Errno::Efault.as_i32() as i64))
}

/// Write one possibly unaligned userspace `int`, matching Linux `put_user`. # C: O(1)
pub(crate) fn write_user_i32(ptr: u64, value: i32) -> Result<(), i64> {
    validate_user_buf_writable(ptr, 4, 1)?;
    uaccess::copy_to_user(ptr, &value.to_ne_bytes())
        .map_err(|_| -(Errno::Efault.as_i32() as i64))
}

/// Same as `validate_user_buf` but confirms every page in the range belongs to
/// a readable VMA before the kernel copies from it.
/// # C: O(N_vmas spanning the range)
pub(crate) fn validate_user_buf_readable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    use vmm::VmaProt;
    validate_user_buf(ptr, len, align)?;
    covered_by(ptr, len, VmaProt::READ)
}

/// Shared walk for both directions: is `[ptr, ptr + len)` covered by VMAs
/// carrying `need`? Steps VMA-by-VMA (`crate::uaccess_range::range_covered`),
/// never page-by-page — the range is a user-controlled length, and this runs
/// with interrupts masked, so a per-page loop is a CPU freeze the caller
/// chooses the duration of (B1476: 300+ s observed, which also starved the
/// peer CPU's TLB-shootdown ACK).
/// # C: O(N_vmas spanning the range)
fn covered_by(ptr: u64, len: u64, need: vmm::VmaProt) -> Result<(), i64> {
    use hal::UserVirtAddr;
    use crate::uaccess_range::Span;
    if len == 0 { return Ok(()); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    // SAFETY: mm slot single-mutator per `13§5`; we are the running task on this CPU and the sole reader during the syscall.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    let ok = crate::uaccess_range::range_covered(ptr, len, |va| {
        let uva = UserVirtAddr::new(va)?;
        let v = mm.find_vma(uva)?;
        Some(Span { end: v.end.as_u64(), allowed: v.prot.contains(need) })
    });
    if ok { Ok(()) } else { Err(-(Errno::Efault.as_i32() as i64)) }
}
