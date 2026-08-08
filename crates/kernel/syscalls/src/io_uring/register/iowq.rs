// Worker limits and worker processor affinity.
//
// The limit registration is also a query: it writes back what the limits were
// before the call, and a zero in either slot asks for that class to be left
// alone. A caller therefore reads its current limits by registering two zeros,
// which is the only way it can find them out.

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::iowq::{acct, pool};

/// # C: O(1)
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_REGISTER_IOWQ_MAX_WORKERS`. # C: O(1)
pub fn max_workers(inode: &IoUringInode, arg: u64) -> i64 {
    let mut b = [0u8; 4 * acct::NR];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let mut want = [0u32; acct::NR];
    for c in 0..acct::NR {
        let v = u32::from_ne_bytes([b[c * 4], b[c * 4 + 1], b[c * 4 + 2], b[c * 4 + 3]]);
        if v > i32::MAX as u32 { return err(Errno::Einval); }
        want[c] = v;
    }
    let prev = inode.set_iowq_max(want);
    for c in 0..acct::NR { b[c * 4..c * 4 + 4].copy_from_slice(&prev[c].to_ne_bytes()); }
    if uaccess::copy_to_user(arg, &b).is_err() { return err(Errno::Efault); }
    0
}

/// The widest processor mask this kernel can express in one word. A caller
/// naming processors above it is asking for something that cannot be honoured,
/// which is a different answer from asking for something forbidden.
pub const MAX_CPUS: u32 = 64;

/// `IORING_REGISTER_IOWQ_AFF`, and its unregistering form when `len == 0`:
/// which processors workers may run on. # C: O(1)
pub fn affinity(arg: u64, len: u32) -> i64 {
    if len == 0 {
        // Unregistering restores the unrestricted set.
        pool::set_cpu_mask(0);
        return 0;
    }
    // The caller's mask is a byte array; anything past the word this kernel
    // schedules on must be empty rather than silently dropped.
    let take = core::cmp::min(len as usize, MAX_CPUS as usize / 8);
    let mut b = [0u8; MAX_CPUS as usize / 8];
    if uaccess::copy_from_user(&mut b[..take], arg).is_err() { return err(Errno::Efault); }
    let mask = u64::from_ne_bytes(b);
    if mask == 0 { return err(Errno::Einval); }
    pool::set_cpu_mask(mask);
    0
}
