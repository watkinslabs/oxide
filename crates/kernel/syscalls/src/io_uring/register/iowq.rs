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

/// Apply a worker mask to the ring's submission-poll thread, if it has one.
/// Linux routes an `IORING_SETUP_SQPOLL` ring's affinity registration through
/// the poll thread, and parks it across the change: a thread moved between
/// processors mid-pass would resume its loop on a processor the caller has
/// just said it may not use. # C: O(1) + the park
fn apply_to_poll_thread(inode: &IoUringInode, mask: cpu::CpuMask) {
    let Some(sqd) = crate::io_uring::sqpoll::of(inode) else { return };
    // SAFETY: process context in the register syscall path on the caller's own CPU, holding no lock the poll thread takes; the caller is a user task, never the poll thread itself.
    let parked = unsafe { sqd.park() };
    parked.set_cpus_allowed(mask);
    // `SqParkGuard::drop` is Linux `io_sq_thread_unpark` and releases the
    // SQPOLL control mutex after the affinity update.
}

/// `IORING_REGISTER_IOWQ_AFF`, and its unregistering form when `len == 0`:
/// which processors workers may run on. # C: O(1)
pub fn affinity(inode: &IoUringInode, arg: u64, len: u32) -> i64 {
    if len == 0 {
        // Unregistering restores the unrestricted set.
        pool::set_cpu_mask(cpu::CpuMask::empty());
        apply_to_poll_thread(inode, cpu::CpuMask::empty());
        return 0;
    }
    // The ABI is a byte array sized for the kernel CPU mask. Bytes beyond the
    // native mask are not read and therefore cannot be silently truncated.
    let take = core::cmp::min(len as usize, cpu::mask::CPU_MASK_WORDS * 8);
    let mut b = [0u8; cpu::mask::CPU_MASK_WORDS * 8];
    if uaccess::copy_from_user(&mut b[..take], arg).is_err() { return err(Errno::Efault); }
    let mut words = [0u64; cpu::mask::CPU_MASK_WORDS];
    for (word, bytes) in words.iter_mut().zip(b.chunks_exact(8)) {
        *word = u64::from_ne_bytes(bytes.try_into().expect("eight-byte mask word"));
    }
    let mask = cpu::CpuMask::from_words(&words);
    if mask.is_empty() { return err(Errno::Einval); }
    pool::set_cpu_mask(mask);
    apply_to_poll_thread(inode, mask);
    0
}
