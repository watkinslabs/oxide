// process_vm_readv/writev (310/311) decision core — Linux
// `mm/process_vm_access.c` plus the `lib/iov_iter.c` import path
// (`copy_iovec_from_user` / `iovec_from_user` / `__import_iovec` /
// `import_ubuf`) those two syscalls run their iov arrays through.
//
// Non-gated on purpose: everything here is errno ORDER, truncation policy
// and partial-transfer accounting — the parts a hosted test can pin down
// without a boot (`tests/pvmrw_decide_hosted.rs`). The kernel-only halves
// (user copies, foreign page-table walks) live in `import`/`task`/`xfer`.

use syscall::errno::Errno;

/// Linux `UIO_MAXIOV` (`include/uapi/linux/uio.h`): segment-count ceiling
/// `iovec_from_user` enforces for both iov arrays.
pub const UIO_MAXIOV: usize = 1024;

/// `sizeof(struct iovec)` on both LP64 targets: `void *` + `size_t`.
pub const IOVEC_BYTES: usize = core::mem::size_of::<u64>() * 2;

/// Linux `MAX_RW_COUNT` (`include/linux/fs.h`) — the ceiling
/// `__import_iovec`/`import_ubuf` TRUNCATE the local iov total to.
pub use uaccess::MAX_RW_COUNT;

/// Bounce-buffer ceiling for one transfer step. Linux batches at
/// `PVM_MAX_USER_PAGES` pinned pages; the exact batch is invisible to
/// userspace because partial transfers are accounted either way, but it
/// must be bounded or a 2 GiB iov would ask the allocator for 2 GiB.
pub const CHUNK_MAX: usize = 64 * 1024;

const PAGE_SHIFT: u32 = 12;
const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;

/// `-errno` in syscall return form.
fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

/// Linux `iovec_from_user`: zero segments are legal and mean "nothing to
/// do"; more than `UIO_MAXIOV` is EINVAL — checked before the array is
/// touched, so an unreadable array with a bad count still reports EINVAL.
/// # C: O(1)
pub fn check_seg_count(nr_segs: usize) -> Result<(), i64> {
    if nr_segs > UIO_MAXIOV { return Err(e(Errno::Einval)); }
    Ok(())
}

/// Linux `copy_iovec_from_user`: an `iov_len` that is negative when cast to
/// `ssize_t` is EINVAL. Applies to BOTH arrays (the remote array goes
/// through `iovec_from_user`, which shares this loop).
/// # C: O(1)
pub fn check_seg_len(len: u64) -> Result<(), i64> {
    if len > i64::MAX as u64 { return Err(e(Errno::Einval)); }
    Ok(())
}

/// `copy_iovec_from_user` validates EVERY segment's length in one pass
/// before any later rule runs, so a bad length in a trailing segment
/// outranks a bad address in a leading one.
/// # C: O(n)
pub fn check_all_seg_lens(iovs: &[(u64, u64)]) -> Result<(), i64> {
    for &(_, len) in iovs { check_seg_len(len)?; }
    Ok(())
}

/// Decode one `struct iovec` from the raw bytes of a fetched iov array.
/// # C: O(1)
pub fn decode_iov(raw: &[u8], i: usize) -> (u64, u64) {
    let o = i * IOVEC_BYTES;
    let mut w = [0u8; 8];
    w.copy_from_slice(&raw[o..o + 8]);
    let base = u64::from_ne_bytes(w);
    w.copy_from_slice(&raw[o + 8..o + IOVEC_BYTES]);
    (base, u64::from_ne_bytes(w))
}

/// Linux `__import_iovec` / `import_ubuf` over the LOCAL array, run after
/// `check_all_seg_lens`. Two rules that are easy to get backwards:
///   * `MAX_RW_COUNT` TRUNCATES a segment, it never rejects it — the excess
///     is silently dropped and the syscall reports the shorter count.
///   * a one-segment array is imported by `import_ubuf`, which clamps
///     BEFORE `access_ok`; a multi-segment array is imported by the
///     `__import_iovec` loop, which runs `access_ok` on the UNCLAMPED
///     length first. So `liovcnt == 1` with a huge length succeeds where
///     the same length inside a two-segment array is EFAULT.
/// Returns the importable byte total.
/// # C: O(n)
pub fn import_local(iovs: &mut [(u64, u64)]) -> Result<u64, i64> {
    let single = iovs.len() == 1;
    let mut total: u64 = 0;
    for seg in iovs.iter_mut() {
        let room = MAX_RW_COUNT as u64 - total;
        if single && seg.1 > room { seg.1 = room; }
        if !uaccess::access_ok(seg.0, seg.1 as usize) { return Err(e(Errno::Efault)); }
        if seg.1 > room { seg.1 = room; }
        total += seg.1;
    }
    Ok(total)
}

/// Linux `process_vm_rw_core`'s `nr_pages` precheck over the REMOTE array:
/// the transfer loop runs only if some remote segment spans at least one
/// page. An all-zero-length remote array therefore returns 0 WITHOUT
/// looking the pid up — no ESRCH for a dead pid, no EPERM for a foreign one.
/// # C: O(n)
pub fn remote_pages(iovs: &[(u64, u64)]) -> u64 {
    let mut max = 0u64;
    for &(base, len) in iovs {
        if len == 0 { continue; }
        let last = base.wrapping_add(len - 1);
        let n = (last >> PAGE_SHIFT).wrapping_sub(base >> PAGE_SHIFT).wrapping_add(1);
        if n > max { max = n; }
    }
    max
}

/// Linux `process_vm_rw_core` tail: `if (total_len) rc = total_len`. Any
/// bytes moved outrank a later failure — the errno surfaces only when
/// nothing moved at all.
/// # C: O(1)
pub fn finish(total: usize, rc: i64) -> i64 {
    if total > 0 { total as i64 } else { rc }
}

/// One transfer step: `len` bytes between local VA `local` and remote VA
/// `remote`.
pub struct Chunk { pub local: u64, pub remote: u64, pub len: usize }

/// Lockstep walk of the local and remote iov arrays.
///
/// Zero-length segments are SKIPPED, never terminators: Linux's `iov_iter`
/// steps over empty local segments, and `process_vm_rw_single_vec` returns
/// 0 immediately for `len == 0` and moves to the next remote segment. The
/// walk ends when EITHER side is exhausted, which is how a short local
/// array truncates a long remote one.
pub struct Lockstep { li: usize, lo: u64, ri: usize, ro: u64 }

impl Default for Lockstep {
    fn default() -> Self { Self::new() }
}

impl Lockstep {
    /// # C: O(1)
    pub fn new() -> Self { Lockstep { li: 0, lo: 0, ri: 0, ro: 0 } }

    /// Next chunk, or `None` once either array is exhausted.
    /// # C: O(zero-length run length)
    pub fn next(&mut self, l: &[(u64, u64)], r: &[(u64, u64)]) -> Option<Chunk> {
        while self.li < l.len() && l[self.li].1 <= self.lo { self.li += 1; self.lo = 0; }
        while self.ri < r.len() && r[self.ri].1 <= self.ro { self.ri += 1; self.ro = 0; }
        if self.li >= l.len() || self.ri >= r.len() { return None; }
        let (lbase, llen) = l[self.li];
        let (rbase, rlen) = r[self.ri];
        let span = core::cmp::min(llen - self.lo, rlen - self.ro);
        let len = core::cmp::min(span, CHUNK_MAX as u64) as usize;
        Some(Chunk {
            local:  lbase.saturating_add(self.lo),
            remote: rbase.saturating_add(self.ro),
            len,
        })
    }

    /// Record `n` bytes moved out of the chunk `next` just handed out.
    /// # C: O(1)
    pub fn advance(&mut self, n: usize) { self.lo += n as u64; self.ro += n as u64; }
}

/// Bytes from `va` to the end of its page — the step size a page-granular
/// permission probe advances by.
/// # C: O(1)
pub fn page_remaining(va: u64) -> usize {
    (PAGE_BYTES - (va & (PAGE_BYTES - 1))) as usize
}
