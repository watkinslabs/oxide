// The transfer engine both process_vm_readv (310) and process_vm_writev
// (311) run — Linux `process_vm_rw` → `process_vm_rw_core`. The two slots
// differ only in `Dir`, exactly as Linux's two `SYSCALL_DEFINE6`s differ
// only in `vm_write`.

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::decide::{self, Chunk};
use super::import::read_iovs;
use super::task::target_mm;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// Linux `vm_write`: which way the bytes move.
pub(crate) enum Dir { Read, Write }

/// `process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write)`.
///
/// Check order is the whole contract; an earlier step's verdict wins:
///   1. `flags != 0` → EINVAL, before either array is looked at.
///   2. `import_iovec(lvec)` — local count/length/address rules.
///   3. no local bytes → return 0, WITHOUT reading `rvec` and without
///      resolving `pid` (so `liovcnt == 0` never reports ESRCH/EFAULT).
///   4. `iovec_from_user(rvec)` — remote count/length rules only.
///   5. `nr_pages == 0` → return 0, still before the pid lookup.
///   6. `find_get_task_by_vpid` → ESRCH, then `mm_access` → ESRCH/EPERM.
///   7. copy loop, then `if (total_len) rc = total_len`.
/// # C: O(sum(min(local,remote) iov lens))
pub(crate) fn run(args: &SyscallArgs, dir: Dir) -> i64 {
    let pid     = args.a0 as i32;
    let liov_p  = args.a1;
    let liovcnt = args.a2 as usize;
    let riov_p  = args.a3;
    let riovcnt = args.a4 as usize;
    let flags   = args.a5;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let mut liovs = match read_iovs(liov_p, liovcnt) { Ok(v) => v, Err(rv) => return rv };
    let local_total = match decide::import_local(&mut liovs[..]) { Ok(t) => t, Err(rv) => return rv };
    if local_total == 0 { return 0; }
    let riovs = match read_iovs(riov_p, riovcnt) { Ok(v) => v, Err(rv) => return rv };
    if decide::remote_pages(&riovs[..]) == 0 { return 0; }
    // Hold the Arc for the WHOLE loop: it is the only thing pinning the
    // foreign address space against a concurrent exit/execve tearing its
    // page tables and frames down mid-walk.
    let mm = match target_mm(pid) { Ok(m) => m, Err(rv) => return rv };
    let root = mm.root_pa();
    let mut step = decide::Lockstep::new();
    let mut total = 0usize;
    let mut rc = 0i64;
    while let Some(c) = step.next(&liovs[..], &riovs[..]) {
        let n = match dir { Dir::Read => read_chunk(root, &c), Dir::Write => write_chunk(root, &c) };
        total += n;
        step.advance(n);
        // A short step is Linux's `-EFAULT` arm (an unpinnable remote page,
        // or `copied < copy` on the local side). It only ever surfaces when
        // the whole call moved nothing.
        if n < c.len { rc = -(Errno::Efault.as_i32() as i64); break; }
    }
    decide::finish(total, rc)
}

/// One `Dir::Read` step: foreign pages → bounce buffer → caller. Returns
/// bytes moved; a short return ends the transfer.
/// # C: O(chunk len)
fn read_chunk(root: u64, c: &Chunk) -> usize {
    let len = writable_prefix(c.local, c.len);
    if len == 0 { return 0; }
    let mut tmp = alloc::vec![0u8; len];
    // SAFETY: `run` holds the target's AddressSpace Arc across this call, so `root` names live page tables; `read_foreign_user` only reads HHDM-mapped frames and stops at the first unmapped leaf.
    let got = unsafe { pmm::user_as::read_foreign_user(root, c.remote, &mut tmp[..]) };
    if got == 0 { return 0; }
    // SAFETY: `raw_copy_to_user` is the extable-protected copy; `tmp` is a kernel-owned Vec live for `got` bytes and `c.local` was access_ok'd at import and prot-checked by `writable_prefix`.
    let left = unsafe { uaccess::raw_copy_to_user(c.local, tmp.as_ptr(), got) };
    got - left
}

/// One `Dir::Write` step: caller → bounce buffer → foreign pages.
/// # C: O(chunk len)
fn write_chunk(root: u64, c: &Chunk) -> usize {
    let len = readable_prefix(c.local, c.len);
    if len == 0 { return 0; }
    let mut tmp = alloc::vec![0u8; len];
    // SAFETY: `raw_copy_from_user` is the extable-protected copy; `tmp` is a kernel-owned Vec writable for `len` bytes and `c.local` was access_ok'd at import and prot-checked by `readable_prefix`.
    let left = unsafe { uaccess::raw_copy_from_user(tmp.as_mut_ptr(), c.local, len) };
    let got = len - left;
    if got == 0 { return 0; }
    // SAFETY: `run` holds the target's AddressSpace Arc across this call, so `root` names live page tables; `write_foreign_user` refuses non-writable leaves and stops at the first unmapped one.
    unsafe { pmm::user_as::write_foreign_user(root, c.remote, &tmp[..got]) }
}

/// Longest prefix of `[base, base+len)` the kernel may write through.
///
/// Linux's `copy_page_to_iter` faults per page and reports what it managed
/// to move, so a partly-unwritable local buffer must yield its writable
/// prefix rather than the whole chunk failing. The kernel-mode store itself
/// is only recoverable through the extable, so the VMA protection is
/// confirmed first with the canonical `userbuf` helper.
/// # C: O(1) on the common whole-chunk hit; O(N_pages) otherwise
fn writable_prefix(base: u64, len: usize) -> usize {
    if validate_user_buf_writable(base, len as u64, 1).is_ok() { return len; }
    let mut ok = 0usize;
    while ok < len {
        let va = base + ok as u64;
        let step = core::cmp::min(len - ok, decide::page_remaining(va));
        if validate_user_buf_writable(va, step as u64, 1).is_err() { break; }
        ok += step;
    }
    ok
}

/// `writable_prefix` for the `Dir::Write` source side. # C: O(1) / O(N_pages)
fn readable_prefix(base: u64, len: usize) -> usize {
    if validate_user_buf_readable(base, len as u64, 1).is_ok() { return len; }
    let mut ok = 0usize;
    while ok < len {
        let va = base + ok as u64;
        let step = core::cmp::min(len - ok, decide::page_remaining(va));
        if validate_user_buf_readable(va, step as u64, 1).is_err() { break; }
        ok += step;
    }
    ok
}
