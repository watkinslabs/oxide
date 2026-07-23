// 311 process_vm_writev — one syscall, one file (docs/53 §0).
//
// Real cross-process memory transfer using the existing foreign-mm
// peek/poke helpers. Writes from our memory into the target's. Used by
// gdb/strace-style debuggers and by sandbox supervisors that need to
// patch a tracee's memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::pvmrw_common::{read_iovs, target_mm};

/// `sys_process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 311. Writes from our memory into the target's.
/// # C: O(sum(remote iov lens))
pub fn sys_process_vm_writev(args: &SyscallArgs) -> i64 {
    let pid    = args.a0 as u32;
    let liov_p = args.a1;
    let liovcnt = args.a2 as usize;
    let riov_p = args.a3;
    let riovcnt = args.a4 as usize;
    let flags  = args.a5;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let liovs = match read_iovs(liov_p, liovcnt) { Ok(v) => v, Err(rv) => return rv };
    let riovs = match read_iovs(riov_p, riovcnt) { Ok(v) => v, Err(rv) => return rv };
    // Hold `target_mm` alive for the WHOLE chunked copy loop below — its
    // Arc is the only thing pinning the foreign AS against a concurrent
    // exit/execve tearing it (and its physical frames) down mid-walk.
    // Without this, a write can land in a freed-and-reallocated physical
    // frame if the target exits mid-transfer.
    let target_mm = match target_mm(pid) { Ok(m) => m, Err(rv) => return rv };
    let target_root = target_mm.root_pa();
    let mut total: usize = 0;
    let mut li = 0usize; let mut lo = 0u64;
    let mut ri = 0usize; let mut ro = 0u64;
    while li < liovs.len() && ri < riovs.len() {
        let (lbase, llen) = liovs[li];
        let (rbase, rlen) = riovs[ri];
        let lremain = llen - lo;
        let rremain = rlen - ro;
        let chunk = core::cmp::min(lremain, rremain) as usize;
        if chunk == 0 { break; }
        let src = lbase + lo;
        if src >= hal::USER_VA_END
            || src.checked_add(chunk as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        let mut tmp = alloc::vec![0u8; chunk];
        // SAFETY: src+chunk validated < USER_VA_END; CPL=0 byte reads through caller's AS into kernel-owned tmp slice; bounded by chunk.
        unsafe {
            for i in 0..chunk {
                tmp[i] = core::ptr::read_volatile((src + i as u64) as *const u8);
            }
        }
        // SAFETY: `target_mm` (bound above, alive for this whole loop) pins the foreign AS; rbase+ro+chunk is the remote iov range; writes via HHDM, only on writable leaves per foreign-PT walk.
        let n = unsafe { pmm::user_as::write_foreign_user(target_root, rbase + ro, &tmp[..]) };
        if n == 0 { break; }
        total += n;
        lo += n as u64; if lo >= llen { li += 1; lo = 0; }
        ro += n as u64; if ro >= rlen { ri += 1; ro = 0; }
        if n < chunk { break; }
    }
    total as i64
}
