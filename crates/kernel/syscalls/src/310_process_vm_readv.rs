// 310 process_vm_readv — one syscall, one file (docs/53 §0).
//
// Real cross-process memory transfer using the existing foreign-mm
// peek/poke helpers. Reads from the target's memory into our own. Used
// by gdb/strace-style debuggers and by sandbox supervisors that need to
// inspect a tracee's memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::pvmrw_common::{read_iovs, target_mm};

/// `sys_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 310. Reads from the target's memory into our own.
/// # C: O(sum(remote iov lens))
pub fn sys_process_vm_readv(args: &SyscallArgs) -> i64 {
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
    let target_mm = match target_mm(pid) { Ok(m) => m, Err(rv) => return rv };
    let target_root = target_mm.root_pa();
    // Walk both iov sequences in lockstep, splitting when one runs out.
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
        let mut tmp = alloc::vec![0u8; chunk];
        // SAFETY: `target_mm` (bound above, alive for this whole loop) pins the foreign AS; rbase + chunk is the remote iov range; reads only via HHDM-mapped frames.
        let n = unsafe { pmm::user_as::read_foreign_user(target_root, rbase + ro, &mut tmp[..]) };
        if n == 0 { break; }
        // Copy n bytes into local AS at lbase + lo.
        let dst = lbase + lo;
        if dst >= hal::USER_VA_END
            || dst.checked_add(n as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: dst+n validated < USER_VA_END; CPL=0 byte copies through caller's AS; n bytes from kernel-owned tmp slice.
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((dst + i as u64) as *mut u8, tmp[i]);
            }
        }
        total += n;
        lo += n as u64; if lo >= llen { li += 1; lo = 0; }
        ro += n as u64; if ro >= rlen { ri += 1; ro = 0; }
        if n < chunk { break; }
    }
    total as i64
}
