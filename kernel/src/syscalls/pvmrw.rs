// `process_vm_readv` / `process_vm_writev` (slots 310/311). Real
// cross-process memory transfer using the existing foreign-mm peek/
// poke helpers. Used by gdb/strace-style debuggers and by sandbox
// supervisors that need to inspect or patch a tracee's memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// Read each iovec entry pair into kernel-side `Vec<(u64,u64)>`. The
/// iov array itself lives in the *caller's* address space.
fn read_iovs(p: u64, n: usize) -> Result<alloc::vec::Vec<(u64, u64)>, i64> {
    if n > 1024 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if n == 0 { return Ok(alloc::vec::Vec::new()); }
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add((n * 16) as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let mut out = alloc::vec::Vec::with_capacity(n);
    // SAFETY: p+(n*16) validated < USER_VA_END; CPL=0 reads pairs of u64 (iov_base, iov_len) through caller's AS at the iovec layout offsets.
    unsafe {
        for i in 0..n {
            let base = core::ptr::read_volatile((p + (i * 16) as u64) as *const u64);
            let len  = core::ptr::read_volatile((p + (i * 16 + 8) as u64) as *const u64);
            out.push((base, len));
        }
    }
    Ok(out)
}

fn target_root_pa(pid: u32) -> Result<u64, i64> {
    let task = match sched::live::registry::lookup(pid) {
        Some(t) => t, None => return Err(-(Errno::Esrch.as_i32() as i64)),
    };
    // SAFETY: target task may be on another CPU; mm slot is single-mutator per task per `13§5`. The Arc<AddressSpace> snapshot is OK.
    let mm = match unsafe { task.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Esrch.as_i32() as i64)),
    };
    Ok(mm.root_pa())
}

/// `sys_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 310. Reads from the target's memory into our own.
/// # C: O(sum(remote iov lens))
pub fn kernel_sys_process_vm_readv(args: &SyscallArgs) -> i64 {
    let pid    = args.a0 as u32;
    let liov_p = args.a1;
    let liovcnt = args.a2 as usize;
    let riov_p = args.a3;
    let riovcnt = args.a4 as usize;
    let flags  = args.a5;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let liovs = match read_iovs(liov_p, liovcnt) { Ok(v) => v, Err(rv) => return rv };
    let riovs = match read_iovs(riov_p, riovcnt) { Ok(v) => v, Err(rv) => return rv };
    let target_root = match target_root_pa(pid) { Ok(p) => p, Err(rv) => return rv };
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
        // SAFETY: target_root is the foreign task's AS root_pa snapshot held by Arc; rbase + chunk is the remote iov range; reads only via HHDM-mapped frames.
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

/// `sys_process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 311. Writes from our memory into the target's.
/// # C: O(sum(remote iov lens))
pub fn kernel_sys_process_vm_writev(args: &SyscallArgs) -> i64 {
    let pid    = args.a0 as u32;
    let liov_p = args.a1;
    let liovcnt = args.a2 as usize;
    let riov_p = args.a3;
    let riovcnt = args.a4 as usize;
    let flags  = args.a5;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let liovs = match read_iovs(liov_p, liovcnt) { Ok(v) => v, Err(rv) => return rv };
    let riovs = match read_iovs(riov_p, riovcnt) { Ok(v) => v, Err(rv) => return rv };
    let target_root = match target_root_pa(pid) { Ok(p) => p, Err(rv) => return rv };
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
        // SAFETY: target_root is the foreign task's root_pa snapshot held by Arc; rbase+ro+chunk is the remote iov range; writes via HHDM, only on writable leaves per foreign-PT walk.
        let n = unsafe { pmm::user_as::write_foreign_user(target_root, rbase + ro, &tmp[..]) };
        if n == 0 { break; }
        total += n;
        lo += n as u64; if lo >= llen { li += 1; lo = 0; }
        ro += n as u64; if ro >= rlen { ri += 1; ro = 0; }
        if n < chunk { break; }
    }
    total as i64
}
