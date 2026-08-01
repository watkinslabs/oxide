// 440 process_madvise — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::s028_madvise::{LiveOps, madvise_behavior_valid, madvise_vmas,
    process_madvise_remote_valid, vector_madvise};

/// `process_madvise(pidfd, iovec, vlen, behavior, flags)` — slot 440.
///
/// Applies ONE advice across a vector of ranges in the address space named by
/// `pidfd`. The whole point of the syscall is the remote case, so the ladder
/// is what makes it safe, in the kernel's order:
///
/// 1. `flags` must be zero.
/// 2. The iovec array is imported from the CALLER's memory — before the pidfd
///    is even looked at, so a bad vector reports EFAULT rather than EBADF.
/// 3. The pidfd resolves to a task.
/// 4. Ptrace read access (fs credentials) on that task, which is what keeps
///    the syscall from becoming an address-space-layout oracle.
/// 5. The advice must be one the syscall recognises at all.
/// 6. Against a FOREIGN mm the advice must additionally be non-destructive —
///    a remote caller may change how warm the target's pages are, never drop
///    its data — and the caller must hold CAP_SYS_NICE.
///
/// "Foreign" means a different mm, not a different task: a sibling thread's
/// pidfd names the caller's own address space and takes the local path,
/// destructive advice included.
///
/// The return value is the byte count actually advised. A malformed or failing
/// range stops the vector and the count covers only the entries before it;
/// the errno surfaces only when nothing at all was advised.
/// # C: O(N_entries x N_vmas)
pub fn sys_process_madvise(args: &SyscallArgs) -> i64 {
    let pidfd  = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2 as usize;
    let advice = args.a3;
    let flags  = args.a4;

    if flags != 0 { return errno(Errno::Einval); }

    // The iovec array lives in the CALLER's AS. Imported first, matching the
    // kernel: a faulting vector is EFAULT even when the pidfd is also bad.
    let iovs = match crate::pvmrw::pvmrw_common::read_iovs(iov, iovcnt) { Ok(v) => v, Err(e) => return e };

    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; sole reader of its fd_table slot per `13§5`; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let file = match fdt.get(pidfd) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    let identity = match pidfd::identity_from_inode(&file.inode()) {
        Some(identity) => identity,
        None => return errno(Errno::Einval),
    };
    let target = match identity.task() {
        Some(target) => target,
        None => return errno(Errno::Esrch),
    };

    // `mm_access(task, PTRACE_MODE_READ_FSCREDS)`: reaching into a foreign
    // address space requires the same authority as reading its maps. READ
    // class, so the ATTACH-only security tail does not apply.
    if sched::ptrace_access::may_access_mode(cur, &target, sched::ptrace_access::Mode::FsCreds).is_err() {
        return errno(Errno::Eperm);
    }
    // target is a foreign task: clone_mm pins against a concurrent
    // exit/execve mm replacement on another CPU. No mm = a kernel thread or a
    // task already past its mm teardown, which `mm_access` reports as ESRCH.
    let target_mm = match target.clone_mm() { Some(mm) => mm, None => return errno(Errno::Esrch) };

    if !madvise_behavior_valid(advice) { return errno(Errno::Einval); }

    // SAFETY: running task on this CPU; mm slot single-mutator per `13§5`.
    let own_mm = unsafe { cur.mm_ref() }.map(alloc::sync::Arc::clone);
    let local = own_mm.as_ref().is_some_and(|mm| alloc::sync::Arc::ptr_eq(mm, &target_mm));
    if !local {
        if !process_madvise_remote_valid(advice) { return errno(Errno::Einval); }
        if !cur.has_cap(sched::cap::SYS_NICE) { return errno(Errno::Eperm); }
    }

    let vmas = target_mm.snapshot_vmas();
    let mut ops = LiveOps { mm: target_mm, local };
    vector_madvise(&iovs, |start, len| madvise_vmas(start, len, advice, &vmas, &mut ops))
}
