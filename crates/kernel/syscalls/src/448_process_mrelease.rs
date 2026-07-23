// 448 process_mrelease — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

// SIGKILL pending bit in `Task::sigpending` (Signum SIGKILL=9 → bit 8).
const SIGKILL_PENDING_BIT: u64 = 1 << 8;
// sig arg for `sig_perm_check`: mrelease carries no signal (Linux gates
// on PTRACE_MODE); 0 avoids the SIGCONT same-session bypass.
const NO_SIG: i32 = 0;

/// process_mrelease(pidfd, flags). Reclaims the address space of a
/// DYING target (pending SIGKILL or already Zombie), resolved via the
/// pidfd. Linux `process_mrelease` requires the target be exiting and
/// forbids releasing self. Returns 0 on success.
/// # C: O(target_mm pages) via AS Drop→teardown
pub fn sys_process_mrelease(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pidfd = args.a0 as i32;
    let flags = args.a1;

    // Linux: flags must be 0.
    if flags != 0 { return errno(Errno::Einval); }

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

    // Linux forbids releasing the caller's own mm.
    if target.tid == cur.tid { return errno(Errno::Einval); }

    // Require the target be exiting: pending SIGKILL OR already Zombie
    // (Linux gate: `task_will_free_mem` / signal_group_exit / PF_EXITING).
    let sigkill_pending = target.sigpending.load(Ordering::Acquire) & SIGKILL_PENDING_BIT != 0;
    let is_zombie = target.state() == sched::task::TaskState::Zombie;
    if !sigkill_pending && !is_zombie { return errno(Errno::Einval); }

    if !crate::signal::sig_perm_check(cur, &target, NO_SIG) {
        return errno(Errno::Eperm);
    }
    // target is a foreign task: clone_mm pins against a concurrent
    // exit/execve mm replacement on another CPU.
    let mm = match target.clone_mm() {
        Some(mm) => mm,
        None => return errno(Errno::Esrch),
    };

    // Reap the target's ANONYMOUS pages in place (Linux `process_mrelease`
    // → OOM-reaper `__oom_reap_task_mm`): unmap + free every anon VMA's
    // frames to reclaim memory eagerly, but LEAVE the mm attached. The
    // target still has a valid address space when it is next scheduled to
    // process the pending SIGKILL and run its own exit teardown.
    //
    // Detaching the mm (`replace_mm(None)`) would be UNSAFE: the context
    // switch treats a null root as lazy-TLB (kernel-thread) and keeps the
    // previous CR3, so a dying USER task could return to user mode against
    // the WRONG address space before it exits. In-place anon reap avoids
    // that entirely. File-backed pages are skipped (reclaimable from
    // backing store, like Linux). If the mm is already gone, Linux
    // `find_lock_task_mm` returns NULL and process_mrelease returns ESRCH.
    // SAFETY: oxide is UP (`smp cpus=0`) and the target is EXITING, so it is
    // not executing on any CPU; the foreign root the evictor walks is stable
    // for this call (target pinned via the pidfd's Arc<Task>, mm cloned).
    let root = mm.root_pa();
    let guard = mm.vmas_for_test();
    for vma in guard.iter() {
        if matches!(vma.backing, vmm::VmaBacking::Anonymous) {
            let start = vma.start.as_u64();
            let len = vma.end.as_u64().saturating_sub(start);
            if len != 0 { pmm::user_as::evict_foreign_pages_in_range(root, start, len); }
        }
    }
    0
}
