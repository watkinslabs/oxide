// 448 process_mrelease — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use sched::Task;
use crate::misc::misc_common::errno;
use crate::process_mrelease::{disposition, task_will_free_mem, Disposition, ExitState};

/// Read one task's `__task_will_free_mem` inputs.
///
/// `coredumping` is always false: nothing here writes a core dump on the way
/// out, so the "dying but asleep in the dumper" state the kernel guards
/// against cannot occur. `Zombie` is this kernel's `PF_EXITING` — a task past
/// its own exit path.
fn exit_state(t: &Task) -> ExitState {
    ExitState {
        coredumping: false,
        group_exit: t.thread_group.group_exit_status().is_some(),
        thread_group_empty: t.thread_group.is_single_member(),
        exiting: t.state() == sched::task::TaskState::Zombie,
    }
}

/// `find_lock_task_mm` — during a group exit the thread the pidfd names may
/// already have dropped its mm while a sibling still holds it, so the reap
/// target is the first thread of the group that still has one.
fn find_task_mm(target: &Arc<Task>, tasks: &[Arc<Task>]) -> Option<(Arc<Task>, Arc<vmm::AddressSpace>)> {
    if let Some(mm) = target.clone_mm() { return Some((Arc::clone(target), mm)); }
    let tgid = target.tgid.load(core::sync::atomic::Ordering::Acquire);
    tasks.iter()
        .filter(|t| t.tgid.load(core::sync::atomic::Ordering::Acquire) == tgid)
        .find_map(|t| t.clone_mm().map(|mm| (Arc::clone(t), mm)))
}

/// `process_mrelease(pidfd, flags)` — slot 448.
///
/// Releases the anonymous memory of a DYING process early, so a killer does
/// not have to wait for the victim to be scheduled before the memory comes
/// back. The pidfd is the whole authority — there is no separate permission
/// check — which is why the "is it really dying" ladder carries all the
/// safety: a live target, or one whose mm another live process still shares,
/// is refused.
///
/// The mm is NOT detached. Detaching it would leave the dying task with a null
/// page-table root, which the context switch reads as a kernel thread and so
/// keeps the previous root — a user task could then return to user mode
/// against another process's address space. Reaping in place avoids that
/// entirely, and file-backed pages are left alone because they are
/// reclaimable from their backing store.
/// # C: O(N_tasks + target_mm anon pages)
pub fn sys_process_mrelease(args: &SyscallArgs) -> i64 {
    let pidfd = args.a0 as i32;
    let flags = args.a1;

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

    let tasks = sched::registry::try_snapshot().unwrap_or_default();
    // `find_lock_task_mm` returning NULL is ESRCH: the whole group is already
    // past its mm teardown, so there is nothing left to release.
    let Some((holder, mm)) = find_task_mm(&target, &tasks) else { return errno(Errno::Esrch) };

    // Tasks sharing this mm from OUTSIDE the holder's thread group (CLONE_VM
    // without CLONE_THREAD). Same-group threads are already accounted for by
    // the holder's own group-exit state.
    let tgid = holder.tgid.load(core::sync::atomic::Ordering::Acquire);
    let sharers: Vec<ExitState> = tasks.iter()
        .filter(|t| t.tgid.load(core::sync::atomic::Ordering::Acquire) != tgid)
        .filter(|t| t.clone_mm().is_some_and(|other| Arc::ptr_eq(&other, &mm)))
        .map(|t| exit_state(t))
        .collect();
    // `mm_users`: this mm's holder plus every outside sharer.
    let mm_users = 1 + sharers.len() as u64;
    let oom_skip = mm.oom_skip();
    let will_free = task_will_free_mem(exit_state(&holder), oom_skip, mm_users, &sharers);

    match disposition(will_free, oom_skip) {
        Disposition::Refuse(e) => return errno(e),
        Disposition::AlreadyDrained => return 0,
        Disposition::Reap => {}
    }

    // The target has been killed but has NOT necessarily left its CPU, and its
    // siblings may still be running, so the foreign-root evictor invalidates
    // every CPU in the mm's cpumask before releasing a frame.
    let guard = mm.vmas_for_test();
    for vma in guard.iter() {
        if matches!(vma.backing, vmm::VmaBacking::Anonymous) {
            let start = vma.start.as_u64();
            let len = vma.end.as_u64().saturating_sub(start);
            if len != 0 { pmm::user_as::evict_foreign_pages_in_range(&mm, start, len); }
        }
    }
    drop(guard);
    mm.set_oom_skip();
    0
}
