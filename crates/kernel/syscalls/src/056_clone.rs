// Unified clone dispatch (sys_clone_dispatch) extracted from
// syscall_glue.rs to keep that file under the 1000-line cap. Drives
// fork/vfork/clone/clone3 — see body for honored CLONE_* flag bits.
// Module manifest:
// - namespaces: task namespace inheritance and clone-time publication.
// - io_context: CLONE_IO sharing of the I/O priority context.

#![cfg(target_os = "oxide-kernel")]
use syscall::errno::Errno;
#[path = "056_clone/namespaces.rs"]
mod namespaces;
#[path = "056_clone/publication.rs"]
mod publication;
#[path = "056_clone/fd_table.rs"]
mod fd_table;
#[path = "056_clone/io_context.rs"]
mod io_context;
#[path = "056_clone/request.rs"]
mod request;
#[path = "056_clone/arch_spawn.rs"]
mod arch_spawn;

use arch_spawn::clone_spawn_arch;
use request::{caller_facts, errno, put_tid_best_effort, user_i32_ptr_ok};
pub(crate) use request::set_requested_pids_ok;
pub(crate) use crate::clone_abi::{
    CloneRequest, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID,
    CLONE_CLEAR_SIGHAND, CLONE_FS, CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_PIDFD,
    CLONE_SETTLS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VFORK, CLONE_VM,
};
/// `sys_clone_dispatch` — unified clone path for fork/vfork/
/// clone/clone3. `flags` carries the Linux CLONE_* bitmap; the lowest
/// 8 bits are the exit_signal (SIGCHLD = 17 for fork). `child_stack`
/// is non-zero for thread spawns (libc-allocated user stack); `ptid`
/// + `ctid` are user pointers honored by CLONE_PARENT_SETTID /
/// CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID.
///
/// # C: O(parent VMAs) for COW; O(1) for CLONE_VM
pub fn sys_clone_dispatch(req: CloneRequest<'_>) -> i64 {
    use core::sync::atomic::Ordering;
    let CloneRequest { flags, exit_signal, child_stack, parent_tid: ptid, pidfd: pidfd_ptr,
                       child_tid: ctid, tls, into_cgroup: into_cgid, set_tid } = req;
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return errno(Errno::Einval),
    };
    if let Err(e) = crate::clone_abi::validate_clone(
        flags, exit_signal, caller_facts(cur), req.pidfd_aliases_parent_tid())
    {
        return errno(e);
    }
    if let Err(e) = crate::clone_abi::clone_dest_ok(flags, user_i32_ptr_ok(pidfd_ptr)) {
        return errno(e);
    }
    let _exec_guard = match publication::exec_guard(cur, (flags & CLONE_THREAD) != 0) {
        Ok(guard) => guard, Err(e) => return errno(e),
    };
    // SAFETY: we are the running task on this CPU; no concurrent writer to our mm; preempt-off through the syscall handler.
    let parent_mm = match unsafe { cur.mm_ref() } {
        Some(m) => m,
        None    => return errno(Errno::Einval),
    };
    // cgroup v2 pids controller (`26§4`): a fork/clone producing one more
    // TASK past an ancestor pids.max fails with EAGAIN (Linux
    // pids_can_fork). The pids controller counts threads too, so this gates
    // CLONE_THREAD as well, resolved against the process's cgroup (tgid).
    {
        let proc_pid = cur.tgid.load(core::sync::atomic::Ordering::Relaxed) as u64;
        let exceeds = match into_cgid {
            Some(cg) if (flags & CLONE_THREAD) == 0 => cgroup::fork_would_exceed_cgroup(cg),
            _ => cgroup::fork_would_exceed_pids(proc_pid),
        };
        if exceeds {
            return errno(Errno::Eagain);
        }
    }
    let share_vm = (flags & CLONE_VM) != 0;
    let child_mm: alloc::sync::Arc<vmm::AddressSpace> = if share_vm {
        // CLONE_VM: child shares parent's address space; no PT root
        // alloc, no per-page copy. Threads land here.
        alloc::sync::Arc::clone(parent_mm)
    } else {
        #[cfg(target_arch = "x86_64")]
        let new_root = {
            // SAFETY: capture_kernel_master ran at pmm::user_as::init; PMM up.
            match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
                Some(r) => r,
                None    => return errno(Errno::Enomem),
            }
        };
        #[cfg(target_arch = "aarch64")]
        let new_root = {
            // SAFETY: master L0 captured at pmm::user_as::init; PMM up; new_user_l0 zeroes + populates kernel half.
            match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
                Some(r) => r,
                None    => return errno(Errno::Enomem),
            }
        };
        let hhdm = pmm::user_as::hhdm_offset();
        // F157: COW fork (Linux's fork-time page-table COW semantic). Walks parent
        // PT, bumps struct-page refcount via inc_ref, maps same PA
        // RO in child + remaps parent RO. First write on either
        // side triggers handle_page_fault_cow which copies+splits.
        // TEST (debug-eager-fork): copy every page into a fresh private frame
        // instead of COW-sharing — eliminates ALL parent/child frame sharing.
        // If the garbage corruption vanishes under this, the bug is in COW page
        // sharing (a shared frame mapped writable); if not, fork is exonerated.
        #[cfg(all(target_arch = "x86_64", feature = "debug-eager-fork"))]
        let res = parent_mm.fork_copy_pages::<hal_x86_64::mmu_ops::X86Mmu, _>(
            new_root, hhdm, pmm::setup::alloc_one_frame);
        #[cfg(all(target_arch = "x86_64", not(feature = "debug-eager-fork")))]
        let res = loop {
            let parked = core::cell::Cell::new(false);
            let draining_swap = core::cell::Cell::new(None);
            let attempt = parent_mm.fork_cow_pages_with_swap::<hal_x86_64::mmu_ops::X86Mmu, _, _, _, _>(
                new_root, hhdm,
                // SAFETY: pa is a current PMM-allocated frame mapped in parent's PT; inc_ref bumps the per-page refcount.
                |pa| unsafe { pmm::setup::inc_ref(pa); },
                |va, entry| match pmm::swap::retain_page(entry) {
                    Ok(()) => Ok(()),
                    Err(pmm::swap::SwapError::Busy) => {
                        draining_swap.set(Some((va, entry)));
                        Err(vmm::Error::Again)
                    }
                    Err(_) => Err(vmm::Error::NoMem),
                },
                |entry| { let _ = pmm::swap::free_page(entry); },
                |marker| { parked.set(true); sched::live::migration_wait::park(marker.token()); },
            );
            if matches!(attempt, Err(vmm::Error::Again)) {
                if let Some((va, entry)) = draining_swap.get() {
                    if pmm::user_as::restore_swap_for_fork(parent_mm, va, entry).is_err() {
                        return errno(Errno::Enomem);
                    }
                    continue;
                }
                if parked.get() { sched::live::migration_wait::schedule_after_park(); }
                continue;
            }
            break attempt;
        };
        #[cfg(target_arch = "aarch64")]
        let res = loop {
            let parked = core::cell::Cell::new(false);
            let draining_swap = core::cell::Cell::new(None);
            let attempt = parent_mm.fork_cow_pages_with_swap::<hal_aarch64::mmu_ops::ArmMmu, _, _, _, _>(
                new_root, hhdm,
                // SAFETY: pa is a current PMM-allocated frame mapped in parent's PT; inc_ref bumps the per-page refcount.
                |pa| unsafe { pmm::setup::inc_ref(pa); },
                |va, entry| match pmm::swap::retain_page(entry) {
                    Ok(()) => Ok(()),
                    Err(pmm::swap::SwapError::Busy) => {
                        draining_swap.set(Some((va, entry)));
                        Err(vmm::Error::Again)
                    }
                    Err(_) => Err(vmm::Error::NoMem),
                },
                |entry| { let _ = pmm::swap::free_page(entry); },
                |marker| { parked.set(true); sched::live::migration_wait::park(marker.token()); },
            );
            if matches!(attempt, Err(vmm::Error::Again)) {
                if let Some((va, entry)) = draining_swap.get() {
                    if pmm::user_as::restore_swap_for_fork(parent_mm, va, entry).is_err() {
                        return errno(Errno::Enomem);
                    }
                    continue;
                }
                if parked.get() { sched::live::migration_wait::schedule_after_park(); }
                continue;
            }
            break attempt;
        };
        match res {
            Ok(m) => {
                pmm::user_as::install_teardown(&m);
                m
            }
            Err(_) => return errno(Errno::Enomem),
        }
    };
    let child_tid = sched::live::next_tid();
    let thread_group = if (flags & CLONE_THREAD) != 0 {
        Some(alloc::sync::Arc::clone(&cur.thread_group))
    } else {
        None
    };
    let spawn = clone_spawn_arch(child_tid, child_stack, child_mm, thread_group);
    let child = match spawn {
        Ok(t)  => t,
        // A `SCHED_DEADLINE` parent cannot fork: the child would inherit an
        // admitted bandwidth reservation that was granted to exactly one task.
        Err(sched::live::spawn::SpawnError::Again) => return errno(Errno::Eagain),
        Err(_) => return errno(Errno::Enomem),
    };
    // The child cannot run yet, so charge the concrete stack to the cgroup it
    // will enter. The Task retains this allocating owner until final release.
    let stack_memcg = if (flags & CLONE_THREAD) != 0 {
        cgroup::cgroup_of(cur.tgid.load(Ordering::Acquire) as u64)
    } else {
        into_cgid.unwrap_or_else(|| cgroup::cgroup_of(cur.tid as u64))
    };
    if !child.try_charge_kernel_stack(stack_memcg) { return errno(Errno::Enomem); }
    child.exit_signal.store(exit_signal as u8, Ordering::Release);
    // CLONE_THREAD: the new task joins the caller's thread group.
    // Without it the child is its own process leader and tgid==tid.
    if (flags & CLONE_THREAD) != 0 {
        child.tgid.store(cur.tgid.load(Ordering::Acquire), Ordering::Release);
        // Every thread of a process shares ONE visible PID (Linux: getpid()
        // returns the tgid for all threads; SO_PEERCRED and /proc/<pid> use
        // that same value). `spawn_user_thread_for_fork` stamped a fresh
        // vtgid/vtid pair; keep the distinct vtid (== gettid()) but overwrite
        // vtgid with the group leader's so the thread reports the PROCESS pid.
        // Without this each thread carried its own vpid, so a D-Bus call made
        // from a worker thread reported a pid whose /proc/<pid>/cgroup was the
        // root cgroup (that pid was never placed in a cgroup) — logind's
        // GetSessionByPID then returned NoSessionForPID and GNOME never logged
        // in.
        child.vtgid.store(cur.vtgid.load(Ordering::Acquire), Ordering::Release);
    } else {
        // Linux `copy_signal` -> `tty_audit_fork`: a NEW thread group inherits
        // the parent's terminal-audit mask, and only the mask. A CLONE_THREAD
        // child shares the parent's group and therefore its state already, so
        // it takes this path only when a real process was created. Auditing a
        // login shell without this would record nothing the shell ran.
        fs::tty_audit::on_fork(cur, child.visible_pid());
    }
    let prepared_pidfd = match publication::prepare_pidfd(cur, &child, flags, pidfd_ptr) {
        Ok(prepared) => prepared,
        Err(error) => return error,
    };
    // Record parent_tid for wait ownership. CLONE_PARENT makes the child a
    // sibling of the caller: its wait parent is the caller's parent.
    let wait_parent_tid = if (flags & CLONE_PARENT) != 0 {
        cur.parent_tid.load(Ordering::Acquire)
    } else { cur.tid };
    child.parent_tid.store(wait_parent_tid, Ordering::Release);
    // cgroup v2 (`26§4`): a forked process inherits the parent's cgroup
    // (Linux cgroup_post_fork); a new thread charges the process's cgroup
    // so pids.current counts it.
    if (flags & CLONE_THREAD) == 0 {
        if let Some(error) = crate::clone_cgroup::attach_new_process(into_cgid, child_tid as u64, cur.tid as u64) { return error; }
    } else {
        let proc_pid = cur.tgid.load(core::sync::atomic::Ordering::Relaxed) as u64;
        cgroup::charge_thread(proc_pid, child_tid as u64);
    }
    // Inherit parent's pgid + sid per POSIX fork(2). setpgid/setsid in
    // child override later. Without inheritance every fork would land
    // in its own pgrp and shells couldn't track job state.
    child.set_pgrp(cur.pgrp());
    child.set_session(cur.session());
    child.inherit_audit_identity(cur);
    // Inherit Linux `fs_struct`: CLONE_FS shares one owner; fork snapshots it.
    child.inherit_fs_context_from(cur, (flags & CLONE_FS) != 0);
    // Linux `copy_semundo`. CLONE_SYSVSEM shares the SysV `SEM_UNDO` adjustment
    // list by reference, and it is a flag in its OWN right — not a consequence
    // of CLONE_THREAD. A plain fork(2) child must start with no list, or it
    // would hand back adjustments its parent still owes; a
    // clone(CLONE_SYSVSEM) child WITHOUT CLONE_THREAD must share the parent's,
    // or each would undo the other's operations at its own exit.
    if let Err(e) = ipc::sysv::sem::undo::copy_semundo(
        (flags & CLONE_SYSVSEM) != 0, &cur.sysvsem_undo, &child.sysvsem_undo)
    {
        return errno(e);
    }
    // Inherit rlimits and ctty per POSIX fork(2). child is unpublished and
    // therefore the sole writer to child's own slots; cur's rlimits read
    // goes through the lock since cur is a real, possibly-foreign-observed
    // task (prlimit64/sched_setattr can target it from another CPU).
    child.set_all_rlimits(cur.all_rlimits());
    // F200: ctty inherits across fork(2) per POSIX §11.1.3. A CLONE_THREAD
    // child SHARES the parent's thread group and therefore already sees the
    // same terminal, so this only ever seeds a freshly forked process.
    child.set_ctty(cur.ctty());
    // umask lives on the shared `fs_struct` owner (Linux) — `inherit_fs_context_from`
    // already shares it for CLONE_FS and snapshot-copies it otherwise.
    // Linux `dup_task_struct` copies `task_struct::personality` wholesale, so a
    // process that set PER_LINUX32/ADDR_NO_RANDOMIZE/READ_IMPLIES_EXEC keeps it
    // across fork; only `execve` re-derives it. Without this every child came up
    // at PER_LINUX and `personality(0xffffffff)` in a forked child reported the
    // wrong persona.
    child.personality.store(cur.personality.load(Ordering::Acquire), Ordering::Release);
    // Linux `rseq_fork`: a CLONE_VM child (a thread) starts unregistered and
    // its libc registers a fresh area; a non-CLONE_VM child (fork) INHERITS
    // the registration, because its copied address space still holds the same
    // `struct rseq` at the same address and its libc will not re-register.
    // Dropping the inheritance leaves a forked child whose user space
    // believes rseq is live while the kernel neither publishes ids nor aborts
    // critical sections — the exact silent-corruption shape rseq exists to
    // prevent. `Task::new` already left the CLONE_VM case cleared.
    if !share_vm {
        child.rseq_ptr.store(cur.rseq_ptr.load(Ordering::Acquire), Ordering::Release);
        child.rseq_len.store(cur.rseq_len.load(Ordering::Acquire), Ordering::Release);
        child.rseq_sig.store(cur.rseq_sig.load(Ordering::Acquire), Ordering::Release);
        child.rseq_slice_enabled.store(cur.rseq_slice_enabled.load(Ordering::Acquire), Ordering::Release);
    }
    // The number to return to the parent: the child's pid AS THE CALLER'S pid
    // namespace numbers it, which is not the child's own number whenever this
    // call put the child in a deeper namespace. Captured now, before the
    // `child` Arc may be dropped at the end.
    let child_vpid_ret = match namespaces::inherit_and_publish(cur, &child, flags, set_tid) {
        Ok(nr) => nr,
        Err(e) => return errno(e),
    };
    // Linux `copy_creds` charges the new task to its account, then
    // `copy_process` decides on the resulting count — the task being admitted
    // is INSIDE the number it is judged against, which is what makes the
    // limit a ceiling on live tasks rather than on tasks-plus-one. Runs after
    // the namespace publication above because the account is keyed on the
    // child's user namespace, which that call installs.
    sched::ucounts::charge_task(&child);
    if !sched::ucounts::fork_admits(&child, cur) {
        sched::ucounts::uncharge_task(&child);
        return errno(Errno::Eagain);
    }
    // Parent Weak<Task> for `park_zombie` SIGCHLD delivery. CLONE_PARENT
    // inherits the caller's parent link; otherwise the caller becomes parent.
    if (flags & CLONE_PARENT) != 0 {
        child.set_parent_weak(cur.parent_weak());
    } else if let Some(rq) = sched::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw in `Runqueue::new` / `swap_current`; bumping the strong count is sound because the conceptual Arc held by current is alive while we run on it.
            unsafe { alloc::sync::Arc::increment_strong_count(raw); }
            // SAFETY: matching from_raw consumes the bumped count.
            let parent_arc = unsafe { alloc::sync::Arc::from_raw(raw) };
            child.set_parent_weak(Some(alloc::sync::Arc::downgrade(&parent_arc)));
        }
    }
    fd_table::inherit(cur, &child, flags);
    io_context::inherit(cur, &child, flags);

    let child_sigactions = if (flags & CLONE_CLEAR_SIGHAND) != 0 {
        alloc::sync::Arc::new(sched::SigActions::new())
    } else if (flags & CLONE_SIGHAND) != 0 {
        cur.sigactions_arc()
    } else {
        alloc::sync::Arc::new(cur.sigactions_ref().fork_clone())
    };
    // SAFETY: child is not scheduled yet; clone path is sole mutator of its task slots.
    unsafe { child.replace_sigactions(child_sigactions); }
    // F205: ALWAYS inherit sigmask on clone/fork, regardless of
    // CLONE_SIGHAND. Per POSIX fork(2) "process signal mask" is in
    // the unconditional-inherit list; per Linux copy_thread() the
    // mask is unconditionally copied. The prior
    // CLONE_SIGHAND-only condition meant that musl's `fork() →
    // __block_all_sigs() → _Fork() → __restore_sigs(saved=...)`
    // chain corrupted the child's mask: child started at 0, the
    // first __restore_sigs read the inherited save buffer (=
    // blocked-app) and SET mask to blocked-app — not the prior
    // mask the parent saw, but the snapshot the parent captured
    // INSIDE its critical section. Subsequent restore_sigs cycles
    // propagated that wrong value down through the child's
    // lifetime, leaving SIGCHLD permanently in the mask for
    // dropbear-aarch64 and breaking the SSH channel-close path.
    child.sigmask.store(cur.sigmask.load(Ordering::Acquire), Ordering::Release);
    // CLONE_PARENT_SETTID: write child tid in caller's AS.
    if (flags & CLONE_PARENT_SETTID) != 0 {
        // The child's TID as userspace numbers it (the vtid), not the opaque
        // internal one. The child already exists at this point, so a store that
        // faults cannot un-create it and must not fail the call.
        put_tid_best_effort(ptid, child.vtid.load(Ordering::Acquire));
    }
    // CLONE_CHILD_SETTID writes the child's TID into the CHILD's address
    // space. Only a CLONE_VM child shares the caller's page tables, so the
    // write can be done here; a forked child's copy of that page is
    // COW-mapped read-only and belongs to a page-table root this CPU is not
    // running on. The write is therefore recorded on the child and performed
    // by the child itself at its first return to user mode, where the store
    // takes an ordinary COW fault in the right address space.
    //
    // This is not cosmetic: a C library caches its thread id in the thread
    // control block and populates it through exactly this flag on every
    // `fork()`. Dropping the write left a forked child holding its PARENT's
    // thread id, so `raise()`/`abort()` in the child — which target
    // (own pid, cached tid) — addressed a thread that does not exist in the
    // child's thread group.
    if (flags & CLONE_CHILD_SETTID) != 0 {
        if (flags & CLONE_VM) != 0 {
            // The address space is shared, so the store lands in the child's
            // mapping and can be made from here.
            put_tid_best_effort(ctid, child.vtid.load(Ordering::Acquire));
        } else {
            child.set_child_tid.store(ctid, Ordering::Release);
        }
    }
    // CLONE_CHILD_CLEARTID: stash for thread-exit FUTEX_WAKE path.
    if (flags & CLONE_CHILD_CLEARTID) != 0 {
        child.clear_child_tid.store(ctid, Ordering::Release);
    }
    // CLONE_SETTLS: x86_64 stores TLS in FS_BASE; child resumes
    // with this base via wrmsr at iretq-prep. F242: wire it up
    // so pthread's per-thread FS_BASE is correct — pthread_self()
    // in the child returns the child's pthread struct (not the
    // parent's), which is required for pthread_join's
    // detach_state futex sync.
    #[cfg(target_arch = "x86_64")]
    if (flags & CLONE_SETTLS) != 0 {
        // SAFETY: child task not yet scheduled; sole writer to arch_ctx.
        unsafe {
            let p: *mut hal_x86_64::ContextX86_64 = child.arch_ctx_ptr();
            (*p).fs_base = tls;
        }
    }
    // aarch64 stores it in TPIDR_EL0, which `switch_to`'s asm restores from
    // `ContextAArch64::tpidr`. Linux's aarch64 `copy_thread`:
    // `if (clone_flags & CLONE_SETTLS) p->thread.uw.tp_value = tls;`, applied by
    // `tls_thread_switch()`.
    //
    // This arm did not exist: the tls argument was discarded on aarch64 and the
    // child kept the value `spawn_user_thread_for_fork` copied from the PARENT's
    // live TPIDR_EL0. Every `pthread_create`d thread therefore ran on the main
    // thread's thread pointer, so `pthread_self()`, `errno` and every `__thread`
    // variable in a worker resolved to the main thread's storage. Caught by
    // `wait_diff`'s `groupsig|handler_runs_in_unblocked_thread`: the row's
    // `gettid()` said the SIGUSR1 handler ran on the sibling while
    // `pthread_self()` insisted it was the main thread (`tls_agrees=0`), which
    // is exactly the shape of a shared thread pointer.
    #[cfg(target_arch = "aarch64")]
    if (flags & CLONE_SETTLS) != 0 {
        // SAFETY: child task not yet scheduled; sole writer to its arch_ctx.
        unsafe {
            let p: *mut hal_aarch64::ContextAArch64 = child.arch_ctx_ptr();
            (*p).tpidr = tls;
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = (tls, CLONE_SETTLS);

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_clone: parent_tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" child_tid=");
        klog::write_dec_u64(child_tid as u64);
        klog::write_raw(b" flags=");
        klog::write_hex_u64(flags);
        klog::write_raw(b"\n");
    }

    // Arm the vfork completion before publication. The child can run as soon
    // as publication commits it; arming afterwards loses a fast exec/exit and
    // can leave the parent parked forever on a completion that already ran.
    if (flags & CLONE_VFORK) != 0 {
        child.vfork_pending.store(true, Ordering::Release);
    }

    // Linux `copy_process(..., trace, ...)` -> `ptrace_init_task`: decide the
    // event BEFORE publication and auto-attach the child to the same tracer,
    // so a child that runs the instant it is published is already linked and
    // already destined to stop. Deciding after publication would race a fast
    // child past its own attach point.
    let traced_event = crate::s101_ptrace_event::clone_event_reported(
        flags, exit_signal as u64, cur.traced_by.load(Ordering::Acquire) != 0,
        cur.ptrace_options.load(Ordering::Acquire));
    crate::ptrace::stop::init_task(cur, &child, traced_event);
    // The message `PTRACE_GETEVENTMSG` reports for a fork/vfork/clone event is
    // the CHILD's pid as the tracer's pid namespace numbers it.
    let child_event_msg = child.vtid.load(Ordering::Acquire) as u64;

    // Linux `wake_up_new_task`: the child is now fully built — vtgid, fd
    // table, sigmask, CLONE_SETTLS FS_BASE, and the set_child_tid writes are
    // all final. ONLY now make it schedulable, so no CPU (SMP) can pick it up
    // and run its glibc thread-start trampoline with the parent's stale
    // FS_BASE / an unfinished vtgid (which aliased the creator's TLS and made
    // GCond signals target the wrong futex word — the greeter/SMP wedge).
    // Linux `copy_creds`: the child's cred is a copy of the parent's, so it
    // starts out sharing the session keyring and the `jit_keyring` default.
    // Unconditional on the flags — a new thread and a new process copy the same
    // two fields; what differs (thread keyring dropped, process keyring kept
    // only within a thread group) is already expressed by the store's tid/tgid
    // keying. Must run BEFORE publication, or a child scheduled immediately can
    // observe a keyring-less cred it is supposed to have inherited.
    fs::keyring::fork_keys(cur.tid, child_tid);
    // Linux `perf_event_init_task` → `inherit_task_group`: every
    // `attr.inherit` task-scoped perf event the parent has open gets a clone
    // targeting the child, so a later read of the parent's fd folds in
    // whatever the child counts before it exits (`fold_into_parent` at
    // `sys_exit`/`do_exit`). Must run before publication like the keyring
    // copy above — the child must already carry its events the instant it
    // becomes schedulable.
    fs::perf::inherit::on_fork(cur.tid, child_tid, (flags & CLONE_THREAD) != 0);
    // `perf_event_fork(child)`: the side-band record that tells a consumer the
    // new thread exists, so samples carrying its tid can be attributed.
    crate::perf_sideband::note_fork(child_tid, child.tgid.load(Ordering::Relaxed),
                                    cur.tid, cur.tgid.load(Ordering::Relaxed));
    publication::commit(&child, (flags & CLONE_THREAD) != 0, prepared_pidfd);

    // Linux `_do_fork`: "forking complete and child started to run, tell
    // ptracer" — the fork/vfork/clone event stop is reported AFTER
    // `wake_up_new_task`, so a tracer that resumes us on the event finds the
    // child already alive and already stopped at its own attach point.
    if let Some(ev) = traced_event { crate::ptrace::stop::ptrace_event(ev, child_event_msg); }

    publication::finish(child, (flags & CLONE_VFORK) != 0, child_event_msg);

    // Return the child's vpid to the parent (Linux: clone/fork returns the
    // child's TID == its PID for a new process). vtid==vtgid for a forked
    // process; for a thread it's the thread's vtid. This is the SAME value
    // the child's getpid()/gettid() report and that waitpid()/kill() take —
    // ONE pid identity. (The internal tid stays a kernel-only registry key.)
    child_vpid_ret as i64
}
