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

pub(crate) use crate::clone_abi::{
    CloneCaller, CloneRequest, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID,
    CLONE_CLEAR_SIGHAND, CLONE_FS, CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_PIDFD,
    CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, CLONE_VM,
};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `PTRACE_EVENT_VFORK_DONE`, named through the ptrace UAPI owner rather than
/// inline so the two spellings cannot drift.
fn uapi_event_vfork_done() -> u32 { crate::s101_ptrace_uapi::EVENT_VFORK_DONE }

/// Publish a tid into a user `int` that the caller nominated through one of the
/// `CLONE_*_SETTID` flags. Best-effort by contract: the address is never
/// pre-validated and a fault is swallowed, so a caller that names an
/// unwritable — or null — destination still gets its child.
/// # C: O(1)
fn put_tid_best_effort(uaddr: u64, tid: u32) {
    if uaddr == 0 { return; }
    let _ = uaccess::copy_to_user(uaddr, &(tid as i32).to_le_bytes());
}

/// Facts about the running task the shared validation ladder needs.
/// # C: O(pid-ns depth)
fn caller_facts(cur: &sched::Task) -> CloneCaller {
    CloneCaller { is_ns_init: sched::live::zombies::is_namespace_init(cur) }
}

/// `clone3` `set_tid[]` admission: every requested pid must be a usable pid
/// number, must not already name a live task in the namespace it applies to,
/// and the caller must hold the privilege that lets it pick one. Reserving the
/// number here keeps the ordinary allocator from handing the same one out
/// later.
/// # C: O(N_requested × N_tasks)
pub(crate) fn set_requested_pids_ok(requested: &[u32]) -> Result<(), Errno> {
    use namespace_identity::NamespaceKind;
    let cur = sched::live::current().ok_or(Errno::Esrch)?;
    let mut level = cur.namespace_owner(NamespaceKind::Pid).map(|ns| ns.pin());
    let mut depth = 0usize;
    while let Some(ns) = level {
        depth += 1;
        level = ns.parent();
    }
    // The child is one level deeper than the caller when it is the init of a
    // pid namespace this very call creates.
    crate::clone_abi::set_tid_values_ok(requested, depth + 1)?;
    let user_ns = cur.namespace_owner(NamespaceKind::User).ok_or(Errno::Esrch)?;
    if !nscg::proc_ns::has_cap_for(cur, &user_ns.pin(), sched::cap::SYS_ADMIN) {
        return Err(Errno::Eperm);
    }
    // A number already naming a live task in the namespace it applies to
    // cannot be handed out twice. Levels are walked outward from the caller's
    // own pid namespace, which is the one the child's innermost entry lands in
    // unless this call also creates a deeper one.
    let mut level = cur.namespace_owner(NamespaceKind::Pid);
    for pid in requested {
        let Some(here) = level else { break };
        if sched::registry::lookup_in_namespace(&here, *pid).is_some() {
            return Err(Errno::Eexist);
        }
        level = here.parent().and_then(|parent| parent.get_active());
    }
    Ok(())
}

fn user_i32_ptr_ok(p: u64) -> bool {
    p != 0 && uaccess::access_ok(p, core::mem::size_of::<i32>())
}

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
        // F157: COW fork (Linux mm/memory.c semantic). Walks parent
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
    child.set_pgid(cur.pgid());
    child.set_sid(cur.sid());
    // Inherit Linux `fs_struct`: CLONE_FS shares one owner; fork snapshots it.
    child.inherit_fs_context_from(cur, (flags & CLONE_FS) != 0);
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
    // mask is unconditionally copied (kernel/fork.c). The prior
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
    // `ContextAArch64::tpidr`. Linux `arch/arm64/kernel/process.c` `copy_thread`:
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
    publication::commit(&child, (flags & CLONE_THREAD) != 0, prepared_pidfd);

    // Linux `_do_fork`: "forking complete and child started to run, tell
    // ptracer" — the fork/vfork/clone event stop is reported AFTER
    // `wake_up_new_task`, so a tracer that resumes us on the event finds the
    // child already alive and already stopped at its own attach point.
    if let Some(ev) = traced_event { crate::ptrace::stop::ptrace_event(ev, child_event_msg); }

    // F156: CLONE_VFORK suspension. Linux semantic — parent blocks
    // until child execve(2)s or _exit(2)s. With CLONE_VM the two
    // share the address space, so without this the parent races on
    // shared heap/stack and may modify state the child is reading.
    // The child was armed before publication; park the parent until it
    // clears. Wake sites:
    //   - sys_execve: after CLOEXEC drop, before SP setup.
    //   - sys_exit / sys_exit_group: alongside mark_done.
    if (flags & CLONE_VFORK) != 0 {
        // Hold the Arc<child> across the yield loop so the child's
        // task struct stays alive even if it Zombies + parks before
        // we re-acquire CPU. Zombies-park doesn't free; just releases
        // the runqueue Arc.
        let watch = alloc::sync::Arc::clone(&child);
        drop(child);
        // PARK (Sleeping) until the child clears vfork_pending — do NOT
        // busy-yield. A busy-yield keeps the parent Runnable, so on UP the
        // scheduler re-picks it forever and NO other task runs; a vfork child
        // that blocks in a syscall (never reaching exec/exit) then deadlocks
        // the whole system with IRQs off (dead timer, no watchdog). The
        // child's departure sites (execve/exit/signal-death via `vfork_done`)
        // wake us. set-Sleeping-then-recheck closes the lost-wakeup race: if
        // the child clears+wakes between the recheck and schedule(), the wake
        // CASes us back Runnable and schedule() just re-picks us to re-loop.
        loop {
            cur.set_state(sched::TaskState::Sleeping);
            if !watch.vfork_pending.load(Ordering::Acquire) {
                cur.set_state(sched::TaskState::Runnable);
                break;
            }
            // SAFETY: process ctx; preempt-off; runqueue installed; self is
            // Sleeping so schedule() switches away without re-enqueueing us.
            unsafe { sched::live::schedule(); }
        }
        drop(watch);
        // Linux `if (!wait_for_vfork_done(p, &vfork)) ptrace_event_pid(
        // PTRACE_EVENT_VFORK_DONE, pid)`: the parent reports a SECOND event
        // once the child released it, so a tracer can tell "vfork issued" from
        // "vfork's address-space borrow is over".
        crate::ptrace::stop::ptrace_event(uapi_event_vfork_done(), child_event_msg);
    } else {
        // Drop our local Arc; runqueue's enqueue clone keeps the
        // child alive until it Zombies + parks.
        drop(child);
    }

    // Return the child's vpid to the parent (Linux: clone/fork returns the
    // child's TID == its PID for a new process). vtid==vtgid for a forked
    // process; for a thread it's the thread's vtid. This is the SAME value
    // the child's getpid()/gettid() report and that waitpid()/kill() take —
    // ONE pid identity. (The internal tid stays a kernel-only registry key.)
    child_vpid_ret as i64
}

/// x86_64 fork-spawn: capture parent's saved-syscall regs from the
/// per-task syscall stack, build the child's iretq-resume frame.
#[cfg(target_arch = "x86_64")]
fn clone_spawn_arch(
    child_tid: u32,
    child_stack: u64,
    child_mm: alloc::sync::Arc<vmm::AddressSpace>,
    thread_group: Option<alloc::sync::Arc<sched::thread_group::ThreadGroup>>,
) -> Result<alloc::sync::Arc<sched::Task>, sched::live::spawn::SpawnError> {
    let regs = hal_x86_64::current_pt_regs();
    if regs.is_null() { return Err(sched::live::spawn::SpawnError::NoRunqueue); }
    // SAFETY: we are running on the parent's per-task syscall stack; current_pt_regs() is its live entry frame; we read but do not write.
    let frame = unsafe { &*regs };
    let user_rip = frame.rip;
    let user_rflags = frame.rflags;
    // Thread spawns pass a libc-allocated stack via clone()/clone3();
    // honor it so each thread has its own user stack rather than
    // racing on the parent's. fork(2) leaves child_stack=0 and the
    // child resumes on the parent's RSP after the COW copy.
    let user_rsp = if child_stack != 0 { child_stack } else { frame.rsp };
    let pregs = hal_x86_64::ForkRegs {
        rdi: frame.rdi, rsi: frame.rsi, rdx: frame.rdx,
        r10: frame.r10, r8:  frame.r8,  r9:  frame.r9,
        rcx: frame.rcx, r11: frame.r11,
        r12: frame.r12,
        rbx: frame.rbx, rbp: frame.rbp,
        r13: frame.r13, r14: frame.r14, r15: frame.r15,
    };
    sched::cputime_trace::clone_frame(child_tid, user_rip, user_rsp, user_rflags);
    // SAFETY: runqueue installed by elf_smoke; child_mm freshly forked from parent AS w/ kernel-half cloned per P2-19; user_rip/rflags/rsp + pregs captured from parent's saved syscall stack.
    unsafe {
        sched::live::spawn_user_thread_for_fork(
            child_tid, "fork-child", user_rip, user_rsp, user_rflags,
            &pregs, child_mm, thread_group,
        )
    }
}

/// aarch64 fork-spawn: read parent's saved SVC frame, snapshot
/// x0..x30 + ELR/SPSR/SP_EL0 into a `hal_aarch64::ForkRegs`, then
/// build the child's IRQ-resume frame via `new_user_for_fork`.
#[cfg(target_arch = "aarch64")]
fn clone_spawn_arch(
    child_tid: u32,
    child_stack: u64,
    child_mm: alloc::sync::Arc<vmm::AddressSpace>,
    thread_group: Option<alloc::sync::Arc<sched::thread_group::ThreadGroup>>,
) -> Result<alloc::sync::Arc<sched::Task>, sched::live::spawn::SpawnError> {
    // SAFETY: the task-owned pointer remains tied to this parent even if clone
    // blocked and another task entered SVC on the same CPU.
    let svc = unsafe { &*crate::arch_frame::current_svc_frame() };
    let mut pregs = hal_aarch64::ForkRegs::default();
    // SvcFrame.gp = [u64; 18]   (x0..x17)
    // SvcFrame.x18_x29 = [u64; 2]  ([x18, x29] packed via stp)
    // SvcFrame.x30 = u64
    for i in 0..18 { pregs.x[i] = svc.gp[i]; }
    pregs.x[18] = svc.x18_x29[0];
    pregs.x[29] = svc.x18_x29[1];
    pregs.x[30] = svc.x30;
    pregs.elr_el1  = svc.elr_el1;
    pregs.spsr_el1 = svc.spsr_el1;
    pregs.sp_el0   = svc.sp_el0;
    // Callee-saved x19..x28 are now saved by the SVC entry asm into
    // svc.x19_x28[0..10]. Copy through to the child's ForkRegs so
    // the child resumes with the parent's full callee-saved state.
    for i in 0..10 { pregs.x[19 + i] = svc.x19_x28[i]; }

    // fork(2): child_stack=0 → child resumes on parent's SP_EL0.
    // clone(2) with child_stack: child resumes on the supplied stack.
    let user_sp = if child_stack != 0 { child_stack } else { pregs.sp_el0 };
    // ELR_EL1 in the saved frame is already the post-SVC PC (the
    // instruction following `svc #0`), so the child resumes there
    // with x0 = 0 (Linux clone return for child).
    let user_ip = pregs.elr_el1;

    sched::cputime_trace::clone_frame(child_tid, user_ip, user_sp, pregs.spsr_el1);
    // SAFETY: runqueue installed; child_mm freshly forked from parent AS via fork_copy_pages w/ kernel-half cloned at new_user_l0; pregs captured from parent's SVC frame.
    unsafe {
        sched::live::spawn_user_thread_for_fork(
            child_tid, "fork-child", user_ip, user_sp, &pregs, child_mm,
            thread_group,
        )
    }
}
