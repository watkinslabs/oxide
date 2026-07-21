// Unified clone dispatch (sys_clone_dispatch) extracted from
// syscall_glue.rs to keep that file under the 1000-line cap. Drives
// fork/vfork/clone/clone3 — see body for honored CLONE_* flag bits.
// Module manifest:
// - namespaces: task namespace inheritance and clone-time publication.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

#[path = "056_clone/namespaces.rs"]
mod namespaces;
#[path = "056_clone/publication.rs"]
mod publication;
#[path = "056_clone/fd_table.rs"]
mod fd_table;

pub(crate) const CSIGNAL:              u64 = 0xff;
pub(crate) const CLONE_VM:             u64 = 0x100;
pub(crate) const CLONE_FS:             u64 = 0x200;
pub(crate) const CLONE_FILES:          u64 = 0x400;
pub(crate) const CLONE_SIGHAND:        u64 = 0x800;
pub(crate) const CLONE_PIDFD:          u64 = 0x1000;
pub(crate) const CLONE_VFORK:          u64 = 0x4000;
pub(crate) const CLONE_PARENT:         u64 = 0x8000;
pub(crate) const CLONE_THREAD:         u64 = 0x10000;
pub(crate) const CLONE_NEWNS:          u64 = 0x20000;
pub(crate) const CLONE_SETTLS:         u64 = 0x80000;
pub(crate) const CLONE_PARENT_SETTID:  u64 = 0x100000;
pub(crate) const CLONE_CHILD_CLEARTID: u64 = 0x200000;
pub(crate) const CLONE_DETACHED:       u64 = 0x400000;
pub(crate) const CLONE_CHILD_SETTID:   u64 = 0x1000000;
pub(crate) const CLONE_NEWUSER:        u64 = 0x10000000;
pub(crate) const CLONE_NEWPID:         u64 = 0x20000000;
pub(crate) const CLONE_CLEAR_SIGHAND:  u64 = 1u64 << 32;
pub(crate) const CLONE_INTO_CGROUP:    u64 = 1u64 << 33;
pub(crate) const CLONE_LEGACY_FLAGS:   u64 = 0xffff_ffff;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// # C: O(1)
pub(crate) fn validate_clone_core(flags: u64) -> Result<(), Errno> {
    crate::s272_unshare::validate_namespace_flags(flags)?;
    let exit_signal = (flags & CSIGNAL) as u8;
    if exit_signal != 0 && sched::clone_exit_signal(exit_signal).is_none() { return Err(Errno::Einval); }
    if (flags & (CLONE_NEWNS | CLONE_FS)) == (CLONE_NEWNS | CLONE_FS) { return Err(Errno::Einval); }
    if (flags & (CLONE_NEWUSER | CLONE_FS)) == (CLONE_NEWUSER | CLONE_FS) { return Err(Errno::Einval); }
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 { return Err(Errno::Einval); }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 { return Err(Errno::Einval); }
    // Linux requires a shared mm for vfork: the parent is suspended while
    // the child temporarily runs in that same address space.
    if (flags & CLONE_VFORK) != 0 && (flags & CLONE_VM) == 0 { return Err(Errno::Einval); }
    if (flags & CLONE_THREAD) != 0 && (flags & (CLONE_NEWUSER | CLONE_NEWPID)) != 0 { return Err(Errno::Einval); }
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_PIDFD) != 0 { return Err(Errno::Einval); }
    if (flags & (CLONE_THREAD | CLONE_PARENT)) != 0 && exit_signal != 0 { return Err(Errno::Einval); }
    if (flags & CLONE_PIDFD) != 0 && (flags & CLONE_DETACHED) != 0 { return Err(Errno::Einval); }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_CLEAR_SIGHAND) != 0 { return Err(Errno::Einval); }
    Ok(())
}

fn user_i32_ptr_ok(p: u64) -> bool {
    p != 0 && p.checked_add(core::mem::size_of::<i32>() as u64).map_or(false, |e| e <= hal::USER_VA_END)
}

/// `sys_clone_dispatch` — unified clone path for fork/vfork/
/// clone/clone3. `flags` carries the Linux CLONE_* bitmap; the lowest
/// 8 bits are the exit_signal (SIGCHLD = 17 for fork). `child_stack`
/// is non-zero for thread spawns (libc-allocated user stack); `ptid`
/// + `ctid` are user pointers honored by CLONE_PARENT_SETTID /
/// CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID.
///
/// # C: O(parent VMAs) for COW; O(1) for CLONE_VM
pub fn sys_clone_dispatch(
    _args: &SyscallArgs,
    flags: u64,
    child_stack: u64,
    ptid: u64,
    pidfd_ptr: u64,
    ctid: u64,
    tls: u64,
    into_cgid: Option<u64>,
) -> i64 {
    use core::sync::atomic::Ordering;
    if let Err(e) = validate_clone_core(flags) { return errno(e); }
    if (flags & CLONE_PARENT_SETTID) != 0 && !user_i32_ptr_ok(ptid) { return errno(Errno::Efault); }
    if (flags & CLONE_PIDFD) != 0 && !user_i32_ptr_ok(pidfd_ptr) { return errno(Errno::Efault); }
    if (flags & CLONE_CHILD_SETTID) != 0 && !user_i32_ptr_ok(ctid) { return errno(Errno::Efault); }
    if (flags & CLONE_CHILD_CLEARTID) != 0 && ctid >= hal::USER_VA_END { return errno(Errno::Efault); }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return errno(Errno::Einval),
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
    // The vpid (vtid) to return to the parent — captured now, before the
    // `child` Arc may be dropped at the end. spawn stamped it.
    let child_vpid_ret = child.vtid.load(Ordering::Acquire);
    child.exit_signal.store((flags & CSIGNAL) as u8, Ordering::Release);

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
        if let Some(cg) = into_cgid { cgroup::attach_tid_into(cg, child_tid as u64); }
        else { cgroup::inherit(child_tid as u64, cur.tid as u64); }
    } else {
        let proc_pid = cur.tgid.load(core::sync::atomic::Ordering::Relaxed) as u64;
        cgroup::charge_thread(proc_pid, child_tid as u64);
    }
    // Inherit parent's pgid + sid per POSIX fork(2). setpgid/setsid in
    // child override later. Without inheritance every fork would land
    // in its own pgrp and shells couldn't track job state.
    child.pgid.store(cur.pgid.load(Ordering::Acquire), Ordering::Release);
    child.sid.store(cur.sid.load(Ordering::Acquire), Ordering::Release);
    // Inherit Linux `fs_struct`: CLONE_FS shares one owner; fork snapshots it.
    child.inherit_fs_context_from(cur, (flags & CLONE_FS) != 0);
    // Inherit rlimits and ctty per POSIX fork(2).
    // SAFETY: child is unpublished and therefore the sole writer to these slots.
    unsafe {
        *child.rlimits.get() = *cur.rlimits.get();
        // F200: ctty inherits across fork(2) per POSIX §11.1.3.
        *child.ctty.get() = (*cur.ctty.get()).clone();
    }
    child.umask.store(cur.umask.load(Ordering::Acquire), Ordering::Release);
    if let Err(e) = namespaces::inherit_and_publish(cur, &child, flags, child_vpid_ret) {
        return errno(e);
    }
    // Parent Weak<Task> for `park_zombie` SIGCHLD delivery. CLONE_PARENT
    // inherits the caller's parent link; otherwise the caller becomes parent.
    if (flags & CLONE_PARENT) != 0 {
        // SAFETY: caller is current on this CPU; child not scheduled; clone
        // just copies the existing parent Weak without mutating the caller.
        unsafe { *child.parent_arc.get() = (*cur.parent_arc.get()).clone(); }
    } else if let Some(rq) = sched::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw in `Runqueue::new` / `swap_current`; bumping the strong count is sound because the conceptual Arc held by current is alive while we run on it.
            unsafe { alloc::sync::Arc::increment_strong_count(raw); }
            // SAFETY: matching from_raw consumes the bumped count.
            let parent_arc = unsafe { alloc::sync::Arc::from_raw(raw) };
            // SAFETY: child task hasn't been scheduled yet (just spawned); we are sole writer to its parent_arc slot per the single-mutator-per-active-CPU invariant in `13§5`.
            unsafe { *child.parent_arc.get() = Some(alloc::sync::Arc::downgrade(&parent_arc)); }
        }
    }

    fd_table::inherit(cur, &child, flags);

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
        // SAFETY: ptid validated < USER_VA_END; CPL=0 writes in caller's AS.
        // Linux writes the child's TID (the vtid userspace sees), not the
        // opaque internal tid.
        unsafe { core::ptr::write_volatile(ptid as *mut i32, child.vtid.load(Ordering::Acquire) as i32); }
    }
    // CLONE_CHILD_SETTID: writes happen in child AS — for CLONE_VM
    // the AS is shared with parent so the write is visible directly;
    // for non-CLONE_VM the child's freshly forked AS still has the
    // page COW-mapped from parent (write-fault on its first store
    // splits per P2-15c). The write here goes through the parent's
    // active CR3, which only matches the child for CLONE_VM. Skip
    // it otherwise — a real impl would queue the write for the
    // child's first instruction.
    if (flags & CLONE_CHILD_SETTID) != 0 && (flags & CLONE_VM) != 0
    {
        // SAFETY: ctid validated < USER_VA_END; AS shared (CLONE_VM); CPL=0.
        // Child's TID = its vtid (what gettid() returns), not internal tid.
        unsafe { core::ptr::write_volatile(ctid as *mut i32, child.vtid.load(Ordering::Acquire) as i32); }
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
    #[cfg(not(target_arch = "x86_64"))]
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

    // Linux `wake_up_new_task`: the child is now fully built — vtgid, fd
    // table, sigmask, CLONE_SETTLS FS_BASE, and the set_child_tid writes are
    // all final. ONLY now make it schedulable, so no CPU (SMP) can pick it up
    // and run its glibc thread-start trampoline with the parent's stale
    // FS_BASE / an unfinished vtgid (which aliased the creator's TLS and made
    // GCond signals target the wrong futex word — the greeter/SMP wedge).
    publication::commit(&child, (flags & CLONE_THREAD) != 0, prepared_pidfd);

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
    // SAFETY: we are running on the parent's per-task syscall stack; current_user_frame() points at the saved tail; we read but do not write.
    let frame = unsafe { &*hal_x86_64::current_user_frame() };
    let user_rip = frame[0];
    let user_rflags = frame[1];
    // Thread spawns pass a libc-allocated stack via clone()/clone3();
    // honor it so each thread has its own user stack rather than
    // racing on the parent's. fork(2) leaves child_stack=0 and the
    // child resumes on the parent's RSP after the COW copy.
    let user_rsp = if child_stack != 0 { child_stack } else { frame[2] };
    // SAFETY: same dispatch-context invariant as current_user_frame; full_frame block is the 15-quadword saved area at top-0x78..top.
    let full = unsafe { hal_x86_64::current_user_full_frame() };
    // SAFETY: full points to the 15-quadword saved area at top-0x78..top of the kernel stack for the current user task; layout is fixed by syscall entry asm.
    let pregs = unsafe {
        hal_x86_64::ForkRegs {
            rdi: *full.add(1),
            rsi: *full.add(2),
            rdx: *full.add(3),
            r10: *full.add(4),
            r8:  *full.add(5),
            r9:  *full.add(6),
            rcx: *full.add(7),
            r11: *full.add(8),
            // index 9 = user RSP, NOT user's r12. r12 sits in the
            // B04-added save at index 15 (top of the 16-slot frame).
            rbx: *full.add(10),
            rbp: *full.add(11),
            r13: *full.add(12),
            r14: *full.add(13),
            r15: *full.add(14),
            r12: *full.add(15),
        }
    };
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

    // SAFETY: runqueue installed; child_mm freshly forked from parent AS via fork_copy_pages w/ kernel-half cloned at new_user_l0; pregs captured from parent's SVC frame.
    unsafe {
        sched::live::spawn_user_thread_for_fork(
            child_tid, "fork-child", user_ip, user_sp, &pregs, child_mm,
            thread_group,
        )
    }
}
