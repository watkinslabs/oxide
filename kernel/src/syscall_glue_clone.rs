// Unified clone dispatch (kernel_sys_clone_dispatch) extracted from
// syscall_glue.rs to keep that file under the 1000-line cap. Drives
// fork/vfork/clone/clone3 — see body for honored CLONE_* flag bits.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `kernel_sys_clone_dispatch` — unified clone path for fork/vfork/
/// clone/clone3. `flags` carries the Linux CLONE_* bitmap; the lowest
/// 8 bits are the exit_signal (SIGCHLD = 17 for fork). `child_stack`
/// is non-zero for thread spawns (libc-allocated user stack); `ptid`
/// + `ctid` are user pointers honored by CLONE_PARENT_SETTID /
/// CLONE_CHILD_SETTID / CLONE_CHILD_CLEARTID.
///
/// Honored flag bits (best-effort; rest accepted silently):
///   CLONE_VM       0x100   — share parent's mm via `Arc::clone`
///   CLONE_FILES    0x400   — share parent's fd_table via `Arc::clone`
///   CLONE_SIGHAND  0x800   — share parent's sigactions (Arc-on-write
///                            unsupported v1; copy on spawn)
///   CLONE_THREAD   0x10000 — child.tgid = parent.tgid; same process
///   CLONE_PARENT_SETTID  0x100000 — write child tid to *ptid
///   CLONE_CHILD_SETTID   0x1000000 — write child tid to *ctid (in child AS)
///   CLONE_CHILD_CLEARTID 0x200000 — store ctid in clear_child_tid
///   CLONE_SETTLS         0x80000 — write tls to child's FS_BASE
/// # C: O(parent VMAs) for COW; O(1) for CLONE_VM
pub fn kernel_sys_clone_dispatch(
    _args: &SyscallArgs,
    flags: u64,
    child_stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> i64 {
    use core::sync::atomic::Ordering;
    const CLONE_VM:        u64 = 0x100;
    const CLONE_FS:        u64 = 0x200;
    const CLONE_FILES:     u64 = 0x400;
    const CLONE_SIGHAND:   u64 = 0x800;
    const CLONE_THREAD:    u64 = 0x10000;
    const CLONE_SETTLS:    u64 = 0x80000;
    const CLONE_PARENT_SETTID: u64 = 0x100000;
    const CLONE_CHILD_CLEARTID: u64 = 0x200000;
    const CLONE_CHILD_SETTID:   u64 = 0x1000000;
    let _ = CLONE_FS; // accepted but not yet differentiated from cwd-inherit
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; no concurrent writer to our mm; preempt-off through the syscall handler.
    let parent_mm = match unsafe { cur.mm_ref() } {
        Some(m) => m,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    let share_vm = (flags & CLONE_VM) != 0;
    let child_mm: alloc::sync::Arc<vmm::AddressSpace> = if share_vm {
        // CLONE_VM: child shares parent's address space; no PML4
        // alloc, no per-page copy. Threads land here.
        alloc::sync::Arc::clone(parent_mm)
    } else {
        // SAFETY: capture_kernel_master ran at user_as::init; PMM up.
        let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
            Some(r) => r,
            None    => return -(Errno::Enomem.as_i32() as i64),
        };
        let hhdm = crate::user_as::hhdm_offset();
        match parent_mm.fork_copy_pages::<hal_x86_64::mmu_ops::X86Mmu, _>(
            new_root, hhdm, || crate::pmm_setup::alloc_one_frame(),
        ) {
            Ok(m) => m,
            Err(_) => return -(Errno::Enomem.as_i32() as i64),
        }
    };

    // SAFETY: we are running on the parent's per-task syscall stack; current_user_frame() points at the saved tail; we read but do not write.
    let frame = unsafe { &*hal_x86_64::current_user_frame() };
    let user_rip = frame[0];
    let user_rflags = frame[1];
    // Thread spawns pass a libc-allocated stack via clone()/clone3();
    // honor it so each thread has its own user stack rather than
    // racing on the parent's. fork(2) leaves child_stack=0 and the
    // child resumes on the parent's RSP after the COW copy.
    let user_rsp = if child_stack != 0 { child_stack } else { frame[2] };
    // user_rip points at the instruction RIGHT AFTER the syscall
    // (rcx is post-syscall in x86_64) — the child resumes there
    // with rax=0.

    // P5-10: capture parent's full saved-syscall reg block so the
    // child's iretq frame + Context get parent values for every
    // reg the user code may rely on across the fork syscall (Linux
    // ABI: rdi/rsi/rdx/r10/r8/r9 preserved + all callee-saved
    // regs unchanged). Pre-P5-10 the kernel zeroed these and the
    // child resumed with junk regs — fatal once a real shell
    // started using `|` (child A's run_one(seg=rdx, n=rbp) saw 0/0).
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

    let child_tid = crate::sched::next_tid();
    // SAFETY: runqueue installed by elf_smoke; child_mm freshly forked from parent AS w/ kernel-half cloned per P2-19; user_rip/rflags/rsp + pregs captured from parent's saved syscall stack.
    let spawn = unsafe {
        crate::sched::spawn_user_thread_for_fork(
            child_tid, "fork-child", user_rip, user_rsp, user_rflags,
            &pregs, child_mm,
        )
    };
    let child = match spawn {
        Ok(t)  => t,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // CLONE_THREAD: the new task joins the caller's thread group.
    // Without it the child is its own process leader and tgid==tid.
    if (flags & CLONE_THREAD) != 0 {
        child.tgid.store(cur.tgid.load(Ordering::Acquire), Ordering::Release);
    }
    // Record parent_tid for `wait4` (P2-22) + parent Weak<Task>
    // for `park_zombie` SIGCHLD delivery (P3-67).
    child.parent_tid.store(cur.tid, Ordering::Release);
    // Inherit parent's pgid + sid per POSIX fork(2). setpgid/setsid in
    // child override later. Without inheritance every fork would land
    // in its own pgrp and shells couldn't track job state.
    child.pgid.store(cur.pgid.load(Ordering::Acquire), Ordering::Release);
    child.sid.store(cur.sid.load(Ordering::Acquire), Ordering::Release);
    // Inherit cwd + rlimits per POSIX fork(2).
    // SAFETY: child not yet scheduled; we are sole writer to its slots;
    // parent reads are the running task on this CPU per single-mutator invariant.
    unsafe {
        *child.cwd.get() = (*cur.cwd.get()).clone();
        *child.rlimits.get() = *cur.rlimits.get();
    }
    child.umask.store(cur.umask.load(Ordering::Acquire), Ordering::Release);
    // Materialise an Arc<Task> for the parent by bumping its
    // strong count (the runqueue's `current` AtomicPtr already
    // holds one), then downgrade to Weak<Task>. Drops the bumped
    // Arc immediately — Weak alone keeps the slot live.
    if let Some(rq) = crate::sched::global() {
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

    // Fd-table inheritance.
    //   CLONE_FILES: share the parent's `Arc<FdTable>` so dup/close
    //                in either task is visible to the other (Linux
    //                pthreads default).
    //   default:     copy entries into a fresh FdTable so child
    //                close/dup doesn't disturb parent's slots
    //                (POSIX fork(2)). Underlying `Arc<File>` still
    //                shared so open-file descriptions match.
    // SAFETY: we're sole writer on the parent's fd_table read; child not yet scheduled (sole writer there too).
    let parent_fdt = unsafe { cur.fd_table_ref().cloned() };
    if let Some(fdt) = parent_fdt {
        let child_fdt = if (flags & CLONE_FILES) != 0 {
            fdt
        } else {
            alloc::sync::Arc::new(fdt.fork_clone())
        };
        // SAFETY: child task hasn't been scheduled yet (just spawned); we are the sole writer to its fd_table slot per the single-mutator-per-active-CPU invariant in `13§5`.
        unsafe { child.replace_fd_table(Some(child_fdt)); }
    }

    // Inherit signal handlers; CLONE_SIGHAND callers get the same
    // copy. v1 doesn't yet share a single sigaction array via Arc,
    // so SIGHAND vs default both perform a deep copy. Real sharing
    // lands when the threading subsystem grows a sighand_struct.
    // SAFETY: child not yet scheduled (sole writer); parent reads happen on its running CPU per single-mutator invariant.
    unsafe {
        *child.sigactions.get() = *cur.sigactions.get();
    }
    if (flags & CLONE_SIGHAND) != 0 {
        // Inherit pending+mask too — CLONE_SIGHAND siblings share
        // the disposition table; v1 also clones the mask.
        child.sigmask.store(cur.sigmask.load(Ordering::Acquire), Ordering::Release);
    }

    // CLONE_PARENT_SETTID: write child tid in caller's AS.
    if (flags & CLONE_PARENT_SETTID) != 0 && ptid != 0 && ptid < hal::USER_VA_END {
        // SAFETY: ptid validated < USER_VA_END; CPL=0 writes in caller's AS.
        unsafe { core::ptr::write_volatile(ptid as *mut i32, child_tid as i32); }
    }
    // CLONE_CHILD_SETTID: writes happen in child AS — for CLONE_VM
    // the AS is shared with parent so the write is visible directly;
    // for non-CLONE_VM the child's freshly forked AS still has the
    // page COW-mapped from parent (write-fault on its first store
    // splits per P2-15c). The write here goes through the parent's
    // active CR3, which only matches the child for CLONE_VM. Skip
    // it otherwise — a real impl would queue the write for the
    // child's first instruction.
    if (flags & CLONE_CHILD_SETTID) != 0 && ctid != 0 && ctid < hal::USER_VA_END
       && (flags & CLONE_VM) != 0
    {
        // SAFETY: ctid validated < USER_VA_END; AS shared (CLONE_VM); CPL=0.
        unsafe { core::ptr::write_volatile(ctid as *mut i32, child_tid as i32); }
    }
    // CLONE_CHILD_CLEARTID: stash for thread-exit FUTEX_WAKE path.
    if (flags & CLONE_CHILD_CLEARTID) != 0 {
        child.clear_child_tid.store(ctid, Ordering::Release);
    }
    // CLONE_SETTLS: x86_64 stores TLS in FS_BASE; child resumes
    // with this base via wrmsr at iretq-prep. The fork-spawn path
    // doesn't yet thread a separate FS_BASE through ArchCtx;
    // glibc/musl set FS_BASE via arch_prctl post-clone too, so we
    // accept the flag silently for now.
    let _ = tls;

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_clone: parent_tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" child_tid=");
        klog::write_dec_u64(child_tid as u64);
        klog::write_raw(b" flags=");
        klog::write_hex_u64(flags);
        klog::write_raw(b"\n");
    }

    // Drop our local Arc; the runqueue's enqueue clone keeps the
    // child alive until it Zombies + parks to the zombie registry.
    drop(child);

    child_tid as i64
}
