// Glue between per-arch syscall asm stub and dispatch table per `15§4`.

#![cfg(target_os = "oxide-kernel")]

use syscall::{dispatch, SyscallArgs};
use syscall::errno::Errno;
use hal::{USER_VA_END};
#[cfg(target_arch = "x86_64")]
use hal::TimerOps;

const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Write a utsname field at offset `off`: `src` then NUL pad to 65 B.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    for i in 0..n {
        // SAFETY: caller validated [tp, tp + UTSNAME_TOTAL_LEN) lies below USER_VA_END and is mapped writable; CPL=0 ignores leaf U-bit.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, src[i]); }
    }
    for i in n..UTSNAME_FIELD_LEN {
        // SAFETY: same validated range as the byte writes above; NUL pad to 65-byte slot length.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd = args.a4 as i64;
    match crate::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

fn kernel_munmap(args: &SyscallArgs) -> i64 {
    crate::user_as::glue_munmap(args.a0, args.a1)
}

/// sys_read via fd_table.
#[cfg(target_arch = "x86_64")]
fn kernel_sys_read(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    if cnt == 0 { return 0; }
    if buf == 0 || buf >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // ConsoleInode produces 1 byte/call (line discipline); pipes
    // and /dev/zero|random fill the full buffer. Inode chooses.
    if buf.checked_add(cnt).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let len = cnt as usize;
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END; user pages mapped via active CR3 (caller's AS); CPL=0 writes through user mapping; demand-paging resolves any not-present user pages on first kernel-side write.
    let user_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, len)
    };
    match file.read(user_buf) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_write via fd_table.
fn kernel_sys_write(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    if cnt == 0 { return 0; }
    if buf == 0 || buf.checked_add(cnt).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return dispatch(1, args),
    };
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return dispatch(1, args),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let len = cnt as usize;
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END above; user pages mapped via active CR3 (caller's AS); CPL=0 reads through user mapping.
    let user_buf: &[u8] = unsafe {
        core::slice::from_raw_parts(buf as *const u8, len)
    };
    match file.write(user_buf) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

fn kernel_sys_pipe2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    let pipefd = args.a0;
    let flags  = args.a1 as u32;
    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC:  u32 = 0o2000000;
    if pipefd == 0 || pipefd >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let inode = crate::dev_pipe::PipeInode::new();
    let dentry = Dentry::new(None, "pipe".to_string(), inode.clone());
    let mut r_oflags = OpenFlags::O_RDONLY;
    let mut w_oflags = OpenFlags::O_WRONLY;
    if (flags & O_NONBLOCK) != 0 { r_oflags |= OpenFlags::O_NONBLOCK; w_oflags |= OpenFlags::O_NONBLOCK; }
    let r_file = File::new(inode.clone(), dentry.clone(), r_oflags);
    let w_file = File::new(inode, dentry, w_oflags);
    let r_fd = match fdt.alloc(r_file)  { Ok(f) => f, Err(e) => return -(e as i64) };
    let w_fd = match fdt.alloc(w_file)  { Ok(f) => f, Err(e) => {
        let _ = fdt.close(r_fd);
        return -(e as i64);
    }};
    if (flags & O_CLOEXEC) != 0 {
        let _ = fdt.set_cloexec(r_fd, true);
        let _ = fdt.set_cloexec(w_fd, true);
    }
    // SAFETY: pipefd validated < USER_VA_END; user page mapped per active CR3 = caller's AS.
    unsafe {
        core::ptr::write_volatile(pipefd as *mut i32,         r_fd);
        core::ptr::write_volatile((pipefd + 4) as *mut i32,   w_fd);
    }
    0
}

/// sys_brk — adjust brk within ELF heap VMA.
fn kernel_sys_brk(args: &SyscallArgs) -> i64 {
    let req = args.a0;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return 0,
    };
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent mm writer.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(),
        None    => return 0,
    };
    if req == 0 {
        return mm.brk() as i64;
    }
    mm.try_set_brk(req) as i64
}


fn kernel_sys_close(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.close(fd) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}


fn kernel_sys_getpid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current()
        .map(|c| c.tgid.load(Ordering::Acquire) as i64)
        .unwrap_or(1)
}

fn kernel_sys_getppid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current()
        .map(|c| c.parent_tid.load(Ordering::Acquire) as i64)
        .unwrap_or(0)
}

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
#[cfg(target_arch = "x86_64")]
pub fn kernel_sys_clone_dispatch_pub(
    args: &SyscallArgs, flags: u64, child_stack: u64, ptid: u64, ctid: u64, tls: u64,
) -> i64 { kernel_sys_clone_dispatch(args, flags, child_stack, ptid, ctid, tls) }

#[cfg(target_arch = "x86_64")]
fn kernel_sys_clone_dispatch(
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

/// `sys_waitid(idtype, id, infop, options, rusage)` — slot 247.
/// Linux idtype: P_ALL=0, P_PID=1, P_PGID=2, P_PIDFD=3.
/// Maps onto wait4: P_ALL → pid=-1, P_PID → pid=id, P_PGID →
/// pid=-id. P_PIDFD not honored (no real pidfd substrate v1; the
/// id is the underlying tid which works for the v1 single-thread
/// case). On success writes the canonical siginfo_t fields:
/// si_signo=SIGCHLD(17), si_pid=tid, si_status=exit-code, si_code=1
/// (CLD_EXITED). Linux requires waitid to write 0 to si_pid on a
/// WNOHANG miss; we honor that.
/// # C: same as wait4 — bounded by zombie poll
#[cfg(target_arch = "x86_64")]
fn kernel_sys_waitid(args: &SyscallArgs) -> i64 {
    const P_ALL: u64 = 0;
    const P_PID: u64 = 1;
    const P_PGID: u64 = 2;
    let idtype  = args.a0;
    let id      = args.a1 as i32;
    let infop   = args.a2;
    let options = args.a3;
    let pid_for_wait4: i32 = match idtype {
        P_ALL  => -1,
        P_PID  => id,
        P_PGID => -id,
        _      => id, // P_PIDFD: treat as pid in v1
    };
    let mut sa = *args;
    sa.a0 = pid_for_wait4 as u64;
    sa.a1 = 0;       // wstatus -- we'll synthesize siginfo from rv
    sa.a2 = options; // WNOHANG/WEXITED bits overlap appropriately
    sa.a3 = 0;
    let rv = kernel_sys_wait4(&sa);
    if infop != 0 && infop < USER_VA_END {
        // SAFETY: infop validated < USER_VA_END; CPL=0 writes through caller's AS.
        // Zero-fill 128-byte siginfo_t per POSIX, then patch in si_signo/si_pid.
        unsafe {
            for i in 0..128usize {
                core::ptr::write_volatile((infop + i as u64) as *mut u8, 0);
            }
            if rv > 0 {
                core::ptr::write_volatile(infop          as *mut i32, 17 /* SIGCHLD */);
                core::ptr::write_volatile((infop + 8)    as *mut i32, 1  /* CLD_EXITED */);
                core::ptr::write_volatile((infop + 16)   as *mut i32, rv as i32 /* si_pid */);
                // si_status at +24
                core::ptr::write_volatile((infop + 24)   as *mut i32, 0);
            }
        }
    }
    if rv < 0 { rv } else { 0 }
}

#[cfg(target_arch = "x86_64")]
fn kernel_sys_wait4(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const WNOHANG: u64 = 1;
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let options = args.a2;
    let _rusage  = args.a3;

    let parent_tid = match crate::sched::current() {
        Some(c) => c.tid,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Loop: try to reap; if no match, yield + retry. Bounded
    // because schedule() picks runnable children which eventually
    // exit + park.
    loop {
        if let Some((tid, code)) = crate::sched::reap_one(parent_tid, pid) {
            // POSIX wstatus encoding: low 7 bits = signal (0 for
            // normal exit), bit 7 = core flag, bits 8..16 =
            // exit code. v1 only handles normal exits.
            let wstat: i32 = (code & 0xff) << 8;
            if wstatus != 0 && wstatus < USER_VA_END {
                // SAFETY: wstatus validated < USER_VA_END; user page mapped (caller's user code already executed from this AS); CPL=0 reads/writes through the user mapping.
                unsafe { core::ptr::write_volatile(wstatus as *mut i32, wstat); }
            }
            debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
            return tid as i64;
        }
        if (options & WNOHANG) != 0 { return 0; }
        // No zombie ready — sleep until a child exits. `park_for_wait4`
        // marks us Sleeping + pushes us to the WAITERS list; the next
        // `park_zombie` call (from a child's sys_exit handler) sets us
        // back to Runnable and enqueues us on the runqueue. Until then
        // schedule() picks idle (or another runnable task), letting
        // the LAPIC timer + tty input path keep ticking.
        // SAFETY: process ctx; runqueue installed; preempt-off; we
        // yield via schedule() immediately after parking so the
        // Sleeping state is observed by the picker.
        unsafe { crate::sched::park_for_wait4(); }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { crate::sched::schedule(); }
        // After resume, ZOMBIES likely contains a new entry.
        // Loop body re-tries.
        let _ = Ordering::Acquire; // touch to keep ordering import live
    }
}

/// sys_exit: mark Zombie, stash exit_status, schedule away.
/// # SAFETY: dispatch ctx on task's syscall kstack, IRQs masked.
/// # C: O(log N) + O(1)
/// `delete_module(name, flags)` slot 176. v1 takes the module
/// index encoded as the user pointer (since we don't yet parse
/// .modinfo names): pass the index in the low 16 bits.
fn kernel_sys_delete_module(args: &SyscallArgs) -> i64 {
    let idx = args.a0 as usize & 0xFFFF;
    if crate::dev_modules::unload(idx) { 0 } else { -(Errno::Einval.as_i32() as i64) }
}

/// `init_module(image, len, params)` slot 175.
/// `image` is a user-mapped pointer to the .ko bytes; `len` is
/// the size; `params` ignored for v1.
fn kernel_sys_init_module(args: &SyscallArgs) -> i64 {
    let img = args.a0;
    let len = args.a1 as usize;
    if img == 0 || img >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if len == 0 || len > 16 * 1024 * 1024 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: ptr range validated < USER_VA_END; user pages mapped under caller's AS; bounded read.
    let bytes: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(img as *const u8, len).to_vec()
    };
    match crate::dev_modules::load_blob(&bytes) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}

/// `finit_module(fd, params, flags)` slot 313. Reads the file
/// content via the fd then delegates to load_blob. v1 caps file
/// size at 16 MiB.
fn kernel_sys_finit_module(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut buf = alloc::vec::Vec::new();
    let mut chunk = [0u8; 4096];
    let mut off = 0u64;
    loop {
        match file.inode().read(off, &mut chunk) {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&chunk[..n]); off += n as u64; }
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        if buf.len() > 16 * 1024 * 1024 { return -(Errno::E2big.as_i32() as i64); }
    }
    match crate::dev_modules::load_blob(&buf) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}

fn kernel_sys_exit(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use alloc::sync::Arc;
    let _ = args;
    // No runqueue (arm direct drop_to_el0 pre-P2-13e): nothing
    // to Zombie. Pre-P2-22 fallthrough behavior.
    if crate::sched::global().is_none() {
        return 0;
    }
    if let Some(rq) = crate::sched::global() {
        // Snapshot exit code + state before parking — the
        // current task's strong ref needs to live in the zombie
        // registry until wait4 reaps it.
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw in `Runqueue::new` / `swap_current`; bumping the strong count is sound because we then matching `from_raw` to materialise an owned Arc.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: matching from_raw consumes the bumped count.
            let arc = unsafe { Arc::from_raw(raw) };
            arc.exit_status.store(args.a0 as i32, Ordering::Release);
            crate::sched::mark_done(&arc);
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_exit: tid=");
                klog::write_dec_u64(arc.tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(args.a0);
                klog::write_raw(b"\n");
            }
            crate::sched::park_zombie(arc);
        }
    }
    // SAFETY: process ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { crate::sched::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}


/// `sys_getrandom(buf, len, flags)` — slot 318. NOT cryptographic.
fn kernel_sys_getrandom(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let len  = args.a1;
    let _fl  = args.a2;
    if len == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, len, 1) { return rv; }
    let mut written: u64 = 0;
    while written < len {
        let v = crate::dev_misc::lcg_next().to_le_bytes();
        let n = (len - written).min(8);
        // SAFETY: validated [buf, buf+len) below USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((buf + written + i) as *mut u8, v[i as usize]);
            }
        }
        written += n;
    }
    written as i64
}

use crate::syscall_glue_proc::{kernel_sys_kill, kernel_sys_tgkill};

fn kernel_uname(args: &SyscallArgs) -> i64 {
    let tp = args.a0;
    if let Err(rv) = validate_user_buf(tp, UTSNAME_TOTAL_LEN as u64, 1) { return rv; }
    // SAFETY: range validated above; user-half VA is mapped writable
    // by the userspace-smoke setup. Each field write iterates byte-
    // by-byte so no alignment requirement.
    unsafe {
        // sysname == "Linux" so libc/configure scripts that gate on it pass.
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"Linux");
        let host = crate::hostname::snapshot();
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, &host);
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, b"5.15.0-oxide");
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, b"#1 SMP PREEMPT oxide v0.1.0");
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, b"(none)");
    }
    0
}

/// Validate that a user buffer `[ptr, ptr + len)` lies entirely
/// below `USER_VA_END` and is `align`-byte aligned at `ptr`.
/// Returns Ok(()) or Err(-EFAULT-as-i64) ready to return from a
/// glue handler.
/// # C: O(1)
pub(crate) fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}


/// x86 sys_arch_prctl — slot 158. ARCH_SET_FS writes IA32_FS_BASE
/// via wrmsr; ARCH_GET_FS returns 0 (rdmsr stub); else -EINVAL.
#[cfg(target_arch = "x86_64")]
fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        crate::syscall_nrs::ARCH_SET_FS => {
            // Reject non-canonical / kernel-VA addresses.
            if val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: val is a user-canonical address per the check
            // above; wrmsr IA32_FS_BASE = val updates the per-CPU
            // segment base used by user-mode `fs:` accesses.
            unsafe { hal_x86_64::set_user_fs_base(val); }
            0
        }
        crate::syscall_nrs::ARCH_GET_FS => {
            // val is a user pointer to a u64 receiving FS_BASE.
            if val == 0 || val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: rdmsr IA32_FS_BASE is privileged; no memory effect.
            let base = unsafe { hal_x86_64::get_user_fs_base() };
            // SAFETY: val validated < USER_VA_END; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(val as *mut u64, base); }
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// SysV-ABI hook invoked by `oxide_syscall_entry`. Returns u64 in rax.
/// # SAFETY: caller is the syscall asm; single-CPU; IF=0 (FMASK).
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(
    nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5: 0 };
    // Arch-specific + per-arch-time syscalls handled here (kernel can
    // call hal); others fall through to the arch-neutral dispatch.
    let rv = match nr {
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_ARCH_PRCTL    => kernel_arch_prctl(&args),
        crate::syscall_nrs::NR_CLOCK_GETTIME => crate::syscall_glue_time::kernel_clock_gettime(&args),
        crate::syscall_nrs::NR_CLOCK_GETRES  => crate::syscall_glue_time::kernel_clock_getres(&args),
        crate::syscall_nrs::NR_CLOCK_SETTIME => crate::syscall_glue_time::kernel_clock_settime(&args),
        crate::syscall_nrs::NR_GETTIMEOFDAY  => crate::syscall_glue_time::kernel_gettimeofday(&args),
        crate::syscall_nrs::NR_SETTIMEOFDAY  => crate::syscall_glue_time::kernel_settimeofday(&args),
        crate::syscall_nrs::NR_TIME          => crate::syscall_glue_time::kernel_time(&args),
        crate::syscall_nrs::NR_UNAME         => kernel_uname(&args),
        crate::syscall_nrs::NR_SETHOSTNAME   => crate::syscall_glue_proc::kernel_sys_sethostname(&args),
        crate::syscall_nrs::NR_MMAP          => kernel_mmap(&args),
        crate::syscall_nrs::NR_MUNMAP        => kernel_munmap(&args),
        crate::syscall_nrs::NR_EXIT          => kernel_sys_exit(&args),
        crate::syscall_nrs::NR_GETPID        => kernel_sys_getpid(&args),
        crate::syscall_nrs::NR_GETPPID       => kernel_sys_getppid(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_READ          => kernel_sys_read(&args),
        crate::syscall_nrs::NR_WRITE         => kernel_sys_write(&args),
        crate::syscall_nrs::NR_OPEN          => crate::syscall_glue_open::kernel_sys_open(&args),
        crate::syscall_nrs::NR_BRK           => kernel_sys_brk(&args),
        crate::syscall_nrs::NR_PIPE2         => kernel_sys_pipe2(&args),
        crate::syscall_nrs::NR_FSTAT         => crate::syscall_glue_fs::kernel_sys_fstat(&args),
        crate::syscall_nrs::NR_IOCTL         => crate::syscall_glue_fs::kernel_sys_ioctl(&args),
        crate::syscall_nrs::NR_GETCWD        => crate::syscall_glue_fs::kernel_sys_getcwd(&args),
        crate::syscall_nrs::NR_CHDIR         => crate::syscall_glue_fs::kernel_sys_chdir(&args),
        crate::syscall_nrs::NR_FCHDIR        => crate::syscall_glue_fs::kernel_sys_fchdir(&args),
        crate::syscall_nrs::NR_KILL          => kernel_sys_kill(&args),
        crate::syscall_nrs::NR_TGKILL        => kernel_sys_tgkill(&args),
        crate::syscall_nrs::NR_GETRANDOM     => kernel_sys_getrandom(&args),
        crate::syscall_nrs::NR_SCHED_YIELD   => crate::syscall_glue_proc::kernel_sys_sched_yield(&args),
        crate::syscall_nrs::NR_GETTID        => crate::syscall_glue_proc::kernel_sys_gettid(&args),
        crate::syscall_nrs::NR_SET_TID_ADDRESS => crate::syscall_glue_proc::kernel_sys_set_tid_address(&args),
        crate::syscall_nrs::NR_WRITEV        => crate::syscall_glue_fs::kernel_sys_writev(&args),
        crate::syscall_nrs::NR_READV         => crate::syscall_glue_fs::kernel_sys_readv(&args),
        crate::syscall_nrs::NR_POLL          => crate::syscall_glue_fs::kernel_sys_poll(&args),
        crate::syscall_nrs::NR_PPOLL         => crate::syscall_glue_fs::kernel_sys_ppoll(&args),
        crate::syscall_nrs::NR_SELECT        => crate::syscall_glue_fs::kernel_sys_select(&args),
        crate::syscall_nrs::NR_PSELECT6      => crate::syscall_glue_fs::kernel_sys_pselect6(&args),
        crate::syscall_nrs::NR_LSEEK         => crate::syscall_glue_fs::kernel_sys_lseek(&args),
        crate::syscall_nrs::NR_READLINK      => crate::syscall_glue_fs::kernel_sys_readlink(&args),
        crate::syscall_nrs::NR_READLINKAT    => crate::syscall_glue_fs::kernel_sys_readlinkat(&args),
        crate::syscall_nrs::NR_STATX         => crate::syscall_glue_fs::kernel_sys_statx(&args),
        crate::syscall_nrs::NR_FCNTL         => crate::syscall_glue_fs::kernel_sys_fcntl(&args),
        crate::syscall_nrs::NR_RSEQ          => crate::syscall_glue_proc::kernel_sys_rseq(&args),
        crate::syscall_nrs::NR_MEMBARRIER    => crate::syscall_glue_proc::kernel_sys_membarrier(&args),
        crate::syscall_nrs::NR_GETRLIMIT     => crate::syscall_glue_proc::kernel_sys_getrlimit(&args),
        crate::syscall_nrs::NR_SETRLIMIT     => crate::syscall_glue_proc::kernel_sys_setrlimit(&args),
        crate::syscall_nrs::NR_GETRUSAGE     => crate::syscall_glue_proc::kernel_sys_getrusage(&args),
        crate::syscall_nrs::NR_TIMES         => crate::syscall_glue_proc::kernel_sys_times(&args),
        crate::syscall_nrs::NR_SYSINFO       => crate::syscall_glue_proc::kernel_sys_sysinfo(&args),
        crate::syscall_nrs::NR_MREMAP        => crate::syscall_glue_proc::kernel_sys_mremap(&args),
        crate::syscall_nrs::NR_MSYNC         => crate::syscall_glue_proc::kernel_sys_msync(&args),
        crate::syscall_nrs::NR_MINCORE       => crate::syscall_glue_proc::kernel_sys_mincore(&args),
        crate::syscall_nrs::NR_MLOCK | crate::syscall_nrs::NR_MUNLOCK | crate::syscall_nrs::NR_MLOCKALL | crate::syscall_nrs::NR_MUNLOCKALL
                                 => crate::syscall_glue_proc::kernel_sys_mlock_family(&args),
        crate::syscall_nrs::NR_GETPGRP   => crate::syscall_glue_proc::kernel_sys_getpgrp(&args),
        crate::syscall_nrs::NR_GETPRIORITY => crate::syscall_glue_proc::kernel_sys_getpriority(&args),
        crate::syscall_nrs::NR_SETPRIORITY => crate::syscall_glue_proc::kernel_sys_setpriority(&args),
        crate::syscall_nrs::NR_ALARM     => crate::syscall_glue_proc::kernel_sys_alarm(&args),
        crate::syscall_nrs::NR_PAUSE     => crate::syscall_glue_proc::kernel_sys_pause(&args),
        crate::syscall_nrs::NR_GETITIMER => crate::syscall_glue_proc::kernel_sys_getitimer(&args),
        crate::syscall_nrs::NR_SETITIMER => crate::syscall_glue_proc::kernel_sys_setitimer(&args),
        crate::syscall_nrs::NR_PIDFD_OPEN
                                 => crate::dev_pidfd::kernel_sys_pidfd_open(&args),
        crate::syscall_nrs::NR_PIDFD_SEND_SIGNAL
                                 => crate::dev_pidfd::kernel_sys_pidfd_send_signal(&args),
        crate::syscall_nrs::NR_INOTIFY_INIT | crate::syscall_nrs::NR_INOTIFY_INIT1
                                 => crate::dev_inotify::kernel_sys_inotify_init1(&args),
        crate::syscall_nrs::NR_INOTIFY_ADD_WATCH
                                 => crate::dev_inotify::kernel_sys_inotify_add_watch(&args),
        crate::syscall_nrs::NR_INOTIFY_RM_WATCH
                                 => crate::dev_inotify::kernel_sys_inotify_rm_watch(&args),
        crate::syscall_nrs::NR_SIGNALFD | crate::syscall_nrs::NR_SIGNALFD4
                                 => crate::dev_signalfd::kernel_sys_signalfd4(&args),
        crate::syscall_nrs::NR_TIMERFD_CREATE
                                 => crate::dev_timerfd::kernel_sys_timerfd_create(&args),
        crate::syscall_nrs::NR_TIMERFD_SETTIME
                                 => crate::dev_timerfd::kernel_sys_timerfd_settime(&args),
        crate::syscall_nrs::NR_TIMERFD_GETTIME
                                 => crate::dev_timerfd::kernel_sys_timerfd_gettime(&args),
        crate::syscall_nrs::NR_EPOLL_CREATE | crate::syscall_nrs::NR_EPOLL_CREATE1
                                 => crate::dev_epoll::kernel_sys_epoll_create1(&args),
        crate::syscall_nrs::NR_EPOLL_CTL
                                 => crate::dev_epoll::kernel_sys_epoll_ctl(&args),
        crate::syscall_nrs::NR_EPOLL_WAIT | crate::syscall_nrs::NR_EPOLL_PWAIT
            | crate::syscall_nrs::NR_EPOLL_PWAIT2
                                 => crate::dev_epoll::kernel_sys_epoll_wait(&args),
        crate::syscall_nrs::NR_GETPGID   => crate::syscall_glue_proc::kernel_sys_getpgid(&args),
        crate::syscall_nrs::NR_GETSID    => crate::syscall_glue_proc::kernel_sys_getsid(&args),
        crate::syscall_nrs::NR_SETPGID       => crate::syscall_glue_proc::kernel_sys_setpgid(&args),
        crate::syscall_nrs::NR_SETSID        => crate::syscall_glue_proc::kernel_sys_setsid(&args),
        crate::syscall_nrs::NR_UMASK         => crate::syscall_glue_proc::kernel_sys_umask(&args),
        crate::syscall_nrs::NR_ACCESS        => crate::syscall_glue_fs::kernel_sys_access(&args),
        crate::syscall_nrs::NR_FACCESSAT     => crate::syscall_glue_fs::kernel_sys_faccessat(&args),
        crate::syscall_nrs::NR_EVENTFD | crate::syscall_nrs::NR_EVENTFD2
                                 => crate::syscall_glue_fs::kernel_sys_eventfd2(&args),
        crate::syscall_nrs::NR_GETDENTS | crate::syscall_nrs::NR_GETDENTS64
                                 => crate::syscall_glue_fs::kernel_sys_getdents64(&args),
        crate::syscall_nrs::NR_PREAD64       => crate::syscall_glue_fs::kernel_sys_pread64(&args),
        crate::syscall_nrs::NR_PWRITE64      => crate::syscall_glue_fs::kernel_sys_pwrite64(&args),
        crate::syscall_nrs::NR_PREADV  => crate::syscall_glue_fs::kernel_sys_preadv(&args),
        crate::syscall_nrs::NR_PWRITEV => crate::syscall_glue_fs::kernel_sys_pwritev(&args),
        crate::syscall_nrs::NR_PREADV2 => crate::syscall_glue_fs::kernel_sys_preadv(&args),
        crate::syscall_nrs::NR_PWRITEV2 => crate::syscall_glue_fs::kernel_sys_pwritev(&args),
        crate::syscall_nrs::NR_MEMFD_CREATE => crate::syscall_glue_fs::kernel_sys_memfd_create(&args),
        // memfd_secret(flags) — Linux's "hide from other tasks via
        // page-table partitioning" variant. v1 single-AS scheduler
        // doesn't enforce that hide; we route through memfd_create
        // so the fd is at least functional.
        crate::syscall_nrs::NR_MEMFD_SECRET => {
            let mut sa = args; sa.a0 = 0; sa.a1 = args.a0;
            crate::syscall_glue_fs::kernel_sys_memfd_create(&sa)
        }
        crate::syscall_nrs::NR_MKDIR    => crate::syscall_glue_namei::kernel_sys_mkdir(&args),
        crate::syscall_nrs::NR_MKDIRAT  => crate::syscall_glue_namei::kernel_sys_mkdirat(&args),
        crate::syscall_nrs::NR_RMDIR    => crate::syscall_glue_namei::kernel_sys_rmdir(&args),
        crate::syscall_nrs::NR_UNLINK   => crate::syscall_glue_namei::kernel_sys_unlink(&args),
        crate::syscall_nrs::NR_UNLINKAT => crate::syscall_glue_namei::kernel_sys_unlinkat(&args),
        crate::syscall_nrs::NR_RENAME   => crate::syscall_glue_namei::kernel_sys_rename(&args),
        crate::syscall_nrs::NR_RENAMEAT => crate::syscall_glue_namei::kernel_sys_renameat(&args),
        crate::syscall_nrs::NR_RENAMEAT2 => crate::syscall_glue_namei::kernel_sys_renameat2(&args),
        crate::syscall_nrs::NR_TRUNCATE  => crate::syscall_glue_fs::kernel_sys_truncate(&args),
        crate::syscall_nrs::NR_FTRUNCATE => crate::syscall_glue_fs::kernel_sys_ftruncate(&args),
        crate::syscall_nrs::NR_SENDFILE  => crate::syscall_glue_xfer::kernel_sys_sendfile(&args),
        crate::syscall_nrs::NR_COPY_FILE_RANGE => crate::syscall_glue_xfer::kernel_sys_copy_file_range(&args),
        crate::syscall_nrs::NR_SPLICE     => crate::syscall_glue_xfer::kernel_sys_splice(&args),
        crate::syscall_nrs::NR_TEE        => crate::syscall_glue_xfer::kernel_sys_tee(&args),
        crate::syscall_nrs::NR_VMSPLICE   => crate::syscall_glue_xfer::kernel_sys_vmsplice(&args),
        crate::syscall_nrs::NR_OPENAT        => crate::syscall_glue_open::kernel_sys_openat(&args),
        // openat2(dirfd, path, struct open_how*, size). v1 reads the
        // first 16 bytes (flags+mode) and routes through openat;
        // RESOLVE_BENEATH/RESOLVE_NO_SYMLINKS dropped since we don't
        // have the substrate to enforce them safely.
        crate::syscall_nrs::NR_OPENAT2       => {
            let how = args.a2;
            let mut sa = args; sa.a2 = 0;
            if how != 0 && how < USER_VA_END {
                // SAFETY: how validated < USER_VA_END; struct open_how
                // first u64 = flags, second = mode; CPL=0 reads.
                unsafe {
                    sa.a2 = core::ptr::read_volatile(how as *const u64);
                    sa.a3 = core::ptr::read_volatile((how + 8) as *const u64);
                }
            }
            crate::syscall_glue_open::kernel_sys_openat(&sa)
        }
        crate::syscall_nrs::NR_FACCESSAT2    => crate::syscall_glue_fs::kernel_sys_faccessat(&args),
        crate::syscall_nrs::NR_FSYNC | crate::syscall_nrs::NR_FDATASYNC | crate::syscall_nrs::NR_SYNC
                                 => 0,
        // AF_INET dgram (UDP) — `25§3` minimum. The remaining
        // socket calls (LISTEN/ACCEPT/CONNECT/SENDMSG/etc.) wait
        // on TCP + AF_UNIX which are their own arcs.
        crate::syscall_nrs::NR_SOCKET   => crate::syscall_glue_net::kernel_sys_socket(&args),
        crate::syscall_nrs::NR_BIND     => crate::syscall_glue_net::kernel_sys_bind(&args),
        crate::syscall_nrs::NR_SENDTO   => crate::syscall_glue_net::kernel_sys_sendto(&args),
        crate::syscall_nrs::NR_RECVFROM => crate::syscall_glue_net::kernel_sys_recvfrom(&args),
        crate::syscall_nrs::NR_LISTEN  => crate::syscall_glue_net::kernel_sys_listen(&args),
        crate::syscall_nrs::NR_ACCEPT | crate::syscall_nrs::NR_ACCEPT4
                                       => crate::syscall_glue_net::kernel_sys_accept(&args),
        crate::syscall_nrs::NR_CONNECT => crate::syscall_glue_net::kernel_sys_connect(&args),
        crate::syscall_nrs::NR_SOCKETPAIR => crate::syscall_glue_net::kernel_sys_socketpair(&args),
        crate::syscall_nrs::NR_GETSOCKNAME => crate::syscall_glue_net::kernel_sys_getsockname(&args),
        crate::syscall_nrs::NR_GETPEERNAME => crate::syscall_glue_net::kernel_sys_getpeername(&args),
        crate::syscall_nrs::NR_SHUTDOWN    => crate::syscall_glue_net::kernel_sys_shutdown(&args),
        crate::syscall_nrs::NR_SETSOCKOPT  => crate::syscall_glue_net::kernel_sys_setsockopt(&args),
        crate::syscall_nrs::NR_GETSOCKOPT  => crate::syscall_glue_net::kernel_sys_getsockopt(&args),
        crate::syscall_nrs::NR_SENDMSG => crate::syscall_glue_net::kernel_sys_sendmsg(&args),
        crate::syscall_nrs::NR_RECVMSG => crate::syscall_glue_net::kernel_sys_recvmsg(&args),
        crate::syscall_nrs::NR_SENDMMSG => crate::syscall_glue_net::kernel_sys_sendmmsg(&args),
        crate::syscall_nrs::NR_RECVMMSG => crate::syscall_glue_net::kernel_sys_recvmmsg(&args),
        // chmod/chown family — devfs is read-only, but accept silently
        // for tooling that probes mode/owner without erroring.
        crate::syscall_nrs::NR_FCHMOD | crate::syscall_nrs::NR_FCHMODAT | crate::syscall_nrs::NR_CHMOD
            | crate::syscall_nrs::NR_FCHOWN | crate::syscall_nrs::NR_CHOWN | crate::syscall_nrs::NR_LCHOWN
            | crate::syscall_nrs::NR_FCHOWNAT
            | crate::syscall_nrs::NR_UTIMENSAT | crate::syscall_nrs::NR_UTIMES | crate::syscall_nrs::NR_UTIME
                                 => 0,
        // link/symlink/mknod family — devfs is read-only, refuse.
        crate::syscall_nrs::NR_LINK   => crate::syscall_glue_namei::kernel_sys_link(&args),
        crate::syscall_nrs::NR_LINKAT => crate::syscall_glue_namei::kernel_sys_linkat(&args),
        crate::syscall_nrs::NR_SYMLINK | crate::syscall_nrs::NR_SYMLINKAT
            | crate::syscall_nrs::NR_MKNOD | crate::syscall_nrs::NR_MKNODAT
                                 => -(Errno::Erofs.as_i32() as i64),
        crate::syscall_nrs::NR_FSTATFS | crate::syscall_nrs::NR_STATFS
                                 => crate::syscall_glue_fs::kernel_sys_statfs(&args),
        crate::syscall_nrs::NR_GETCPU        => crate::syscall_glue_proc::kernel_sys_getcpu(&args),
        crate::syscall_nrs::NR_SCHED_GETPARAM => crate::syscall_glue_proc::kernel_sys_sched_getparam(&args),
        crate::syscall_nrs::NR_SCHED_SETSCHEDULER | crate::syscall_nrs::NR_SCHED_GETSCHEDULER
                                 => crate::syscall_glue_proc::kernel_sys_sched_getscheduler(&args),
        crate::syscall_nrs::NR_SCHED_GET_PRIORITY_MAX
                                 => crate::syscall_glue_proc::kernel_sys_sched_get_priority_max(&args),
        crate::syscall_nrs::NR_SCHED_GET_PRIORITY_MIN
                                 => crate::syscall_glue_proc::kernel_sys_sched_get_priority_min(&args),
        crate::syscall_nrs::NR_SCHED_GETAFFINITY
                                 => crate::syscall_glue_proc::kernel_sys_sched_getaffinity(&args),
        crate::syscall_nrs::NR_SCHED_SETAFFINITY
                                 => crate::syscall_glue_proc::kernel_sys_sched_setaffinity(&args),
        crate::syscall_nrs::NR_PRCTL         => crate::syscall_glue_proc::kernel_sys_prctl(&args),
        crate::syscall_nrs::NR_FUTEX         => crate::syscall_glue_proc::kernel_sys_futex(&args),
        crate::syscall_nrs::NR_CLONE3        => crate::syscall_glue_proc::kernel_sys_clone3(&args),
        crate::syscall_nrs::NR_MPROTECT      => crate::syscall_glue_proc::kernel_sys_mprotect(&args),
        crate::syscall_nrs::NR_MADVISE       => crate::syscall_glue_proc::kernel_sys_madvise(&args),
        crate::syscall_nrs::NR_PRLIMIT64     => crate::syscall_glue_proc::kernel_sys_prlimit64(&args),
        crate::syscall_nrs::NR_RT_SIGACTION  => crate::syscall_glue_proc::kernel_sys_rt_sigaction(&args),
        crate::syscall_nrs::NR_RT_SIGPROCMASK => crate::syscall_glue_proc::kernel_sys_rt_sigprocmask(&args),
        crate::syscall_nrs::NR_SIGALTSTACK   => crate::syscall_glue_proc::kernel_sys_sigaltstack(&args),
        crate::syscall_nrs::NR_NANOSLEEP     => crate::syscall_glue_proc::kernel_sys_nanosleep(&args),
        crate::syscall_nrs::NR_CLOCK_NANOSLEEP => crate::syscall_glue_proc::kernel_sys_clock_nanosleep(&args),
        crate::syscall_nrs::NR_CLOSE         => kernel_sys_close(&args),
        crate::syscall_nrs::NR_CLOSE_RANGE   => crate::syscall_glue_fs::kernel_sys_close_range(&args),
        crate::syscall_nrs::NR_DUP           => crate::syscall_glue_fs::kernel_sys_dup(&args),
        crate::syscall_nrs::NR_DUP2          => crate::syscall_glue_fs::kernel_sys_dup2(&args),
        crate::syscall_nrs::NR_DUP3          => crate::syscall_glue_fs::kernel_sys_dup3(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_FORK          => kernel_sys_clone_dispatch(&args, 0x11 /* SIGCHLD */, 0, 0, 0, 0),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_VFORK         => kernel_sys_clone_dispatch(&args, 0x4111 /* CLONE_VM|CLONE_VFORK|SIGCHLD */, 0, 0, 0, 0),
        #[cfg(target_arch = "x86_64")]
        // Linux x86_64 clone(flags, child_stack, ptid, ctid, tls).
        crate::syscall_nrs::NR_CLONE         => kernel_sys_clone_dispatch(&args, args.a0, args.a1, args.a2, args.a3, args.a4),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_EXECVE        => crate::syscall_glue_execve::kernel_sys_execve(&args),
        // execveat(dirfd, path, argv, envp, flags). v1 ignores dirfd
        // + flags and routes through execve with the absolute path
        // resolution it already does.
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_EXECVEAT      => {
            let mut sa = args; sa.a0 = args.a1; sa.a1 = args.a2; sa.a2 = args.a3; sa.a3 = 0;
            crate::syscall_glue_execve::kernel_sys_execve(&sa)
        }
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_WAIT4         => kernel_sys_wait4(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_WAITID        => kernel_sys_waitid(&args),
        crate::syscall_nrs::NR_TKILL         => kernel_sys_kill(&args),
        crate::syscall_nrs::NR_RT_SIGPENDING => crate::syscall_glue_proc::kernel_sys_rt_sigpending(&args),
        crate::syscall_nrs::NR_RT_SIGSUSPEND => crate::syscall_glue_proc::kernel_sys_rt_sigsuspend(&args),
        crate::syscall_nrs::NR_RT_SIGTIMEDWAIT  => crate::syscall_glue_proc::kernel_sys_rt_sigtimedwait(&args),
        crate::syscall_nrs::NR_RT_SIGQUEUEINFO  => crate::syscall_glue_proc::kernel_sys_rt_sigqueueinfo(&args),
        crate::syscall_nrs::NR_RT_TGSIGQUEUEINFO => crate::syscall_glue_proc::kernel_sys_rt_tgsigqueueinfo(&args),
        // Real-impl arms that overlap with compat-stub categories.
        crate::syscall_nrs::NR_PIPE          => kernel_sys_pipe2(&args),
        crate::syscall_nrs::NR_CREAT         => crate::syscall_glue_open::kernel_sys_open(&args),
        crate::syscall_nrs::NR_EXIT_GROUP    => kernel_sys_exit(&args),
        crate::syscall_nrs::NR_INIT_MODULE   => kernel_sys_init_module(&args),
        crate::syscall_nrs::NR_FINIT_MODULE  => kernel_sys_finit_module(&args),
        crate::syscall_nrs::NR_DELETE_MODULE => kernel_sys_delete_module(&args),
        crate::syscall_nrs::NR_NEWFSTATAT    => crate::syscall_glue_fs::kernel_sys_statx(&args),
        crate::syscall_nrs::NR_STAT
            | crate::syscall_nrs::NR_LSTAT   => crate::syscall_glue_fs::kernel_sys_stat(&args),
        crate::syscall_nrs::NR_GETRESUID | crate::syscall_nrs::NR_GETRESGID
                                 => crate::syscall_glue_proc::kernel_sys_getres_uid(&args),
        crate::syscall_nrs::NR_GETUID | crate::syscall_nrs::NR_GETEUID
        | crate::syscall_nrs::NR_GETGID | crate::syscall_nrs::NR_GETEGID
                                 => crate::syscall_glue_proc::kernel_sys_getuid_zero(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_RT_SIGRETURN  => {
            // SAFETY: dispatch tail runs on cur's per-task syscall stack; current_user_frame() points at the live saved tail; rt_sigreturn_x86 only reads/writes the user-frame slots and user-stack frame the dispatcher previously installed.
            unsafe { crate::sig_dispatch::rt_sigreturn_x86() }
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::syscall_nrs::NR_RT_SIGRETURN  => 0,
        // Compat-stub fall-through table per P3-46.
        _ => match crate::syscall_compat::try_compat(nr, &args) {
            Some(rv) => rv,
            None     => dispatch(nr as u32, &args),
        },
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    // alarm(2) deadline check: post SIGALRM (sig 14, bit 13) if the
    // task's alarm_ns has passed.
    if let Some(cur) = crate::sched::current() {
        use core::sync::atomic::Ordering;
        let deadline = cur.alarm_ns.load(Ordering::Acquire);
        if deadline != 0 {
            #[cfg(target_arch = "x86_64")]
            let now = { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 };
            #[cfg(target_arch = "aarch64")]
            let now = { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 };
            if now >= deadline {
                let interval = cur.alarm_interval_ns.load(Ordering::Acquire);
                cur.alarm_ns.store(
                    if interval != 0 { now.saturating_add(interval) } else { 0 },
                    Ordering::Release,
                );
                cur.sigpending.fetch_or(1u64 << 13, Ordering::Release);
            }
        }
    }
    // P4-02: syscall-return preempt point per `13§9`. If the tick or
    // a wakeup set need_resched while we were in the kernel, and we
    // hold no preempt_count locks, voluntarily schedule before
    // returning to user. Signal delivery follows so the user sees
    // pending signals after the resched has run.
    if sched::preempt::preempt_count() == 0 && sched::preempt::take_need_resched() {
        // SAFETY: we are at syscall-return tail, IRQs unmasked, no
        // spinlocks held; matches schedule()'s `# Ctx: process|kthread`
        // requirement per `13§8`.
        unsafe { crate::sched::schedule(); }
    }
    // P3-65: deliver pending signals at syscall return.
    if let Some(p) = crate::syscall_glue_proc::take_lowest_pending() {
        // Job-control signals come first — their default action is
        // stop / continue, not terminate, regardless of handler.
        // SIGSTOP (19) is uncatchable per signal(7); the others (TSTP
        // 20, TTIN 21, TTOU 22) honour a user handler.
        if matches!(p.sig, 19) || (matches!(p.sig, 20 | 21 | 22) && p.handler == 0) {
            #[cfg(target_arch = "x86_64")]
            { crate::sched_stop::stop_until_cont(); }
            return rv as u64;
        }
        if p.sig == 18 {
            // SIGCONT — default no-op. User handler dispatches normally;
            // SIG_DFL silently drops.
            if p.handler != 0 && p.handler != 1 {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: dispatch tail; same conditions as the SIG_DFL→handler arm below.
                unsafe { crate::sig_dispatch::deliver_x86(p.handler, p.restorer, p.sig); }
            }
            return rv as u64;
        }
        match p.handler {
            0 => {
                // SIG_DFL — Linux per signal(7) defaults: SIGCHLD (17),
                // SIGURG (23), SIGWINCH (28) ignore; others terminate.
                if !matches!(p.sig, 17 | 23 | 28) {
                    let exit_args = SyscallArgs { a0: (128 + p.sig) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
                    let _ = kernel_sys_exit(&exit_args);
                }
            }
            1 => {  /* SIG_IGN: drop */ }
            #[cfg(target_arch = "x86_64")]
            handler => {
                // SAFETY: dispatch tail runs on cur's per-task syscall stack; current_user_frame() points at the live saved tail; we rewrite it so sysretq enters the user handler with the constructed frame on the user stack.
                unsafe { crate::sig_dispatch::deliver_x86(handler, p.restorer, p.sig); }
            }
            #[cfg(not(target_arch = "x86_64"))]
            _handler => {
                // arm sa_handler dispatch is M2 follow-up; terminate as fallback.
                let exit_args = SyscallArgs { a0: (128 + p.sig) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
                let _ = kernel_sys_exit(&exit_args);
            }
        }
    }
    rv as u64
}
