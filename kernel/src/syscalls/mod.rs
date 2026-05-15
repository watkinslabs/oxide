// Glue between per-arch syscall asm stub and dispatch table per `15§4`.

#![cfg(target_os = "oxide-kernel")]

pub mod anonfd; pub mod chroot; pub mod clone;  pub mod execve;  pub mod fs; pub mod hwrng; pub mod ioctl; pub mod landlock; pub mod misc; pub mod mmap_file; pub mod net; pub mod mount; pub mod namei;  pub mod newfstatat; pub mod open; pub mod perms;  pub mod proc;  pub mod ptrace_fpu; pub mod pvmrw;  pub mod select; pub mod signal; pub mod time;  pub mod uname; pub mod utime;  pub mod hostname;


use syscall::{dispatch, SyscallArgs};
use syscall::errno::Errno;
use hal::{USER_VA_END};
#[cfg(target_arch = "x86_64")]
use hal::TimerOps;

fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd     = args.a4 as i64;
    let offset = args.a5;
    let flags  = args.a3;
    const MAP_ANON: u64 = 0x20;
    // File-backed mmap: resolve fd, wrap as FileBacking, pass to
    // glue_mmap. Anonymous goes through the None path.
    let backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>> =
        if (flags & MAP_ANON) == 0 && fd >= 0 {
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
            };
            // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
            let fdt = match unsafe { cur.fd_table_ref() } {
                Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
            };
            let file = match fdt.get(fd as i32) {
                Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
            };
            Some(mmap_file::InodeFileBacking::new(file.inode().clone()))
        } else { None };
    match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, offset, backing) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

fn kernel_munmap(args: &SyscallArgs) -> i64 {
    pmm::user_as::glue_munmap(args.a0, args.a1)
}

/// sys_read via fd_table.
/// # C: O(cnt) on the underlying inode read
/// `sys_read(fd, buf, cnt)` — slot 0. Tier-3 shim per `docs/53§4`:
/// parse → validate → fetch → call → encode. Work fn lives in
/// `vfs::File::read` (Tier 2).
/// # C: O(cnt) on the underlying inode read.
pub fn sys_read(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2 as usize;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf_writable(buf, cnt as u64, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END by validate_user_buf_writable; user pages mapped via active CR3; demand-paging resolves not-present pages on first kernel-side write.
    let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, cnt) };
    match file.read(slice) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_write(fd, buf, cnt)` — slot 1. Tier-3 shim per `docs/53§4`.
/// Work fn: `vfs::File::write` (Tier 2).
/// # C: O(cnt) on the underlying inode write.
pub fn sys_write(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2 as usize;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt as u64, 1) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END by validate_user_buf; CPL=0 reads through caller's AS mapping.
    let slice: &[u8] = unsafe { core::slice::from_raw_parts(buf as *const u8, cnt) };
    match file.write(slice) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

fn sys_pipe2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    let pipefd = args.a0;
    let flags  = args.a1 as u32;
    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC:  u32 = 0o2000000;
    if pipefd == 0 || pipefd >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let inode = ::fs::pipe::PipeInode::new();
    inode.writers.store(1, core::sync::atomic::Ordering::Release);
    inode.readers.store(1, core::sync::atomic::Ordering::Release);
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

/// sys_brk — adjust brk within ELF heap VMA. F158: enforces
/// RLIMIT_DATA per Linux semantic.
fn sys_brk(args: &SyscallArgs) -> i64 {
    let req = args.a0;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: running task, no concurrent mm writer per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    if req == 0 { return mm.brk() as i64; }
    // SAFETY: rlimits single-mutator per `13§5`.
    let rlim_data = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::DATA].0 };
    let cur_brk = mm.brk();
    if rlim_data != sched::rlimit::INFINITY
        && req > cur_brk && req - cur_brk > rlim_data {
        return cur_brk as i64;
    }
    mm.try_set_brk(req) as i64
}

/// `sys_close(fd)` — slot 3. Tier-3 shim per `docs/53§4`.
/// Work fn: `vfs::FdTable::close` (Tier 2).
/// # C: O(1)
pub fn sys_close(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.close(fd) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    }
}

fn sys_getpid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    sched::live::current()
        .map(|c| {
            // F105: PID NS — return virtualized vtgid if non-zero,
            // else real tgid. Init NS tasks have vtgid=0 → real tgid.
            let v = c.vtgid.load(Ordering::Acquire);
            if v != 0 { v as i64 } else { c.tgid.load(Ordering::Acquire) as i64 }
        })
        .unwrap_or(1)
}

fn sys_getppid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let ppid = cur.parent_tid.load(Ordering::Acquire);
    // F105: in a non-init pid_ns, parent visible only if it's in the
    // same NS. Tasks in init NS see real ppid as before.
    let cur_ns = cur.pid_ns.load(Ordering::Acquire);
    if cur_ns == 0 { return ppid as i64; }
    match sched::live::registry::lookup(ppid) {
        Some(p) if p.pid_ns.load(Ordering::Acquire) == cur_ns => {
            let v = p.vtgid.load(Ordering::Acquire);
            if v != 0 { v as i64 } else { p.tgid.load(Ordering::Acquire) as i64 }
        }
        _ => 0, // parent not visible from our NS — Linux reports 0 (no parent).
    }
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
fn sys_waitid(args: &SyscallArgs) -> i64 {
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
    let rv = sys_wait4(&sa);
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

fn sys_wait4(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    const WNOHANG: u64 = 1;
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let options = args.a2;
    let _rusage  = args.a3;

    let parent_tid = match sched::live::current() {
        Some(c) => c.tid,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // Loop: try to reap; if no match, yield + retry. Bounded
    // because schedule() picks runnable children which eventually
    // exit + park.
    loop {
        if let Some((tid, code)) = sched::live::reap_one(parent_tid, pid) {
            // POSIX wstatus encoding:
            //   WIFEXITED:    low 7 bits = 0,  bits 8..16 = exit code
            //   WIFSIGNALED:  low 7 bits = signal number, bit 7 = core
            // We use bit 8 of the kernel-side `exit_status` as a
            // "killed-by-signal" marker (set by `sigsegv_terminate_*`,
            // tgkill SIGSEGV/SIGKILL paths). _exit just stores the
            // user-supplied code in the low 8 bits.
            let wstat: i32 = if code & 0x100 != 0 {
                code & 0x7f
            } else {
                (code & 0xff) << 8
            };
            if wstatus != 0 && wstatus < USER_VA_END {
                // SAFETY: wstatus validated < USER_VA_END; user page mapped (caller's user code already executed from this AS); CPL=0 reads/writes through the user mapping.
                unsafe { core::ptr::write_volatile(wstatus as *mut i32, wstat); }
            }
            debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
            return tid as i64;
        }
        // POSIX: wait4 returns -ECHILD if the calling task has no
        // unwaited-for children at all. Without this check the
        // do-while-pid>=0 drain loops in busybox hush + every other
        // userspace shell block forever once the last child exits.
        // Linux returns ECHILD before checking WNOHANG.
        if !sched::live::registry::has_children(parent_tid) {
            return -(Errno::Echild.as_i32() as i64);
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
        unsafe { sched::live::park_for_wait4(); }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
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
fn sys_delete_module(args: &SyscallArgs) -> i64 {
    let idx = args.a0 as usize & 0xFFFF;
    if modules::registry::unload(idx) { 0 } else { -(Errno::Einval.as_i32() as i64) }
}

/// `init_module(image, len, params)` slot 175.
/// `image` is a user-mapped pointer to the .ko bytes; `len` is
/// the size; `params` ignored for v1.
fn sys_init_module(args: &SyscallArgs) -> i64 {
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
    match modules::registry::load_blob(&bytes) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}

/// `finit_module(fd, params, flags)` slot 313. Reads the file
/// content via the fd then delegates to load_blob. v1 caps file
/// size at 16 MiB.
fn sys_finit_module(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
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
    match modules::registry::load_blob(&buf) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}

fn sys_exit(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let _ = args;
    // No runqueue (arm direct drop_to_el0 pre-P2-13e): nothing
    // to Zombie. Pre-P2-22 fallthrough behavior.
    if sched::live::global().is_none() {
        return 0;
    }
    if let Some(rq) = sched::live::global() {
        // Mark prev Zombie + post SIGCHLD without bumping the
        // rq.current strong count. `schedule()` below detects
        // the Zombie state on prev and transfers the swap_current-
        // returned Arc into ZOMBIES — that avoids the prior leak
        // where the bumped Arc was permanently stranded on the
        // dead task's kernel-stack frame inside `schedule()`.
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current was installed via Arc::into_raw and is non-null after install_global; the AtomicPtr's strong-ref-via-raw keeps the pointee alive across this borrow; we are running ON this task so no concurrent freer.
            let task: &sched::Task = unsafe { &*raw };
            task.exit_status.store(args.a0 as i32, Ordering::Release);
            task.vfork_pending.store(false, Ordering::Release); // F156 vfork
            sched::live::mark_done(task);
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_exit: tid=");
                klog::write_dec_u64(task.tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(args.a0);
                klog::write_raw(b"\n");
            }
            sched::live::signal_child_exit(task);
        }
    }
    // SAFETY: process ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { sched::live::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}

/// `sys_getrandom(buf, len, flags)` — slot 318. Prefers hardware
/// RNG (RDRAND on x86_64, RNDR on aarch64); falls back to a
/// per-boot LCG if HW RNG returns failure (CF=0 on RDRAND;
/// NZCV.V=1 on RNDR).
fn sys_getrandom(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let len  = args.a1;
    let _fl  = args.a2;
    if len == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, len, 1) { return rv; }
    let mut written: u64 = 0;
    while written < len {
        let v = hwrng::hw_random_u64().unwrap_or_else(devfs::misc::lcg_next).to_le_bytes();
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


use crate::syscalls::signal::{sys_kill, sys_tgkill};

/// PTRACE_SYSCALL self-stop. Snapshots SIGTRAP siginfo (+0x80
/// when PTRACE_O_TRACESYSGOOD), sets SIGTRAP pending, parks.
/// # C: O(1)
fn ptrace_syscall_stop_if_armed() {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return; }
    // SIGTRAP siginfo snapshot; O_TRACESYSGOOD marks code with 0x80.
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    let code = if (opts & 0x1) != 0 { 0x80 } else { 0 };
    let tracer = cur.traced_by.load(Ordering::Acquire);
    *cur.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: 5, code, pid: tracer, uid: 0, value: 0,
    });
    crate::syscalls::ptrace_fpu::snapshot_current();
    cur.sigpending.fetch_or(1u64 << 4, Ordering::Release); // SIGTRAP
    // SAFETY: process ctx; runqueue installed; preempt-off; immediate self-park via stop_until_cont matches the SIGSTOP path.
    unsafe { sched::live::stop::stop_until_cont(); }
    // Wake: SETFPREGS-modified snapshot → restore before returning
    // to user mode so the new state takes effect.
    crate::syscalls::ptrace_fpu::restore_if_dirty();
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

/// Same as `validate_user_buf` but also confirms every page in
/// the range belongs to a VMA carrying `VmaProt::WRITE`. Used by
/// syscalls that perform kernel-side writes into user buffers
/// (getcwd / read / readv / readlinkat / uname / ...). Without
/// this, a userspace caller passing a pointer into its own
/// .rodata or .text segment would trigger a #PF in CPL=0 when
/// CR0.WP=1 — the kernel doesn't have an extable, so the fault
/// halts the whole system. Pre-validating returns -EFAULT to the
/// syscall caller, which is what the user expected anyway.
/// # C: O(N_pages * log N_vmas) — typically O(1)
pub(crate) fn validate_user_buf_writable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    use hal::UserVirtAddr;
    use vmm::VmaProt;
    validate_user_buf(ptr, len, align)?;
    if len == 0 { return Ok(()); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    // SAFETY: mm slot single-mutator per `13§5`; we are the running task on this CPU and the sole reader during the syscall.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    let mut va = ptr & !0xFFF;
    let end_inclusive = ptr + len - 1;
    while va <= (end_inclusive & !0xFFF) {
        let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
        match mm.find_vma(uva) {
            Some(v) if v.prot.contains(VmaProt::WRITE) => {}
            _ => return Err(-(Errno::Efault.as_i32() as i64)),
        }
        va = va.checked_add(0x1000).ok_or(-(Errno::Efault.as_i32() as i64))?;
    }
    Ok(())
}

/// arch_prctl: ARCH_SET_FS=wrmsr, ARCH_GET_FS=rdmsr+writeback,
/// else EINVAL. GS-base is a follow-up (kernel GS-base reserved).
#[cfg(target_arch = "x86_64")]
fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        syscall::nrs::ARCH_SET_FS => {
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
        syscall::nrs::ARCH_GET_FS => {
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
    // arm64 uses generic numbering; remap to x86_64 (the table key).
    #[cfg(target_arch = "aarch64")]
    let nr = syscall::arm_abi::aarch64_nr_to_x86(nr);

    let args = SyscallArgs { a0, a1, a2, a3, a4, a5: 0 };
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2); }
    // seccomp KILL/TRAP/ERRNO/ALLOW filter check.
    if let Err(rv) = crate::seccomp::check(nr, &[a0, a1, a2, a3, a4, 0]) { return rv as u64; }
    // F108: PTRACE_SYSCALL — if a tracer armed us, self-stop at entry.
    ptrace_syscall_stop_if_armed();
    // Arch-specific + per-arch-time syscalls handled here (kernel can
    // call hal); others fall through to the arch-neutral dispatch.
    let rv = match nr {
        #[cfg(target_arch = "x86_64")]
        syscall::nrs::NR_ARCH_PRCTL    => kernel_arch_prctl(&args),
        syscall::nrs::NR_CLOCK_GETTIME => crate::syscalls::time::kernel_clock_gettime(&args),
        syscall::nrs::NR_CLOCK_GETRES  => crate::syscalls::time::kernel_clock_getres(&args),
        syscall::nrs::NR_CLOCK_SETTIME => crate::syscalls::time::kernel_clock_settime(&args),
        syscall::nrs::NR_GETTIMEOFDAY  => crate::syscalls::time::kernel_gettimeofday(&args),
        syscall::nrs::NR_SETTIMEOFDAY  => crate::syscalls::time::kernel_settimeofday(&args),
        syscall::nrs::NR_TIME          => crate::syscalls::time::kernel_time(&args),
        syscall::nrs::NR_UNAME         => crate::syscalls::uname::kernel_uname(&args),
        syscall::nrs::NR_SETHOSTNAME   => crate::syscalls::proc::sys_sethostname(&args),
        syscall::nrs::NR_SETDOMAINNAME => crate::syscalls::hostname::sys_setdomainname(&args),
        syscall::nrs::NR_MMAP          => kernel_mmap(&args),
        syscall::nrs::NR_MUNMAP        => kernel_munmap(&args),
        syscall::nrs::NR_EXIT          => sys_exit(&args),
        syscall::nrs::NR_GETPID        => sys_getpid(&args),
        syscall::nrs::NR_GETPPID       => sys_getppid(&args),
        syscall::nrs::NR_READ          => sys_read(&args),
        syscall::nrs::NR_WRITE         => sys_write(&args),
        syscall::nrs::NR_OPEN          => crate::syscalls::open::sys_open(&args),
        syscall::nrs::NR_BRK           => sys_brk(&args),
        syscall::nrs::NR_PIPE2         => sys_pipe2(&args),
        syscall::nrs::NR_FSTAT         => crate::syscalls::fs::sys_fstat(&args),
        syscall::nrs::NR_IOCTL         => crate::syscalls::fs::sys_ioctl(&args),
        syscall::nrs::NR_GETCWD        => crate::syscalls::fs::sys_getcwd(&args),
        syscall::nrs::NR_CHDIR         => crate::syscalls::fs::sys_chdir(&args),
        syscall::nrs::NR_FCHDIR        => crate::syscalls::fs::sys_fchdir(&args),
        syscall::nrs::NR_KILL          => sys_kill(&args),
        syscall::nrs::NR_TGKILL        => sys_tgkill(&args),
        syscall::nrs::NR_GETRANDOM     => sys_getrandom(&args),
        syscall::nrs::NR_SCHED_YIELD   => crate::syscalls::proc::sys_sched_yield(&args),
        syscall::nrs::NR_GETTID        => crate::syscalls::proc::sys_gettid(&args),
        syscall::nrs::NR_SET_TID_ADDRESS => crate::syscalls::proc::sys_set_tid_address(&args),
        syscall::nrs::NR_WRITEV        => crate::syscalls::fs::sys_writev(&args),
        syscall::nrs::NR_READV         => crate::syscalls::fs::sys_readv(&args),
        syscall::nrs::NR_POLL          => crate::syscalls::fs::sys_poll(&args),
        syscall::nrs::NR_PPOLL         => crate::syscalls::fs::sys_ppoll(&args),
        syscall::nrs::NR_SELECT        => crate::syscalls::select::sys_select(&args),
        syscall::nrs::NR_PSELECT6      => crate::syscalls::select::sys_pselect6(&args),
        syscall::nrs::NR_LSEEK         => crate::syscalls::fs::sys_lseek(&args),
        syscall::nrs::NR_READLINK      => crate::syscalls::fs::sys_readlink(&args),
        syscall::nrs::NR_READLINKAT    => crate::syscalls::fs::sys_readlinkat(&args),
        syscall::nrs::NR_STATX         => crate::syscalls::fs::sys_statx(&args),
        syscall::nrs::NR_FCNTL         => crate::syscalls::fs::sys_fcntl(&args),
        syscall::nrs::NR_RSEQ          => crate::syscalls::proc::sys_rseq(&args),
        syscall::nrs::NR_MEMBARRIER    => crate::syscalls::proc::sys_membarrier(&args),
        syscall::nrs::NR_UNSHARE       => crate::syscalls::signal::sys_unshare(&args),
        syscall::nrs::NR_SETNS         => crate::syscalls::signal::sys_setns(&args),
        syscall::nrs::NR_PTRACE        => crate::syscalls::signal::sys_ptrace(&args),
        syscall::nrs::NR_FANOTIFY_INIT => ::fs::inotify::sys_inotify_init1(&args),
        syscall::nrs::NR_FANOTIFY_MARK => ::fs::inotify::sys_fanotify_mark(&args),
        syscall::nrs::NR_SHMGET        => ipc::sysv_shm::sys_shmget(&args),
        syscall::nrs::NR_SHMAT         => ipc::sysv_shm::sys_shmat(&args),
        syscall::nrs::NR_SHMDT         => ipc::sysv_shm::sys_shmdt(&args),
        syscall::nrs::NR_SHMCTL        => ipc::sysv_shm::sys_shmctl(&args),
        syscall::nrs::NR_SEMGET        => ::ipc::live::sysv_sem::sys_semget(&args),
        syscall::nrs::NR_SEMOP         => ::ipc::live::sysv_sem::sys_semop(&args),
        syscall::nrs::NR_SEMCTL        => ::ipc::live::sysv_sem::sys_semctl(&args),
        syscall::nrs::NR_SEMTIMEDOP    => ::ipc::live::sysv_sem::sys_semtimedop(&args),
        syscall::nrs::NR_MSGGET        => ::ipc::live::sysv_msg::sys_msgget(&args),
        syscall::nrs::NR_MSGSND        => ::ipc::live::sysv_msg::sys_msgsnd(&args),
        syscall::nrs::NR_MSGRCV        => ::ipc::live::sysv_msg::sys_msgrcv(&args),
        syscall::nrs::NR_MSGCTL        => ::ipc::live::sysv_msg::sys_msgctl(&args),
        syscall::nrs::NR_MQ_OPEN         => ::ipc::live::posix_mq::sys_mq_open(&args),
        syscall::nrs::NR_MQ_UNLINK       => ::ipc::live::posix_mq::sys_mq_unlink(&args),
        syscall::nrs::NR_MQ_TIMEDSEND    => ::ipc::live::posix_mq::sys_mq_timedsend(&args),
        syscall::nrs::NR_MQ_TIMEDRECEIVE => ::ipc::live::posix_mq::sys_mq_timedreceive(&args),
        syscall::nrs::NR_IO_URING_SETUP    => crate::io_uring::sys_io_uring_setup(&args),
        syscall::nrs::NR_IO_URING_ENTER    => crate::io_uring::sys_io_uring_enter(&args),
        syscall::nrs::NR_IO_URING_REGISTER => crate::io_uring::sys_io_uring_register(&args),
        syscall::nrs::NR_SECCOMP       => crate::seccomp::sys_seccomp(&args),
        // bpf(cmd, attr, size): admit fd-creating commands (BPF_PROG_LOAD,
        // BPF_MAP_CREATE) by returning a sentinel fd backed by an
        // anonymous tmpfs inode. v1 doesn't run loaded BPF programs;
        // verifier + JIT ride a follow-up. Other cmds → -ENOSYS so
        // userspace doesn't think it has a working bpf() world.
        syscall::nrs::NR_BPF           => crate::dev_bpf::sys_bpf(&args),
        syscall::nrs::NR_LANDLOCK_CREATE_RULESET => crate::syscalls::landlock::sys_landlock_create_ruleset(&args),
        syscall::nrs::NR_LANDLOCK_ADD_RULE       => crate::syscalls::landlock::sys_landlock_add_rule(&args),
        syscall::nrs::NR_LANDLOCK_RESTRICT_SELF  => crate::syscalls::landlock::sys_landlock_restrict_self(&args),
        // perf_event_open: real PerfEventInode whose read returns the
        // monotonic-ns sample since open; ioctl handles ENABLE/DISABLE/
        // RESET/REFRESH. PMU hardware sampling + ring-buffer mmap
        // ride follow-ups.
        syscall::nrs::NR_PERF_EVENT_OPEN => ::fs::perf::sys_perf_event_open(&args),
        syscall::nrs::NR_USERFAULTFD => ::fs::userfaultfd::sys_userfaultfd(&args),
        // Modern mount API (P29a). fsopen/fsmount/fspick/open_tree return
        // memfd-backed fds tagged with the call's identity for future
        // mount-table integration; fsconfig/move_mount/mount_setattr admit
        // (real per-NS mount-table machinery rides a follow-up).
        syscall::nrs::NR_FSOPEN     => {
            let mut sa = args; sa.a0 = 0; sa.a1 = 1;
            crate::syscalls::anonfd::sys_memfd_create(&sa)
        }
        syscall::nrs::NR_FSMOUNT    => {
            let mut sa = args; sa.a0 = 0; sa.a1 = 1;
            crate::syscalls::anonfd::sys_memfd_create(&sa)
        }
        syscall::nrs::NR_FSPICK     => {
            let mut sa = args; sa.a0 = 0; sa.a1 = 1;
            crate::syscalls::anonfd::sys_memfd_create(&sa)
        }
        syscall::nrs::NR_OPEN_TREE  => {
            let mut sa = args; sa.a0 = 0; sa.a1 = 1;
            crate::syscalls::anonfd::sys_memfd_create(&sa)
        }
        // fsconfig/move_mount/mount_setattr → EOPNOTSUPP (silent-0 lied).
        syscall::nrs::NR_FSCONFIG | syscall::nrs::NR_MOVE_MOUNT
            | syscall::nrs::NR_MOUNT_SETATTR => -(Errno::Eopnotsupp.as_i32() as i64),
        syscall::nrs::NR_GETRLIMIT     => crate::syscalls::proc::sys_getrlimit(&args),
        syscall::nrs::NR_SETRLIMIT     => crate::syscalls::proc::sys_setrlimit(&args),
        syscall::nrs::NR_GETRUSAGE     => crate::syscalls::proc::sys_getrusage(&args),
        syscall::nrs::NR_TIMES         => crate::syscalls::proc::sys_times(&args),
        syscall::nrs::NR_SYSINFO       => crate::syscalls::proc::sys_sysinfo(&args),
        syscall::nrs::NR_MREMAP        => crate::syscalls::proc::sys_mremap(&args),
        syscall::nrs::NR_MSYNC         => crate::syscalls::proc::sys_msync(&args),
        syscall::nrs::NR_MINCORE       => crate::syscalls::proc::sys_mincore(&args),
        syscall::nrs::NR_MLOCK | syscall::nrs::NR_MUNLOCK | syscall::nrs::NR_MLOCKALL | syscall::nrs::NR_MUNLOCKALL
                                 => crate::syscalls::proc::sys_mlock_family(&args),
        syscall::nrs::NR_GETPGRP   => crate::syscalls::proc::sys_getpgrp(&args),
        syscall::nrs::NR_GETPRIORITY => crate::syscalls::proc::sys_getpriority(&args),
        syscall::nrs::NR_SETPRIORITY => crate::syscalls::proc::sys_setpriority(&args),
        syscall::nrs::NR_ALARM     => crate::syscalls::proc::sys_alarm(&args),
        syscall::nrs::NR_PAUSE     => crate::syscalls::proc::sys_pause(&args),
        syscall::nrs::NR_GETITIMER => crate::syscalls::proc::sys_getitimer(&args),
        syscall::nrs::NR_SETITIMER => crate::syscalls::proc::sys_setitimer(&args),
        syscall::nrs::NR_PIDFD_OPEN  => crate::dev::pidfd::sys_pidfd_open(&args),
        syscall::nrs::NR_PIDFD_GETFD => crate::dev::pidfd::sys_pidfd_getfd(&args),
        syscall::nrs::NR_PIDFD_SEND_SIGNAL
                                 => crate::dev::pidfd::sys_pidfd_send_signal(&args),
        syscall::nrs::NR_INOTIFY_INIT | syscall::nrs::NR_INOTIFY_INIT1
                                 => ::fs::inotify::sys_inotify_init1(&args),
        syscall::nrs::NR_INOTIFY_ADD_WATCH
                                 => ::fs::inotify::sys_inotify_add_watch(&args),
        syscall::nrs::NR_INOTIFY_RM_WATCH
                                 => ::fs::inotify::sys_inotify_rm_watch(&args),
        syscall::nrs::NR_SIGNALFD | syscall::nrs::NR_SIGNALFD4
                                 => ::fs::signalfd::sys_signalfd4(&args),
        syscall::nrs::NR_TIMERFD_CREATE
                                 => ::fs::timerfd::sys_timerfd_create(&args),
        syscall::nrs::NR_TIMERFD_SETTIME
                                 => ::fs::timerfd::sys_timerfd_settime(&args),
        syscall::nrs::NR_TIMERFD_GETTIME
                                 => ::fs::timerfd::sys_timerfd_gettime(&args),
        syscall::nrs::NR_EPOLL_CREATE | syscall::nrs::NR_EPOLL_CREATE1
                                 => ::fs::epoll::sys_epoll_create1(&args),
        syscall::nrs::NR_EPOLL_CTL
                                 => ::fs::epoll::sys_epoll_ctl(&args),
        syscall::nrs::NR_EPOLL_WAIT | syscall::nrs::NR_EPOLL_PWAIT
            | syscall::nrs::NR_EPOLL_PWAIT2
                                 => ::fs::epoll::sys_epoll_wait(&args),
        syscall::nrs::NR_GETPGID   => crate::syscalls::proc::sys_getpgid(&args),
        syscall::nrs::NR_GETSID    => crate::syscalls::proc::sys_getsid(&args),
        syscall::nrs::NR_SETPGID       => crate::syscalls::proc::sys_setpgid(&args),
        syscall::nrs::NR_SETSID        => crate::syscalls::proc::sys_setsid(&args),
        syscall::nrs::NR_UMASK         => crate::syscalls::proc::sys_umask(&args),
        syscall::nrs::NR_ACCESS        => crate::syscalls::fs::sys_access(&args),
        syscall::nrs::NR_FACCESSAT     => crate::syscalls::fs::sys_faccessat(&args),
        syscall::nrs::NR_EVENTFD | syscall::nrs::NR_EVENTFD2
                                 => crate::syscalls::anonfd::sys_eventfd2(&args),
        syscall::nrs::NR_GETDENTS | syscall::nrs::NR_GETDENTS64
                                 => crate::syscalls::fs::sys_getdents64(&args),
        syscall::nrs::NR_PREAD64       => crate::syscalls::fs::sys_pread64(&args),
        syscall::nrs::NR_PWRITE64      => crate::syscalls::fs::sys_pwrite64(&args),
        syscall::nrs::NR_PREADV  => crate::syscalls::fs::sys_preadv(&args),
        syscall::nrs::NR_PWRITEV => crate::syscalls::fs::sys_pwritev(&args),
        syscall::nrs::NR_PREADV2 => crate::syscalls::fs::sys_preadv(&args),
        syscall::nrs::NR_PWRITEV2 => crate::syscalls::fs::sys_pwritev(&args),
        syscall::nrs::NR_MEMFD_CREATE => crate::syscalls::anonfd::sys_memfd_create(&args),
        // memfd_secret(flags) — Linux's "hide from other tasks via
        // page-table partitioning" variant. v1 single-AS scheduler
        // doesn't enforce that hide; we route through memfd_create
        // so the fd is at least functional.
        syscall::nrs::NR_MEMFD_SECRET => {
            let mut sa = args; sa.a0 = 0; sa.a1 = args.a0;
            crate::syscalls::anonfd::sys_memfd_create(&sa)
        }
        syscall::nrs::NR_MKDIR    => crate::syscalls::namei::sys_mkdir(&args),
        syscall::nrs::NR_MKDIRAT  => crate::syscalls::namei::sys_mkdirat(&args),
        syscall::nrs::NR_RMDIR    => crate::syscalls::namei::sys_rmdir(&args),
        syscall::nrs::NR_UNLINK   => crate::syscalls::namei::sys_unlink(&args),
        syscall::nrs::NR_UNLINKAT => crate::syscalls::namei::sys_unlinkat(&args),
        syscall::nrs::NR_RENAME   => crate::syscalls::namei::sys_rename(&args),
        syscall::nrs::NR_RENAMEAT => crate::syscalls::namei::sys_renameat(&args),
        syscall::nrs::NR_RENAMEAT2 => crate::syscalls::namei::sys_renameat2(&args),
        syscall::nrs::NR_TRUNCATE  => crate::syscalls::fs::sys_truncate(&args),
        syscall::nrs::NR_FTRUNCATE => crate::syscalls::fs::sys_ftruncate(&args),
        syscall::nrs::NR_FALLOCATE => sched::falloc::sys_fallocate(&args),
        syscall::nrs::NR_SENDFILE  => sched::xfer::sys_sendfile(&args),
        syscall::nrs::NR_COPY_FILE_RANGE => sched::xfer::sys_copy_file_range(&args),
        syscall::nrs::NR_SPLICE     => sched::xfer::sys_splice(&args),
        syscall::nrs::NR_TEE        => sched::xfer::sys_tee(&args),
        syscall::nrs::NR_VMSPLICE   => sched::xfer::sys_vmsplice(&args),
        syscall::nrs::NR_OPENAT        => crate::syscalls::open::sys_openat(&args),
        // openat2: read flags+mode from open_how, route through openat.
        syscall::nrs::NR_OPENAT2       => {
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
            crate::syscalls::open::sys_openat(&sa)
        }
        syscall::nrs::NR_FACCESSAT2    => crate::syscalls::fs::sys_faccessat(&args),
        syscall::nrs::NR_SYNC => 0,
        syscall::nrs::NR_REBOOT => crate::syscalls::misc::sys_reboot(&args),
        nr if matches!(nr, syscall::nrs::NR_FSYNC | syscall::nrs::NR_FDATASYNC
                       | syscall::nrs::NR_SYNCFS | syscall::nrs::NR_SYNC_FILE_RANGE)
                                 => crate::syscalls::misc::sys_fsync(&args),
        nr if matches!(nr, syscall::nrs::NR_PKEY_ALLOC | syscall::nrs::NR_PKEY_FREE
                       | syscall::nrs::NR_PKEY_MPROTECT | syscall::nrs::NR_KCMP
                       | syscall::nrs::NR_SET_MEMPOLICY | syscall::nrs::NR_GET_MEMPOLICY
                       | syscall::nrs::NR_MBIND | syscall::nrs::NR_SET_MEMPOLICY_HOME_NODE
                       | syscall::nrs::NR_MIGRATE_PAGES | syscall::nrs::NR_MOVE_PAGES
                       | syscall::nrs::NR_PROCESS_MADVISE | syscall::nrs::NR_PROCESS_MRELEASE)
                                 => crate::syscalls::misc::dispatch(nr, &args),
        // AF_INET dgram (UDP) per `25§3`.
        syscall::nrs::NR_SOCKET   => crate::syscalls::net::sys_socket(&args),
        syscall::nrs::NR_BIND     => crate::syscalls::net::sys_bind(&args),
        syscall::nrs::NR_SENDTO   => crate::syscalls::net::sys_sendto(&args),
        syscall::nrs::NR_RECVFROM => crate::syscalls::net::sys_recvfrom(&args),
        syscall::nrs::NR_LISTEN  => crate::syscalls::net::sys_listen(&args),
        syscall::nrs::NR_ACCEPT | syscall::nrs::NR_ACCEPT4
                                       => crate::syscalls::net::sys_accept(&args),
        syscall::nrs::NR_CONNECT => crate::syscalls::net::sys_connect(&args),
        syscall::nrs::NR_SOCKETPAIR => crate::syscalls::net::sys_socketpair(&args),
        syscall::nrs::NR_GETSOCKNAME => crate::syscalls::net::sys_getsockname(&args),
        syscall::nrs::NR_GETPEERNAME => crate::syscalls::net::sys_getpeername(&args),
        syscall::nrs::NR_SHUTDOWN    => crate::syscalls::net::sys_shutdown(&args),
        syscall::nrs::NR_SETSOCKOPT  => crate::syscalls::net::sys_setsockopt(&args),
        syscall::nrs::NR_GETSOCKOPT  => crate::syscalls::net::sys_getsockopt(&args),
        syscall::nrs::NR_SENDMSG => crate::syscalls::net::sys_sendmsg(&args),
        syscall::nrs::NR_RECVMSG => crate::syscalls::net::sys_recvmsg(&args),
        syscall::nrs::NR_SENDMMSG => crate::syscalls::net::sys_sendmmsg(&args),
        syscall::nrs::NR_RECVMMSG => crate::syscalls::net::sys_recvmmsg(&args),
        syscall::nrs::NR_FLOCK         => ::fs::flock::sys_flock(&args),
        syscall::nrs::NR_PERSONALITY   => sched::prctl::sys_personality(&args),
        syscall::nrs::NR_CHROOT  => crate::syscalls::chroot::sys_chroot(&args),
        syscall::nrs::NR_MOUNT   => crate::syscalls::mount::sys_mount(&args),
        syscall::nrs::NR_UMOUNT2 => crate::syscalls::mount::sys_umount2(&args),
        syscall::nrs::NR_GET_MEMPOLICY => syscall::numa::sys_get_mempolicy(&args),
        syscall::nrs::NR_VHANGUP       => crate::syscalls::proc::sys_vhangup(&args),
        syscall::nrs::NR_FUTIMESAT | syscall::nrs::NR_UTIMENSAT => crate::syscalls::utime::sys_utimensat(&args),
        syscall::nrs::NR_MQ_NOTIFY     => ::ipc::live::posix_mq::sys_mq_notify(&args),
        syscall::nrs::NR_MQ_GETSETATTR => ::ipc::live::posix_mq::sys_mq_getsetattr(&args),
        syscall::nrs::NR_PROCESS_VM_READV  => crate::syscalls::pvmrw::sys_process_vm_readv(&args), syscall::nrs::NR_PROCESS_VM_WRITEV => crate::syscalls::pvmrw::sys_process_vm_writev(&args),
        syscall::nrs::NR_UTIMES | syscall::nrs::NR_UTIME
            => crate::syscalls::utime::sys_utime_dispatch(nr, &args),
        // link/symlink/mknod family — devfs is read-only, refuse.
        syscall::nrs::NR_LINK   => crate::syscalls::namei::sys_link(&args),
        syscall::nrs::NR_LINKAT => crate::syscalls::namei::sys_linkat(&args),
        syscall::nrs::NR_SYMLINK | syscall::nrs::NR_SYMLINKAT
            | syscall::nrs::NR_MKNOD | syscall::nrs::NR_MKNODAT
                                 => -(Errno::Erofs.as_i32() as i64),
        syscall::nrs::NR_FSTATFS | syscall::nrs::NR_STATFS
                                 => crate::syscalls::fs::sys_statfs(&args),
        syscall::nrs::NR_GETCPU        => crate::syscalls::proc::sys_getcpu(&args),
        syscall::nrs::NR_SCHED_GETPARAM => crate::syscalls::proc::sys_sched_getparam(&args),
        syscall::nrs::NR_SCHED_SETSCHEDULER | syscall::nrs::NR_SCHED_GETSCHEDULER
                                 => crate::syscalls::proc::sys_sched_getscheduler(&args),
        syscall::nrs::NR_SCHED_GET_PRIORITY_MAX
                                 => crate::syscalls::proc::sys_sched_get_priority_max(&args),
        syscall::nrs::NR_SCHED_GET_PRIORITY_MIN
                                 => crate::syscalls::proc::sys_sched_get_priority_min(&args),
        syscall::nrs::NR_SCHED_GETAFFINITY
                                 => crate::syscalls::proc::sys_sched_getaffinity(&args),
        syscall::nrs::NR_SCHED_SETAFFINITY
                                 => crate::syscalls::proc::sys_sched_setaffinity(&args),
        syscall::nrs::NR_PRCTL         => sched::prctl::sys_prctl(&args),
        syscall::nrs::NR_FUTEX         => crate::syscalls::proc::sys_futex(&args),
        syscall::nrs::NR_CLONE3        => crate::syscalls::proc::sys_clone3(&args),
        syscall::nrs::NR_MPROTECT      => crate::syscalls::proc::sys_mprotect(&args),
        syscall::nrs::NR_MADVISE       => crate::syscalls::proc::sys_madvise(&args),
        syscall::nrs::NR_PRLIMIT64     => crate::syscalls::proc::sys_prlimit64(&args),
        syscall::nrs::NR_RT_SIGACTION  => crate::syscalls::signal::sys_rt_sigaction(&args),
        syscall::nrs::NR_RT_SIGPROCMASK => crate::syscalls::signal::sys_rt_sigprocmask(&args),
        syscall::nrs::NR_SIGALTSTACK   => crate::syscalls::signal::sys_sigaltstack(&args),
        syscall::nrs::NR_NANOSLEEP     => crate::syscalls::proc::sys_nanosleep(&args),
        syscall::nrs::NR_CLOCK_NANOSLEEP => crate::syscalls::proc::sys_clock_nanosleep(&args),
        syscall::nrs::NR_CLOSE         => sys_close(&args),
        syscall::nrs::NR_CLOSE_RANGE   => crate::syscalls::fs::sys_close_range(&args),
        syscall::nrs::NR_DUP           => crate::syscalls::fs::sys_dup(&args),
        syscall::nrs::NR_DUP2          => crate::syscalls::fs::sys_dup2(&args),
        syscall::nrs::NR_DUP3          => crate::syscalls::fs::sys_dup3(&args),
        syscall::nrs::NR_FORK          => crate::syscalls::clone::sys_clone_dispatch(&args, 0x11 /* SIGCHLD */, 0, 0, 0, 0),
        syscall::nrs::NR_VFORK         => crate::syscalls::clone::sys_clone_dispatch(&args, 0x4111 /* CLONE_VM|CLONE_VFORK|SIGCHLD */, 0, 0, 0, 0),
        // Linux x86_64 clone(flags, child_stack, ptid, ctid, tls).
        syscall::nrs::NR_CLONE         => crate::syscalls::clone::sys_clone_dispatch(&args, args.a0, args.a1, args.a2, args.a3, args.a4),
        syscall::nrs::NR_EXECVE        => crate::syscalls::execve::sys_execve(&args),
        // execveat(dirfd, path, argv, envp, flags). v1 ignores dirfd
        // + flags and routes through execve with the absolute path
        // resolution it already does.
        syscall::nrs::NR_EXECVEAT      => {
            let mut sa = args; sa.a0 = args.a1; sa.a1 = args.a2; sa.a2 = args.a3; sa.a3 = 0;
            crate::syscalls::execve::sys_execve(&sa)
        }
        syscall::nrs::NR_WAIT4         => sys_wait4(&args),
        syscall::nrs::NR_WAITID        => sys_waitid(&args),
        syscall::nrs::NR_TKILL         => sys_kill(&args),
        syscall::nrs::NR_RT_SIGPENDING => crate::syscalls::signal::sys_rt_sigpending(&args),
        syscall::nrs::NR_RT_SIGSUSPEND => crate::syscalls::signal::sys_rt_sigsuspend(&args),
        syscall::nrs::NR_RT_SIGTIMEDWAIT  => crate::syscalls::signal::sys_rt_sigtimedwait(&args),
        syscall::nrs::NR_RT_SIGQUEUEINFO  => crate::syscalls::signal::sys_rt_sigqueueinfo(&args),
        syscall::nrs::NR_RT_TGSIGQUEUEINFO => crate::syscalls::signal::sys_rt_tgsigqueueinfo(&args),
        // Real-impl arms that overlap with compat-stub categories.
        syscall::nrs::NR_PIPE          => sys_pipe2(&args),
        syscall::nrs::NR_CREAT         => crate::syscalls::open::sys_open(&args),
        syscall::nrs::NR_EXIT_GROUP    => sys_exit(&args),
        syscall::nrs::NR_INIT_MODULE   => sys_init_module(&args),
        syscall::nrs::NR_FINIT_MODULE  => sys_finit_module(&args),
        syscall::nrs::NR_DELETE_MODULE => sys_delete_module(&args),
        syscall::nrs::NR_NEWFSTATAT    => crate::syscalls::fs::sys_newfstatat(&args),
        syscall::nrs::NR_STAT
            | syscall::nrs::NR_LSTAT   => crate::syscalls::fs::sys_stat(&args),
        // Cred family: dispatched via sched::cred::cred_dispatch.
        // Handled in the fallthrough below to keep this match arm small.
        syscall::nrs::NR_SET_ROBUST_LIST => crate::syscalls::proc::sys_set_robust_list(&args),
        syscall::nrs::NR_GET_ROBUST_LIST => crate::syscalls::proc::sys_get_robust_list(&args),
        syscall::nrs::NR_SYSLOG          => syscall::dmesg::sys_syslog(&args),
        // SAFETY: dispatch tail runs on cur's per-task syscall/SVC stack; the per-arch saved frame is live; ::fs::sig_dispatch::rt_sigreturn dispatches to the matching x86/arm helper which only reads/writes saved-frame slots and user-stack frame the dispatcher previously installed via `deliver`.
        syscall::nrs::NR_RT_SIGRETURN  => unsafe { ::fs::sig_dispatch::rt_sigreturn() },
        // Compat-stub fall-through table per P3-46.
        _ => {
            if let Some(rv) = sched::cred::cred_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = sched::timers::timer_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = crate::syscalls::perms::perms_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = ::fs::xattr::xattr_dispatch(nr, &args) { rv }
            else if let Some(rv) = ::fs::keyring::keyring_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = sched::compat::try_compat(nr, &args) {
                rv
            } else {
                dispatch(nr as u32, &args)
            }
        }
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    // POSIX timers + rseq cpu_id writeback at syscall-return tail.
    sched::timers::fire_due_timers();
    crate::syscalls::proc::rseq_writeback();
    // F108: PTRACE_SYSCALL exit-stop, symmetric with the entry-stop above.
    ptrace_syscall_stop_if_armed();
    // alarm(2) deadline check: post SIGALRM (bit 13) if the alarm_ns has passed.
    if let Some(cur) = sched::live::current() {
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
        unsafe { sched::live::schedule(); }
    }
    // P3-65: deliver pending signals at syscall return.
    if let Some(p) = crate::syscalls::signal::take_lowest_pending() {
        // Job-control signals come first — their default action is
        // stop / continue, not terminate, regardless of handler.
        // SIGSTOP (19) is uncatchable per signal(7); the others (TSTP
        // 20, TTIN 21, TTOU 22) honour a user handler.
        if matches!(p.sig, 19) || (matches!(p.sig, 20 | 21 | 22) && p.handler == 0) {
            sched::live::stop::stop_until_cont();
            return rv as u64;
        }
        if p.sig == 18 {
            // SIGCONT — default no-op. User handler dispatches normally;
            // SIG_DFL silently drops.
            if p.handler != 0 && p.handler != 1 {
                // SAFETY: dispatch tail; same conditions as the SIG_DFL→handler arm below.
                unsafe { ::fs::sig_dispatch::deliver(p.handler, p.restorer, p.sig); }
            }
            return rv as u64;
        }
        match p.handler {
            0 => {
                // SIG_DFL — Linux signal(7) defaults: SIGCHLD/SIGURG/
                // SIGWINCH ignore; SIGQUIT/SIGILL/SIGTRAP/SIGABRT/
                // SIGBUS/SIGFPE/SIGSEGV/SIGSYS/SIGXCPU/SIGXFSZ
                // terminate with core; rest terminate.
                if !matches!(p.sig, 17 | 23 | 28) {
                    if matches!(p.sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
                        ::fs::coredump::write_for_current(p.sig as i32);
                    }
                    let exit_args = SyscallArgs { a0: (p.sig | 0x100) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
                    let _ = sys_exit(&exit_args);
                }
            }
            1 => {  /* SIG_IGN: drop */ }
            handler => {
                // SAFETY: dispatch tail runs on cur's per-task syscall/SVC stack; per-arch saved frame is live; ::fs::sig_dispatch::deliver dispatches to deliver_x86/_arm which rewrite the saved frame so the asm epilogue's sysretq/eret enters the user handler with the constructed signal frame on the user stack.
                unsafe { ::fs::sig_dispatch::deliver(handler, p.restorer, p.sig); }
            }
        }
    }
    rv as u64
}
