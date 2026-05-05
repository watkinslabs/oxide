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

/// sys_mmap — anon-only, demand-paged.
fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd = args.a4 as i64;
    match crate::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

/// sys_munmap → AddressSpace::munmap.
fn kernel_munmap(args: &SyscallArgs) -> i64 {
    crate::user_as::glue_munmap(args.a0, args.a1)
}

/// sys_read via fd_table → File::read; ConsoleInode blocks.
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

/// Resolve relative path against current.cwd; len <= 1 falls through
/// (1-byte selector legacy). Returns None when no resolution applies.
/// # C: O(N)
fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    if path_raw.starts_with('/') || path_raw.len() <= 1 { return None; }
    let cur = crate::sched::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

fn kernel_sys_open(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use vfs::{Dentry, File, OpenFlags};
    let path_ptr = args.a0;
    let flags    = args.a1 as u32;
    let _mode    = args.a2;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller already executed user code from this AS); path bounded at 256 B.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let path_raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(path_raw);
    let path_str: &str = resolved.as_deref().unwrap_or(path_raw);
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;
    // /dev/ptmx is a factory: each open allocates a fresh master inode
    // and registers a /dev/pts/<n> slave. See `28§5`.
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev_pty::allocate_pair();
        master
    } else if let Some(i) = crate::devfs::lookup(path_str) { i }
        else if let Some(i) = crate::procfs::lookup_dynamic(path_str) { i }
        else if let Some(i) = crate::tmpfs::lookup(path_str) { i }
        else if (flags & O_CREAT) != 0 && path_str.starts_with("/tmp/") {
            crate::tmpfs::lookup_or_create(path_str)
        } else { return -(Errno::Enoent.as_i32() as i64); };
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: we are running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, path_str.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
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
    crate::sched::current().map(|c| c.tid as i64).unwrap_or(1)
}

fn kernel_sys_getppid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current()
        .map(|c| c.parent_tid.load(Ordering::Acquire) as i64)
        .unwrap_or(0)
}

/// sys_fork: clone AS+pages, spawn child with rax=0 at post-syscall RIP.
/// # C: O(N_vmas) + O(log N)
#[cfg(target_arch = "x86_64")]
fn kernel_sys_fork(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; no concurrent writer to our mm; preempt-off through the syscall handler.
    let parent_mm = match unsafe { cur.mm_ref() } {
        Some(m) => m,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Allocate new PT root for the child.
    // SAFETY: capture_kernel_master ran at user_as::init; PMM up.
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };

    // Clone the AS — VMA tree + per-page copy of Anonymous-backed
    // pages (P2-15c). KernelBytes-backed VMAs re-fault in the
    // child against the shared `&'static [u8]` slice.
    let hhdm = crate::user_as::hhdm_offset();
    let child_mm = match parent_mm.fork_copy_pages::<hal_x86_64::mmu_ops::X86Mmu, _>(
        new_root,
        hhdm,
        || crate::pmm_setup::alloc_one_frame(),
    ) {
        Ok(m) => m,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // SAFETY: we are running on the parent's per-task syscall stack; current_user_frame() points at the saved tail; we read but do not write.
    let frame = unsafe { &*hal_x86_64::current_user_frame() };
    let user_rip = frame[0];
    let user_rsp = frame[2];
    // user_rip points at the instruction RIGHT AFTER the syscall
    // (rcx is post-syscall in x86_64) — the child resumes there
    // with rax=0.

    let child_tid = crate::sched::next_tid();
    // SAFETY: runqueue installed by elf_smoke; child_mm is freshly forked from the parent's AS with kernel-half cloned from master per P2-19; user_rip/user_rsp captured from the parent's syscall frame.
    let spawn = unsafe {
        crate::sched::spawn_user_thread(
            child_tid, "fork-child", user_rip, user_rsp, child_mm,
        )
    };
    let child = match spawn {
        Ok(t)  => t,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };

    // Record parent_tid for `wait4` (P2-22) + parent Weak<Task>
    // for `park_zombie` SIGCHLD delivery (P3-67).
    child.parent_tid.store(cur.tid, Ordering::Release);
    // Inherit parent's pgid + sid per POSIX fork(2). setpgid/setsid in
    // child override later. Without inheritance every fork would land
    // in its own pgrp and shells couldn't track job state.
    child.pgid.store(cur.pgid.load(Ordering::Acquire), Ordering::Release);
    child.sid.store(cur.sid.load(Ordering::Acquire), Ordering::Release);
    // Inherit cwd per POSIX fork(2).
    // SAFETY: child not yet scheduled; we are sole writer to its cwd slot;
    // parent cwd read is the running task on this CPU per single-mutator invariant.
    unsafe {
        let parent_cwd = (*cur.cwd.get()).clone();
        *child.cwd.get() = parent_cwd;
    }
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

    // Inherit parent's fd table (P3-61): clone per-entry into a
    // fresh FdTable so child's close/dup don't disturb parent's
    // slots. The underlying `Arc<File>` is still shared, matching
    // POSIX (parent + child share open-file descriptions but
    // each has its own fd-table). For CLONE_FILES the original
    // Arc-share would apply; v1 fork is the non-CLONE_FILES path.
    // SAFETY: we're sole writer on the parent's fd_table read; child not yet scheduled (sole writer there too).
    let parent_fdt = unsafe { cur.fd_table_ref().cloned() };
    if let Some(fdt) = parent_fdt {
        let child_fdt = alloc::sync::Arc::new(fdt.fork_clone());
        // SAFETY: child task hasn't been scheduled yet (just spawned); we are the sole writer to its fd_table slot per the single-mutator-per-active-CPU invariant in `13§5`.
        unsafe { child.replace_fd_table(Some(child_fdt)); }
    }

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_fork: parent_tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" child_tid=");
        klog::write_dec_u64(child_tid as u64);
        klog::write_raw(b" child_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    // Drop our local Arc; the runqueue's enqueue clone keeps the
    // child alive until it Zombies + parks to the zombie registry.
    drop(child);

    child_tid as i64
}

/// sys_wait4: reap_one + yield-poll. WNOHANG → 0 if no zombie ready.
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
        // No zombie ready — yield and retry. schedule() saves
        // our state into current.arch_ctx + switches; we resume
        // here when a child eventually exits + reschedule picks
        // us back.
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { crate::sched::tick_yield(); }
        // After resume, ZOMBIES likely contains a new entry.
        // Loop body re-tries.
        let _ = Ordering::Acquire; // touch to keep ordering import live
    }
}

/// `sys_execve(path, argv, envp)` per `15§5` / `31§4`.
/// # SAFETY: dispatch ctx, IRQs masked.
/// # C: O(phdrs) + O(N_vmas) + O(1)
#[cfg(target_arch = "x86_64")]
fn kernel_sys_execve(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use vmm::{AddressSpace, VmaBacking, VmaFlags, VmaProt};
    use hal::UserVirtAddr;

    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Einval.as_i32() as i64),
    };

    // Read the first byte of the path argument as a kernel-static
    // ELF selector (v1 stand-in for VFS path lookup per docs/16).
    // `path = NULL` falls back to the default blob — preserves the
    // P2-21 legacy behavior. CPL=0 reads through user pages
    // directly per `15§3` (kernel can read user memory while
    // running on its kernel stack with CR3 = user AS).
    let path_ptr = args.a0;
    let blob = if path_ptr == 0 {
        crate::elf_smoke::EXEC_BLOB
    } else {
        if path_ptr >= USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // Read up to 64 bytes of the user path, NUL-terminated.
        let mut path_buf = [0u8; 64];
        let mut path_len = 0;
        for i in 0..64 {
            // SAFETY: bounded read up to 64 bytes from a user pointer < USER_VA_END; CPL=0 reads through user mapping pre-activate.
            let b = unsafe { core::ptr::read_volatile((path_ptr + i) as *const u8) };
            if b == 0 { break; }
            path_buf[i as usize] = b;
            path_len = (i + 1) as usize;
        }
        let path = &path_buf[..path_len];
        // Path-string lookup first; fall back to first-byte
        // selector form (init blob's iter_block uses non-NUL-
        // terminated single-byte selectors at known VAs).
        if let Some(b) = crate::elf_smoke::lookup_blob_by_path(path) {
            b
        } else if path_len >= 1 {
            match crate::elf_smoke::lookup_blob(path[0]) {
                Some(b) => b,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        } else {
            return -(Errno::Enoent.as_i32() as i64);
        }
    };

    // 1a. Snapshot argv + envp from the OLD user AS into kernel
    //     storage. After we activate the new AS, the old user
    //     pages are unmapped and the user-side argv/envp pointers
    //     would resolve to nothing. v1 caps: 8 entries each, 64
    //     bytes per string.
    const MAX_VEC: usize = 8;
    const MAX_STR: usize = 64;
    let mut argv_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut argv_len = [0usize; MAX_VEC];
    let mut argc: usize = 0;
    let mut envp_buf = [[0u8; MAX_STR]; MAX_VEC];
    let mut envp_len = [0usize; MAX_VEC];
    let mut envc: usize = 0;
    if args.a1 != 0 && args.a1 < USER_VA_END {
        let argv_uva = args.a1;
        for i in 0..MAX_VEC {
            let p = argv_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: argv array entries are 8-byte aligned per Linux ABI; we bound at MAX_VEC; CPL=0 reads through user mapping pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { break; }
            if s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read of user string up to MAX_STR; CPL=0 reads through caller's AS.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { argv_len[i] = j; break; }
                argv_buf[i][j] = b;
                argv_len[i] = j + 1;
            }
            argc += 1;
        }
    }
    if args.a2 != 0 && args.a2 < USER_VA_END {
        let envp_uva = args.a2;
        for i in 0..MAX_VEC {
            let p = envp_uva + (i as u64) * 8;
            if p >= USER_VA_END { break; }
            // SAFETY: envp array entries 8-byte aligned per Linux ABI; bounded MAX_VEC; CPL=0 reads through user mapping pre-activate.
            let s = unsafe { core::ptr::read_volatile(p as *const u64) };
            if s == 0 { break; }
            if s >= USER_VA_END { break; }
            for j in 0..MAX_STR {
                // SAFETY: bounded read of user string up to MAX_STR; CPL=0 reads through caller's AS.
                let b = unsafe { core::ptr::read_volatile((s + j as u64) as *const u8) };
                if b == 0 { envp_len[i] = j; break; }
                envp_buf[i][j] = b;
                envp_len[i] = j + 1;
            }
            envc += 1;
        }
    }

    // 1. Allocate new PT root for the post-execve AS.
    // SAFETY: master PML4 captured at user_as::init; PMM up.
    let new_root = match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
        Some(r) => r,
        None    => return -(Errno::Enomem.as_i32() as i64),
    };

    // 2. Build the new AS shell + load the ELF + register stack.
    let new_as = match AddressSpace::new(new_root) {
        Ok(a)  => a,
        Err(_) => return -(Errno::Enomem.as_i32() as i64),
    };
    let img = match crate::elf_load::load_static_blob(blob, &new_as) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoexec.as_i32() as i64),
    };
    let stack_hint = UserVirtAddr::new(crate::elf_smoke::EXEC_USER_STACK_VA)
        .expect("EXEC_USER_STACK_VA in user range");
    if new_as.mmap(
        Some(stack_hint), 0x1000,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }

    // 3. Replace `current.mm` with the new AS and activate it.
    //    Order: activate BEFORE replace_mm so CR3 doesn't dangle
    //    if drop runs concurrently — but on UP single-CPU the
    //    order is purely defensive.
    use hal::MmuOps;
    // SAFETY: new_root carries kernel-half cloned from master per P2-19; activate writes CR3 + flushes user TLB; preempt-off; single-CPU.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(new_root); }
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent reader of mm on another CPU (UP v1).
    unsafe { cur.replace_mm(Some(new_as)); }

    // P3-61: drop FD_CLOEXEC fds before the new program runs.
    // SAFETY: same single-mutator invariant on fd_table as mm.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        fdt.close_on_exec();
    }

    // 4. Build the SysV initial stack (argc/argv/envp/auxv) per
    //    docs/31§4 step 5. v1 passes empty argv/envp; auxv carries
    //    AT_PHDR/PHENT/PHNUM/PAGESZ/ENTRY/RANDOM so static-PIE musl
    //    `_start` can locate its phdrs and seed its RNG.
    let random16 = {
        let ns = <hal_x86_64::X86TimerOps as TimerOps>::monotonic_ns().0;
        let mut r = [0u8; 16];
        for i in 0..16 { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8 * 0x9b); }
        r
    };
    // Materialise stack-allocated &[&[u8]] slices for the OLD-AS snapshot.
    let mut argv_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..argc { argv_slices[i] = &argv_buf[i][..argv_len[i]]; }
    let mut envp_slices: [&[u8]; MAX_VEC] = [b""; MAX_VEC];
    for i in 0..envc { envp_slices[i] = &envp_buf[i][..envp_len[i]]; }
    // SAFETY: single-mutator per `13§5` for both cmdline + environ slots.
    unsafe {
        *cur.cmdline.get() = Some(sched::argv_to_cmdline(&argv_slices[..argc]));
        *cur.environ.get() = Some(sched::argv_to_cmdline(&envp_slices[..envc]));
    }
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            crate::elf_smoke::EXEC_USER_STACK_TOP,
            &argv_slices[..argc],
            &envp_slices[..envc],
            &img,
            &random16,
        )
    } {
        Some(sp) => sp,
        None     => return -(Errno::Enomem.as_i32() as i64),
    };

    // 5. Overwrite the per-task syscall stack's saved user-frame
    //    so the asm epilogue's `pop rcx; pop r11; pop rsp; sysretq`
    //    lands the user at the new program entry on the built stack.
    // SAFETY: we are running on cur's per-task syscall stack; current_user_frame() points at the live saved tail; the syscall asm pops from these same slots after we return.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    frame[0] = img.entry.as_u64();
    frame[1] = 0x002;
    frame[2] = new_sp;

    debug_sched! {
        klog::write_raw(b"[INFO]  sys_execve: argc=");
        klog::write_dec_u64(argc as u64);
        klog::write_raw(b" envc=");
        klog::write_dec_u64(envc as u64);
        klog::write_raw(b" entry=");
        klog::write_hex_u64(img.entry.as_u64());
        klog::write_raw(b" sp=");
        klog::write_hex_u64(new_sp);
        klog::write_raw(b" new_root=");
        klog::write_hex_u64(new_root);
        klog::write_raw(b"\n");
    }

    // Return value irrelevant — sysretq goes to new program; rax
    // gets clobbered by the new program's first mov.
    0
}

/// sys_exit: mark Zombie, stash exit_status, schedule away.
/// # SAFETY: dispatch ctx on task's syscall kstack, IRQs masked.
/// # C: O(log N) + O(1)
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
            // v1: report 0; once we read FS_BASE back, return that.
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
        crate::syscall_nrs::NR_OPEN          => kernel_sys_open(&args),
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
        crate::syscall_nrs::NR_PREADV | crate::syscall_nrs::NR_PWRITEV
                                 => -(Errno::Enosys.as_i32() as i64),
        crate::syscall_nrs::NR_MKDIR | crate::syscall_nrs::NR_RMDIR | crate::syscall_nrs::NR_UNLINK
            | crate::syscall_nrs::NR_UNLINKAT | crate::syscall_nrs::NR_MKDIRAT
            | crate::syscall_nrs::NR_RENAME | crate::syscall_nrs::NR_RENAMEAT | crate::syscall_nrs::NR_RENAMEAT2
                                 => -(Errno::Erofs.as_i32() as i64),
        crate::syscall_nrs::NR_TRUNCATE  => crate::syscall_glue_fs::kernel_sys_truncate(&args),
        crate::syscall_nrs::NR_FTRUNCATE => crate::syscall_glue_fs::kernel_sys_ftruncate(&args),
        crate::syscall_nrs::NR_SENDFILE  => crate::syscall_glue_xfer::kernel_sys_sendfile(&args),
        crate::syscall_nrs::NR_OPENAT        => crate::syscall_glue_fs::kernel_sys_openat(&args),
        crate::syscall_nrs::NR_FSYNC | crate::syscall_nrs::NR_FDATASYNC | crate::syscall_nrs::NR_SYNC
                                 => 0,
        // Net family — no stack yet per docs/25; ENOSYS.
        crate::syscall_nrs::NR_SOCKET | crate::syscall_nrs::NR_BIND | crate::syscall_nrs::NR_LISTEN
            | crate::syscall_nrs::NR_ACCEPT | crate::syscall_nrs::NR_ACCEPT4 | crate::syscall_nrs::NR_CONNECT
            | crate::syscall_nrs::NR_SENDTO | crate::syscall_nrs::NR_RECVFROM
            | crate::syscall_nrs::NR_SENDMSG | crate::syscall_nrs::NR_RECVMSG
            | crate::syscall_nrs::NR_SHUTDOWN
            | crate::syscall_nrs::NR_GETSOCKNAME | crate::syscall_nrs::NR_GETPEERNAME
            | crate::syscall_nrs::NR_SOCKETPAIR
            | crate::syscall_nrs::NR_SETSOCKOPT | crate::syscall_nrs::NR_GETSOCKOPT
                                 => -(Errno::Enosys.as_i32() as i64),
        // chmod/chown family — devfs is read-only, but accept silently
        // for tooling that probes mode/owner without erroring.
        crate::syscall_nrs::NR_FCHMOD | crate::syscall_nrs::NR_FCHMODAT | crate::syscall_nrs::NR_CHMOD
            | crate::syscall_nrs::NR_FCHOWN | crate::syscall_nrs::NR_CHOWN | crate::syscall_nrs::NR_LCHOWN
            | crate::syscall_nrs::NR_FCHOWNAT
            | crate::syscall_nrs::NR_UTIMENSAT | crate::syscall_nrs::NR_UTIMES | crate::syscall_nrs::NR_UTIME
                                 => 0,
        // link/symlink/mknod family — devfs is read-only, refuse.
        crate::syscall_nrs::NR_LINK | crate::syscall_nrs::NR_LINKAT
            | crate::syscall_nrs::NR_SYMLINK | crate::syscall_nrs::NR_SYMLINKAT
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
        crate::syscall_nrs::NR_FORK          => kernel_sys_fork(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_EXECVE        => kernel_sys_execve(&args),
        #[cfg(target_arch = "x86_64")]
        crate::syscall_nrs::NR_WAIT4         => kernel_sys_wait4(&args),
        crate::syscall_nrs::NR_TKILL         => kernel_sys_kill(&args),
        crate::syscall_nrs::NR_RT_SIGPENDING => crate::syscall_glue_proc::kernel_sys_rt_sigpending(&args),
        crate::syscall_nrs::NR_RT_SIGSUSPEND => crate::syscall_glue_proc::kernel_sys_rt_sigsuspend(&args),
        // Real-impl arms that overlap with compat-stub categories.
        crate::syscall_nrs::NR_PIPE          => kernel_sys_pipe2(&args),
        crate::syscall_nrs::NR_CREAT         => kernel_sys_open(&args),
        crate::syscall_nrs::NR_EXIT_GROUP    => kernel_sys_exit(&args),
        crate::syscall_nrs::NR_NEWFSTATAT    => crate::syscall_glue_fs::kernel_sys_statx(&args),
        crate::syscall_nrs::NR_STAT
            | crate::syscall_nrs::NR_LSTAT   => crate::syscall_glue_fs::kernel_sys_stat(&args),
        crate::syscall_nrs::NR_GETRESUID
            | crate::syscall_nrs::NR_GETRESGID
                                 => crate::syscall_glue_proc::kernel_sys_getres_uid(&args),
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
    // P3-65: deliver pending signals at syscall return. SIG_DFL →
    // terminate (per `27§2`); SIG_IGN → drop; user handler → build
    // a minimal signal frame and route the user back to the handler
    // on resume (sa_restorer issues rt_sigreturn).
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
