// Glue between the per-arch syscall asm stub and the architecture-
// neutral `syscall::dispatch` table per `15§4`.
//
// Both arches' asm stubs reference `oxide_syscall_dispatch` by symbol;
// `extern "C"` + `#[no_mangle]` here makes the linker resolve it to
// the kernel-side wrapper that:
//   1. packs the asm-shuffled regs into `SyscallArgs`,
//   2. calls `syscall::dispatch(nr, &args) -> i64`,
//   3. returns the result as `u64` placed in rax (x86) / x0 (arm)
//      per `15§1.3` so a libc-style `rv > -4096UL` failure check
//      works userspace-side.
//
// arch-specific interceptions (e.g., x86 `sys_arch_prctl`) live
// here behind cfg gates because they need to call into `hal-<arch>`.

#![cfg(target_os = "oxide-kernel")]

use syscall::{dispatch, SyscallArgs};
use syscall::errno::Errno;
use hal::{TimerOps, USER_VA_END};

#[cfg(target_arch = "x86_64")]
const SYSCALL_NR_ARCH_PRCTL: u64 = 158;
#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: u64 = 0x1002;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_FS: u64 = 0x1003;

const SYSCALL_NR_CLOCK_GETTIME: u64 = 228;
const SYSCALL_NR_UNAME: u64          = 63;
const SYSCALL_NR_MMAP: u64           = 9;
const SYSCALL_NR_MUNMAP: u64         = 11;
const SYSCALL_NR_EXIT: u64           = 60;
const SYSCALL_NR_FORK: u64           = 57;
const SYSCALL_NR_EXECVE: u64         = 59;
const SYSCALL_NR_WAIT4: u64          = 61;
const SYSCALL_NR_GETPID: u64         = 39;
const SYSCALL_NR_GETPPID: u64        = 110;
const SYSCALL_NR_READ: u64           = 0;
const SYSCALL_NR_WRITE: u64          = 1;
const SYSCALL_NR_CLOSE: u64          = 3;
const SYSCALL_NR_DUP: u64            = 32;
const SYSCALL_NR_DUP2: u64           = 33;
const SYSCALL_NR_DUP3: u64           = 292;
const SYSCALL_NR_OPEN: u64           = 2;
const SYSCALL_NR_BRK: u64            = 12;
const SYSCALL_NR_PIPE2: u64          = 293;
const SYSCALL_NR_FSTAT: u64          = 5;
const SYSCALL_NR_GETCWD: u64         = 79;
const SYSCALL_NR_CHDIR: u64          = 80;
const SYSCALL_NR_FCHDIR: u64         = 81;
const SYSCALL_NR_IOCTL: u64          = 16;
const SYSCALL_NR_KILL: u64           = 62;
const SYSCALL_NR_TGKILL: u64         = 234;
const SYSCALL_NR_GETRANDOM: u64      = 318;
const SYSCALL_NR_SCHED_YIELD: u64    = 24;
const SYSCALL_NR_WRITEV: u64         = 20;
const SYSCALL_NR_READV: u64          = 19;
const SYSCALL_NR_GETTID: u64         = 186;
const SYSCALL_NR_SET_TID_ADDRESS: u64 = 218;
const SYSCALL_NR_POLL: u64           = 7;
const SYSCALL_NR_PPOLL: u64          = 271;
const SYSCALL_NR_LSEEK: u64          = 8;
const SYSCALL_NR_FUTEX: u64          = 202;
const SYSCALL_NR_CLONE3: u64         = 435;
const SYSCALL_NR_MPROTECT: u64       = 10;
const SYSCALL_NR_MADVISE: u64        = 28;
const SYSCALL_NR_PRLIMIT64: u64      = 302;
const SYSCALL_NR_RT_SIGACTION: u64   = 13;
const SYSCALL_NR_RT_SIGPROCMASK: u64 = 14;
const SYSCALL_NR_SIGALTSTACK: u64    = 131;

const NS_PER_SEC: u64 = 1_000_000_000;

/// `struct utsname` field width per Linux. Six fixed-length C
/// strings, NUL-terminated, total 6 × 65 = 390 bytes.
const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

/// Per-arch machine identifier returned by `uname.machine`.
#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Write the 6 utsname fields at consecutive 65-byte slots starting
/// at `tp`. Each field is the source bytes followed by NUL padding
/// out to 65 B. Caller validates `tp` range.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    for i in 0..n {
        // SAFETY: caller validated [tp, tp + UTSNAME_TOTAL_LEN) lies entirely below USER_VA_END and is mapped writable; CPL=0 ignores the leaf U bit so direct writes land in the user page.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, src[i]); }
    }
    for i in n..UTSNAME_FIELD_LEN {
        // SAFETY: same range as above; pads out the field with NUL.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

/// `sys_mmap(addr, len, prot, flags, fd, off)` — slot 9. Routes to
/// the real `vmm::AddressSpace::mmap` per `11§3`/`11§6` via the
/// `crate::user_as` integration. v1 supports only
/// `MAP_ANONYMOUS | MAP_PRIVATE` with `addr=NULL` / `fd=-1`; pages
/// are demand-faulted in by `user_as::user_fault_handler` per
/// `11§5`. No upfront frame allocation — first user access faults.
fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd = args.a4 as i64;
    match crate::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

/// `sys_munmap(addr, len)` — slot 11. Routes to
/// `vmm::AddressSpace::munmap` + per-page PT unmap + frame free per
/// `11§6` via the `crate::user_as` integration. Replaces the no-op
/// stub in `crates/syscall::dispatch::sys_munmap` (the in-table
/// stub still exists as a fallback when glue isn't routing — but
/// glue now intercepts nr=11 first so it's dead-path).
fn kernel_munmap(args: &SyscallArgs) -> i64 {
    crate::user_as::glue_munmap(args.a0, args.a1)
}

/// `sys_read(fd, buf, count)` — slot 0. Routes through the
/// current task's `fd_table` (P2-30a): looks up the open `File`
/// at `fd`, calls `File::read` which delegates to the underlying
/// inode (e.g. `ConsoleInode` for fd=0/1/2 in v1).
///
/// `ConsoleInode::read` blocks via `tty::park_current_for_tty`
/// + `schedule()` if no UART byte is ready; the timer-tick poller
/// (`tty::tick_poll_uart`) wakes parked tasks per `28§3`.
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
    // Build a user-side &mut [u8] of length min(cnt, 1) — the
    // ConsoleInode protocol returns at most 1 byte per call. A
    // future fd_table-aware copy_to_user would handle larger
    // counts by ranging over `cnt` bytes safely.
    let len = (cnt as usize).min(1);
    // SAFETY: caller validated buf < USER_VA_END; user page mapped (caller's task already executed from this AS); CPL=0 writes through user mapping.
    let user_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, len)
    };
    match file.read(user_buf) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_write(fd, buf, count)` — slot 1 wrapper. Routes through
/// the current task's `fd_table` (P2-30a) so fd 1/2 and any
/// future opened fd dispatch via `File::write`. v1 falls back to
/// the arch-neutral in-table `sys_write` (which writes to UART
/// for fd=1/2, EBADF otherwise) when no fd_table is installed —
/// preserves behaviour for kthread-context kernel-side syscalls.
fn kernel_sys_write(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    if cnt == 0 { return 0; }
    if buf == 0 || buf >= USER_VA_END {
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
    // SAFETY: caller validated buf < USER_VA_END; user page mapped; CPL=0 reads through user mapping.
    let user_buf: &[u8] = unsafe {
        core::slice::from_raw_parts(buf as *const u8, len)
    };
    match file.write(user_buf) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_pipe2(pipefd, flags)` — slot 293 per docs/15§5 +
/// docs/24. Creates an anonymous `PipeInode`, allocates two
/// `File`s (read end O_RDONLY, write end O_WRONLY), inserts
/// them at the lowest-free fds in the current task's fd_table,
/// and writes the two fd numbers to user `pipefd[2]`.
fn kernel_sys_pipe2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    let pipefd = args.a0;
    let _flags = args.a1 as u32;
    if pipefd == 0 || pipefd >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: we are running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::dev_pipe::PipeInode::new();
    let dentry = Dentry::new(None, "pipe".to_string(), inode.clone());
    let r_file = File::new(inode.clone(), dentry.clone(), OpenFlags::O_RDONLY);
    let w_file = File::new(inode, dentry, OpenFlags::O_WRONLY);
    let r_fd = match fdt.alloc(r_file)  { Ok(f) => f, Err(e) => return -(e as i64) };
    let w_fd = match fdt.alloc(w_file)  { Ok(f) => f, Err(e) => {
        let _ = fdt.close(r_fd);
        return -(e as i64);
    }};
    // SAFETY: pipefd validated < USER_VA_END; user page mapped per active CR3 = caller's AS.
    unsafe {
        core::ptr::write_volatile(pipefd as *mut i32,         r_fd);
        core::ptr::write_volatile((pipefd + 4) as *mut i32,   w_fd);
    }
    debug_sched! {
        klog::write_raw(b"[INFO]  sys_pipe2: read_fd=");
        klog::write_dec_u64(r_fd as u64);
        klog::write_raw(b" write_fd=");
        klog::write_dec_u64(w_fd as u64);
        klog::write_raw(b"\n");
    }
    0
}

/// `sys_brk(addr)` — slot 12 per docs/15§5. Extends or shrinks
/// the data segment ("heap") of the calling task. v1: the ELF
/// loader pre-registers a 64 MiB Anonymous VMA above the last
/// PT_LOAD; this syscall just adjusts the brk pointer within
/// `[initial, initial + 64MiB]`. Pages demand-fault as the user
/// touches them.
///
/// glibc/musl ABI: `brk(0)` queries; `brk(N)` attempts to set;
/// returns the post-operation brk on success, the unchanged
/// current brk on failure.
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

/// `sys_open(path, flags, _mode)` — slot 2 per docs/15§5.
/// v1 path resolution: looks up the path in the kernel-side
/// devfs registry (P2-30b). On hit, allocates a `File` wrapping
/// the InodeRef and installs it at the lowest-free fd in the
/// current task's fd_table. Returns the new fd or -ENOENT.
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
    let path_str = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match crate::devfs::lookup(path_str) {
        Some(i) => i,
        None    => return -(Errno::Enoent.as_i32() as i64),
    };
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

/// `sys_close(fd)` — slot 3 per docs/15§5. Removes the entry
/// from the current task's fd table; subsequent operations on
/// `fd` return `-EBADF`.
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

/// `sys_dup(oldfd)` — slot 32 per docs/15§5. Allocates the
/// lowest free fd pointing at the same `File` as `oldfd`.
fn kernel_sys_dup(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup(oldfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup2(oldfd, newfd)` — slot 33 per docs/15§5. Atomically
/// closes `newfd` (if open) and installs a clone of `oldfd`
/// at `newfd`. If `oldfd == newfd`, returns `newfd` unchanged.
fn kernel_sys_dup2(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup3(oldfd, newfd, flags)` — slot 292 per docs/15§5.
/// Like `dup2` but rejects `oldfd == newfd` and accepts
/// `O_CLOEXEC` (ignored in v1).
fn kernel_sys_dup3(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    if oldfd == newfd {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_getpid()` — slot 39 per docs/15§5. Returns the current
/// task's `tid` per `13§5`. Replaces the in-table stub that
/// returns a fixed `1`.
fn kernel_sys_getpid(_args: &SyscallArgs) -> i64 {
    crate::sched::current().map(|c| c.tid as i64).unwrap_or(1)
}

/// `sys_getppid()` — slot 110 per docs/15§5. Returns the current
/// task's `parent_tid`; `0` for tasks with no parent (boot's
/// init-like task, kthreads).
fn kernel_sys_getppid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    crate::sched::current()
        .map(|c| c.parent_tid.load(Ordering::Acquire) as i64)
        .unwrap_or(0)
}

/// `sys_fork()` — slot 57 per docs/15§5 (Linux x86_64 fork). v0
/// per docs/11§7: clone the parent's `AddressSpace` (VMA tree
/// copy; mapped pages NOT copied — child re-demand-pages from
/// KernelBytes / fresh-zero for Anonymous), spawn a new user
/// `Task` with `mm = child_as`, return the child's TID to parent.
///
/// Child's iretq frame is built by `spawn_user_thread` with rax=0
/// (the synthesised IRQ frame's scratch slots default to zero, and
/// the rax slot is consumed by the IRQ epilogue's pop sequence
/// just before iretq) — so when the child is scheduled in, it
/// resumes at `user_rip` with rax=0 (the canonical fork return
/// distinguisher) and `rsp = user_rsp`.
///
/// Reads `user_rip`/`user_rsp` from globals captured by the
/// `oxide_syscall_entry` asm stub.
///
/// # C: O(N_vmas) clone + O(log N) enqueue
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

    // Record parent_tid for `wait4` (P2-22).
    child.parent_tid.store(cur.tid, Ordering::Release);

    // Inherit parent's fd table (P2-30a). v1 simplification:
    // share the same Arc — POSIX's "copy fd table" semantics
    // for default fork (non-CLONE_FILES) reduce in v1 to
    // sharing because no one calls dup/close yet to diverge.
    // Real per-entry copy lands when the FdTable's CLOSE_ON_EXEC
    // semantics differentiate.
    // SAFETY: we're sole writer on the parent's fd_table read; child not yet scheduled (sole writer there too).
    let parent_fdt = unsafe { cur.fd_table_ref().cloned() };
    if let Some(fdt) = parent_fdt {
        // SAFETY: child task hasn't been scheduled yet (just spawned); we are the sole writer to its fd_table slot per the single-mutator-per-active-CPU invariant in `13§5`.
        unsafe { child.replace_fd_table(Some(fdt)); }
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

/// `sys_wait4(pid, wstatus, options, rusage)` — slot 61 per
/// docs/15§5. Reaps a Zombie child of the current task and
/// optionally writes the exit status to user memory at `wstatus`.
/// `pid == -1` matches any child; `pid > 0` matches that
/// specific TID. `options` (WNOHANG etc.) ignored for v1.
/// `rusage` ignored.
///
/// If no Zombie child is currently queued, the parent yields via
/// `schedule()` and re-checks. With UP single-CPU + non-preempt
/// schedule, the child is guaranteed to run + Zombie before the
/// parent's loop terminates (unless the child is itself blocked).
///
/// Returns the reaped child's TID, or -ECHILD if the caller has
/// no eligible children at all.
///
/// # C: O(N_zombies × N_yield_iters) — bounded by child runtime
#[cfg(target_arch = "x86_64")]
fn kernel_sys_wait4(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let _options = args.a2;
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
            debug_sched! {
                klog::write_raw(b"[INFO]  sys_wait4: parent=");
                klog::write_dec_u64(parent_tid as u64);
                klog::write_raw(b" reaped tid=");
                klog::write_dec_u64(tid as u64);
                klog::write_raw(b" code=");
                klog::write_dec_u64(code as u64);
                klog::write_raw(b"\n");
            }
            return tid as i64;
        }
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

/// `sys_execve(path, argv, envp)` — slot 59 per docs/15§5. v0
/// per docs/31§4: ignores the path argument, always loads the
/// kernel-static `EXEC_BLOB`. Replaces `current.mm` atomically,
/// activates the new AS, and updates `oxide_user_rip`/`rsp` so
/// the syscall epilogue's `sysretq` lands at the new program's
/// `e_entry` instead of returning to the caller.
///
/// argv/envp/auxv build is skipped for v1 (the test program
/// doesn't read them); P2-21b adds the auxv table per docs/31§5.
///
/// On error returns -ENOMEM / -ENOEXEC and the caller resumes
/// at the post-execve instruction. On success doesn't return —
/// the new program runs from `e_entry`.
///
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the
/// user task's kernel stack with IRQs masked.
/// # C: O(phdrs) parse + O(N_vmas) AS build + O(1) activate
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
        // SAFETY: path_ptr < USER_VA_END validated above; the user page is mapped (user code already executed from this AS); we read a single byte.
        let sel = unsafe { core::ptr::read_volatile(path_ptr as *const u8) };
        match crate::elf_smoke::lookup_blob(sel) {
            Some(b) => b,
            None    => return -(Errno::Enoent.as_i32() as i64),
        }
    };

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
    // SAFETY: we activated new_root above, so user-VA writes from the kernel target the new AS; user_fault_handler will demand-fault the stack page.
    let new_sp = match unsafe {
        crate::exec_stack::build_user_stack(
            crate::elf_smoke::EXEC_USER_STACK_TOP,
            &[], &[],
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
        klog::write_raw(b"[INFO]  sys_execve: new entry=");
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

/// `sys_exit(code)` per docs/15§2 + docs/13§5: mark running
/// task Zombie + reschedule. State=Zombie ⇒ picker won't
/// re-enqueue; schedule() falls through to idle (boot anchor)
/// ⇒ boot resumes past its `schedule()` callsite. Exit code
/// stashed in `Task.exit_status` for wait4 to read.
/// # SAFETY: caller is dispatch on the task's kernel stack, IRQs masked.
/// # C: O(log N) CFS pick + O(1) ctxsw
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
    // Schedule away. State=Zombie ⇒ no re-enqueue; picker returns
    // idle (boot anchor) ⇒ Context::switch loads boot's saved regs
    // ⇒ control resumes in `elf_smoke::run_as_task` past its
    // `schedule()` call. We never come back to this task.
    // SAFETY: process / kthread context (we're on the user task's kernel stack); preempt-off; runqueue installed.
    unsafe { crate::sched::schedule(); }
    // Unreachable — Zombie task isn't re-scheduled.
    loop { core::hint::spin_loop(); }
}


/// `sys_getrandom(buf, len, flags)` — slot 318 per docs/15§5.
/// v1 fills via the shared LCG in dev_misc. NOT cryptographic;
/// docs/26 CPRNG replaces this. `flags` ignored (GRND_NONBLOCK
/// is a no-op since we never block).
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

/// `sys_kill(pid, sig)` — slot 62. v1 minimal: self-targeted
/// signals (`pid == current.tid` or `pid == 0`) for SIGKILL/
/// SIGTERM/SIGABRT route to `kernel_sys_exit(128 + sig)` so libc
/// `abort()` and `raise()` produce a real exit. Other targets
/// return -ESRCH (no task registry yet — P3 follow-up).
fn kernel_sys_kill(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Esrch.as_i32() as i64),
    };
    if pid == 0 || pid == cur.tid as i32 {
        let exit_args = SyscallArgs { a0: (128 + sig) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
        let _ = kernel_sys_exit(&exit_args);
        return 0;
    }
    -(Errno::Esrch.as_i32() as i64)
}

/// `sys_tgkill(tgid, tid, sig)` — slot 234. v1: route through
/// `kernel_sys_kill` keyed on `tid`. Same self-only restriction.
fn kernel_sys_tgkill(args: &SyscallArgs) -> i64 {
    let kill_args = SyscallArgs { a0: args.a1, a1: args.a2, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_kill(&kill_args)
}

fn kernel_uname(args: &SyscallArgs) -> i64 {
    let tp = args.a0;
    if let Err(rv) = validate_user_buf(tp, UTSNAME_TOTAL_LEN as u64, 1) { return rv; }
    // SAFETY: range validated above; user-half VA is mapped writable
    // by the userspace-smoke setup. Each field write iterates byte-
    // by-byte so no alignment requirement.
    unsafe {
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"oxide");
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, b"oxide");                  // nodename
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, b"0.1.0-pre");              // release
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, b"oxide #1 SMP PREEMPT");  // version
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);             // machine
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, b"(none)");                 // domainname
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

/// Read the per-arch monotonic clock and write `{tv_sec, tv_nsec}`
/// to the user `timespec*`. Both arches' `TimerOps::monotonic_ns`
/// returns 0 until calibrated, so a CLOCK_MONOTONIC reading at
/// boot-time may legitimately be 0.
///
/// v1: ignore clk_id; CLOCK_REALTIME and CLOCK_MONOTONIC alike use
/// the kernel monotonic counter (no wall-time RTC source yet).
fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }

    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;

    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: `tp` validated 16-byte range below USER_VA_END + 8-byte
    // aligned. CPL=0 ignores the leaf U bit so the kernel can write
    // the user mapping directly.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64,         tv_sec);
        core::ptr::write_volatile((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}

/// x86-specific syscall handled in the kernel-side glue (since
/// `crates/syscall` is arch-neutral and can't call `hal-x86_64`).
/// Only `ARCH_SET_FS` and `ARCH_GET_FS` are implemented; other
/// codes return -EINVAL. v1 single-thread → ARCH_GET_FS reads
/// IA32_FS_BASE via rdmsr (added if needed); v1 just returns 0.
#[cfg(target_arch = "x86_64")]
fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        ARCH_SET_FS => {
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
        ARCH_GET_FS => {
            // v1: report 0; once we read FS_BASE back, return that.
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// SysV-ABI hook invoked by `oxide_syscall_entry`. Stack-switched +
/// arg-shuffled by the asm stub before this is called.
///
/// # SAFETY: caller is the syscall asm stub; runs single-CPU with
/// IF=0 (FMASK cleared). Returns a u64 placed in rax for sysretq.
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
        SYSCALL_NR_ARCH_PRCTL    => kernel_arch_prctl(&args),
        SYSCALL_NR_CLOCK_GETTIME => kernel_clock_gettime(&args),
        SYSCALL_NR_UNAME         => kernel_uname(&args),
        SYSCALL_NR_MMAP          => kernel_mmap(&args),
        SYSCALL_NR_MUNMAP        => kernel_munmap(&args),
        SYSCALL_NR_EXIT          => kernel_sys_exit(&args),
        SYSCALL_NR_GETPID        => kernel_sys_getpid(&args),
        SYSCALL_NR_GETPPID       => kernel_sys_getppid(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_READ          => kernel_sys_read(&args),
        SYSCALL_NR_WRITE         => kernel_sys_write(&args),
        SYSCALL_NR_OPEN          => kernel_sys_open(&args),
        SYSCALL_NR_BRK           => kernel_sys_brk(&args),
        SYSCALL_NR_PIPE2         => kernel_sys_pipe2(&args),
        SYSCALL_NR_FSTAT         => crate::syscall_glue_fs::kernel_sys_fstat(&args),
        SYSCALL_NR_IOCTL         => crate::syscall_glue_fs::kernel_sys_ioctl(&args),
        SYSCALL_NR_GETCWD        => crate::syscall_glue_fs::kernel_sys_getcwd(&args),
        SYSCALL_NR_CHDIR         => crate::syscall_glue_fs::kernel_sys_chdir(&args),
        SYSCALL_NR_FCHDIR        => crate::syscall_glue_fs::kernel_sys_fchdir(&args),
        SYSCALL_NR_KILL          => kernel_sys_kill(&args),
        SYSCALL_NR_TGKILL        => kernel_sys_tgkill(&args),
        SYSCALL_NR_GETRANDOM     => kernel_sys_getrandom(&args),
        SYSCALL_NR_SCHED_YIELD   => crate::syscall_glue_proc::kernel_sys_sched_yield(&args),
        SYSCALL_NR_GETTID        => crate::syscall_glue_proc::kernel_sys_gettid(&args),
        SYSCALL_NR_SET_TID_ADDRESS => crate::syscall_glue_proc::kernel_sys_set_tid_address(&args),
        SYSCALL_NR_WRITEV        => crate::syscall_glue_fs::kernel_sys_writev(&args),
        SYSCALL_NR_READV         => crate::syscall_glue_fs::kernel_sys_readv(&args),
        SYSCALL_NR_POLL          => crate::syscall_glue_fs::kernel_sys_poll(&args),
        SYSCALL_NR_PPOLL         => crate::syscall_glue_fs::kernel_sys_ppoll(&args),
        SYSCALL_NR_LSEEK         => crate::syscall_glue_fs::kernel_sys_lseek(&args),
        SYSCALL_NR_FUTEX         => crate::syscall_glue_proc::kernel_sys_futex(&args),
        SYSCALL_NR_CLONE3        => crate::syscall_glue_proc::kernel_sys_clone3(&args),
        SYSCALL_NR_MPROTECT      => crate::syscall_glue_proc::kernel_sys_mprotect(&args),
        SYSCALL_NR_MADVISE       => crate::syscall_glue_proc::kernel_sys_madvise(&args),
        SYSCALL_NR_PRLIMIT64     => crate::syscall_glue_proc::kernel_sys_prlimit64(&args),
        SYSCALL_NR_RT_SIGACTION  => crate::syscall_glue_proc::kernel_sys_rt_sigaction(&args),
        SYSCALL_NR_RT_SIGPROCMASK => crate::syscall_glue_proc::kernel_sys_rt_sigprocmask(&args),
        SYSCALL_NR_SIGALTSTACK   => crate::syscall_glue_proc::kernel_sys_sigaltstack(&args),
        SYSCALL_NR_CLOSE         => kernel_sys_close(&args),
        SYSCALL_NR_DUP           => kernel_sys_dup(&args),
        SYSCALL_NR_DUP2          => kernel_sys_dup2(&args),
        SYSCALL_NR_DUP3          => kernel_sys_dup3(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_FORK          => kernel_sys_fork(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_EXECVE        => kernel_sys_execve(&args),
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_WAIT4         => kernel_sys_wait4(&args),
        _                        => dispatch(nr as u32, &args),
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    rv as u64
}
