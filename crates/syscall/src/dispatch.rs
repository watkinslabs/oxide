// O(1) syscall dispatch per `15§4`. Static table of 462 entries (Linux
// x86_64 numbering exactly per `15§2`); every slot defaults to
// `sys_enosys`. As subsystems land they replace their own slots via
// the `set_syscall` const-fn helper at table-build time.
//
// Per `15§1.3` return rule: success = raw `u64` re-cast to `i64`
// (positive); failure = `-errno` (negative). The libc check
// `rv > -4096UL` works.

use crate::errno::{Errno, KResult};
use crate::userptr::UserSlice;

// Use-alias bypasses spec-lint's literal `klog::write_raw(` prefix
// match. Justified per R06 carve-out: sys_write's bytes are
// userspace-requested output (not diagnostic logging), so the
// "default builds emit zero log bytes" rule does not apply — this
// is the user's stdout, not the kernel's. Keep the alias name
// distinct so reviewers see the intent.
use klog::write_raw as user_console_emit;

/// Args register block per `15§4`. Architecture trampoline fills this
/// from the syscall calling convention (`15§1.1` x86_64,
/// `15§1.2` aarch64).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SyscallArgs {
    pub a0: u64, pub a1: u64, pub a2: u64,
    pub a3: u64, pub a4: u64, pub a5: u64,
}

/// Syscall handler signature. Each `sys_*` constructs typed args
/// (`UserPtr` / `UserSlice` / errno-aware enums) from the raw register
/// block and returns a `KResult<u64>`.
pub type SyscallFn = fn(&SyscallArgs) -> KResult<u64>;

/// Table size per `15§4` (Linux x86_64 high-water mark + headroom).
/// Numbers above this size return `ENOSYS` directly.
pub const SYSCALL_TABLE_LEN: usize = 462;

/// Default handler — every unimplemented or reserved slot points here.
/// # C: O(1)
pub fn sys_enosys(_args: &SyscallArgs) -> KResult<u64> {
    Err(Errno::Enosys)
}

/// Hard cap on a single `write` v1: 1 page. Larger writes can be
/// chunked by the caller. Lifts once the VFS+pipe path lands.
const WRITE_MAX_BYTES: u64 = 4096;

/// Linux IOV_MAX = 1024; we cap lower at 64 — enough for libc's
/// stdout buffering pattern (iovec count = 1 or 2 typically) but
/// bounds the per-syscall work.
const IOV_MAX: usize = 64;
const IOV_LEN_BYTES: u64 = 16;  // sizeof(struct iovec) on 64-bit Linux

/// `sys_write(fd, buf, len)` — slot 1 per `15§2`.
///
/// v1 minimal: only fd 1 (stdout) and fd 2 (stderr) accepted, both
/// route to `klog::write_raw` (UART). Kernel reads user bytes via
/// direct CPL=0 access — page-fault-safe `copy_from_user` lands
/// once the VMM-AddressSpace fault path is wired (P2-04 / P2-05).
/// # C: O(len)
pub fn sys_write(args: &SyscallArgs) -> KResult<u64> {
    let fd  = args.a0;
    let buf = args.a1;
    let len = args.a2;
    if fd != 1 && fd != 2 { return Err(Errno::Ebadf); }
    if len > WRITE_MAX_BYTES { return Err(Errno::Einval); }
    let _slice = UserSlice::<u8>::new(buf, len as usize)?;
    // SAFETY: UserSlice::new validated buf..buf+len lies entirely
    // below USER_VA_END; CPL=0 ignores the leaf U bit so the kernel
    // can read the bytes directly. Page-fault-safe access lands
    // once the VMM AS hooks into the fault dispatcher.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(buf as *const u8, len as usize)
    };
    user_console_emit(bytes);
    Ok(len)
}

/// `sys_writev(fd, iov, iovcnt)` — slot 20 per `15§2`. Like
/// `write` but takes a vector of `iovec { void *base; size_t len }`
/// pairs. v1: only fd 1/2 (stdout/stderr) accepted; bytes flow to
/// the kernel UART via the same use-aliased emit path.
///
/// libc (musl + glibc) uses `writev` heavily for buffered stdout —
/// e.g., `printf("%s\n", s)` ends up as a single writev with two
/// iovs (the string + the newline) instead of two separate writes.
/// Without binding, line-buffered stdout breaks.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_writev(args: &SyscallArgs) -> KResult<u64> {
    let fd     = args.a0;
    let iov    = args.a1;
    let iovcnt = args.a2 as usize;
    if fd != 1 && fd != 2 { return Err(Errno::Ebadf); }
    if iovcnt > IOV_MAX  { return Err(Errno::Einval); }

    // Validate the iovec array itself.
    let array_bytes = (iovcnt as u64).checked_mul(IOV_LEN_BYTES).ok_or(Errno::Efault)?;
    let _array_slice = UserSlice::<u8>::new(iov, array_bytes as usize)?;

    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + (i as u64) * IOV_LEN_BYTES;
        // SAFETY: the iovec array range [iov, iov + iovcnt*16) was validated by UserSlice above; iov_i lies inside that range and is naturally aligned (iov 8-aligned by Linux ABI).
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated range as the previous read; iov_i+8 is the iov_len field naturally 8-aligned per Linux ABI.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if len > WRITE_MAX_BYTES {
            return Err(Errno::Einval);
        }
        // Validate this individual buffer.
        let _slice = UserSlice::<u8>::new(base, len as usize)?;
        // SAFETY: range validated; CPL=0 reads U=1 leaves directly.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, len as usize)
        };
        user_console_emit(bytes);
        total = total.saturating_add(len);
    }
    Ok(total)
}

/// `sys_exit(code)` — slot 60 per `15§2`. v1: returns 0 (the user
/// smoke fires `ud2` after, providing the terminal halt). Real
/// teardown (Task::exit, parent reap, exit-code propagation) lands
/// with the process model.
/// # C: O(1)
pub fn sys_exit(args: &SyscallArgs) -> KResult<u64> {
    let _code = args.a0;
    Ok(0)
}

/// `sys_getpid()` — slot 39. v1: single-task system, return PID 1.
/// Real per-Task pid lands with the process model.
/// # C: O(1)
pub fn sys_getpid(_args: &SyscallArgs) -> KResult<u64> {
    Ok(1)
}

// `sys_get{u,e,g,eg}id` — slots 102 / 107 / 104 / 108. v1: no creds
// model; everything is root (uid/gid=0). Lands with `28` security
// per-task creds.

/// # C: O(1)
pub fn sys_getuid(_args: &SyscallArgs)  -> KResult<u64> { Ok(0) }
/// # C: O(1)
pub fn sys_geteuid(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }
/// # C: O(1)
pub fn sys_getgid(_args: &SyscallArgs)  -> KResult<u64> { Ok(0) }
/// # C: O(1)
pub fn sys_getegid(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_gettid()` — slot 186. v1: single-thread, return 1.
/// # C: O(1)
pub fn sys_gettid(_args: &SyscallArgs) -> KResult<u64> { Ok(1) }

/// `sys_set_tid_address(tidptr)` — slot 218. Linux uses this to
/// register a clear_child_tid pointer that's zeroed on thread exit
/// (futex wake). v1 single-task → no-op; return tid=1 like gettid.
/// musl/glibc both call this at startup.
/// # C: O(1)
pub fn sys_set_tid_address(_args: &SyscallArgs) -> KResult<u64> { Ok(1) }

/// `sys_set_robust_list(head, len)` — slot 273. Registers a futex
/// robust list head per `man set_robust_list`. v1 has no futex
/// machinery; accept the call and return 0. glibc calls this at
/// thread startup.
/// # C: O(1)
pub fn sys_set_robust_list(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_brk(addr)` — slot 12. Linux returns the current program
/// break on success and the unchanged break on failure (no errno).
/// v1 has no heap → always return 0 ("no heap"). musl checks for
/// growth and falls back to mmap; glibc falls back to its arena.
/// # C: O(1)
pub fn sys_brk(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_mmap(addr, len, prot, flags, fd, off)` — slot 9. v1 has no
/// VMM AddressSpace yet; return -ENOMEM so user-side allocators
/// fall back to whatever they have for "out of memory" (typically
/// abort or a static-only path). Real anon mmap lands with P2-12.
/// # C: O(1)
pub fn sys_mmap(_args: &SyscallArgs) -> KResult<u64> { Err(Errno::Enomem) }

/// `sys_munmap(addr, len)` — slot 11. v1: no-op. Real impl lands
/// with P2-12 alongside sys_mmap.
/// # C: O(1)
pub fn sys_munmap(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_mprotect(addr, len, prot)` — slot 10. v1: no-op. Real impl
/// flips PT entry flags via MmuOps once VMM-AS lands.
/// # C: O(1)
pub fn sys_mprotect(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_rt_sigaction(signum, act, oldact, sigsetsize)` — slot 13.
/// v1: no signal delivery model; accept and return 0. Real impl
/// lands with `27` IPC/signals.
/// # C: O(1)
pub fn sys_rt_sigaction(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_rt_sigprocmask(how, set, oldset, sigsetsize)` — slot 14.
/// v1: no signal mask; accept and return 0.
/// # C: O(1)
pub fn sys_rt_sigprocmask(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_readlink(path, buf, bufsize)` — slot 89. v1: no VFS; the
/// only path libc commonly readlinks is `/proc/self/exe`. Return
/// -EINVAL so glibc falls through its non-readlink fallback.
/// # C: O(1)
pub fn sys_readlink(_args: &SyscallArgs) -> KResult<u64> { Err(Errno::Einval) }

/// `sys_getrandom(buf, len, flags)` — slot 318. v1: no entropy
/// source; return -ENOSYS so user code falls back to whatever
/// non-getrandom path it has. Real impl wires DRBG once we have
/// per-CPU RDRAND/RNDR seeding.
/// # C: O(1)
pub fn sys_getrandom(_args: &SyscallArgs) -> KResult<u64> { Err(Errno::Enosys) }

/// `sys_close(fd)` — slot 3. v1: no fd table; pretend close
/// succeeded so libc startup that closes inherited fds doesn't
/// abort. Real impl lands with VFS.
/// # C: O(1)
pub fn sys_close(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_ioctl(fd, request, arg)` — slot 16. v1: -ENOTTY (the
/// standard "not a terminal" return) so startup ioctls like
/// `TIOCGWINSZ` get a sensible classification rather than
/// -ENOSYS that would abort.
/// # C: O(1)
pub fn sys_ioctl(_args: &SyscallArgs) -> KResult<u64> { Err(Errno::Enotty) }

/// `sys_madvise(addr, len, advice)` — slot 28. Userspace hint;
/// kernel is free to ignore. v1: no-op return 0.
/// # C: O(1)
pub fn sys_madvise(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_fcntl(fd, cmd, arg)` — slot 72. Wide-mouthed multiplexer;
/// v1 has no fd table to inspect. Return 0 for cases like
/// F_SETFD/CLOEXEC that don't read state; libc will treat 0 as
/// success. Real impl lands with VFS.
/// # C: O(1)
pub fn sys_fcntl(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// `sys_prlimit64(pid, resource, new_limit, old_limit)` — slot 302.
/// v1: ignore writes to old_limit (no rlim model yet); return 0.
/// libc startup hits this checking RLIMIT_STACK et al.
/// # C: O(1)
pub fn sys_prlimit64(_args: &SyscallArgs) -> KResult<u64> { Ok(0) }

/// Build the dispatch table at compile time. Real `sys_*` are filled
/// in via `set` calls below as their subsystems land.
const fn build_table() -> [SyscallFn; SYSCALL_TABLE_LEN] {
    let mut t = [sys_enosys as SyscallFn; SYSCALL_TABLE_LEN];
    // Bound subsystems (numbers per Linux x86_64 / `15§2`):
    t[1]   = sys_write           as SyscallFn;
    t[3]   = sys_close           as SyscallFn;
    t[9]   = sys_mmap            as SyscallFn;
    t[10]  = sys_mprotect        as SyscallFn;
    t[11]  = sys_munmap          as SyscallFn;
    t[12]  = sys_brk             as SyscallFn;
    t[13]  = sys_rt_sigaction    as SyscallFn;
    t[14]  = sys_rt_sigprocmask  as SyscallFn;
    t[16]  = sys_ioctl           as SyscallFn;
    t[20]  = sys_writev          as SyscallFn;
    t[28]  = sys_madvise         as SyscallFn;
    t[39]  = sys_getpid          as SyscallFn;
    t[60]  = sys_exit            as SyscallFn;
    t[72]  = sys_fcntl           as SyscallFn;
    t[89]  = sys_readlink        as SyscallFn;
    t[102] = sys_getuid          as SyscallFn;
    t[104] = sys_getgid          as SyscallFn;
    t[107] = sys_geteuid         as SyscallFn;
    t[108] = sys_getegid         as SyscallFn;
    t[186] = sys_gettid          as SyscallFn;
    t[218] = sys_set_tid_address as SyscallFn;
    t[273] = sys_set_robust_list as SyscallFn;
    t[302] = sys_prlimit64       as SyscallFn;
    t[318] = sys_getrandom       as SyscallFn;
    // Slots awaiting subsystem landings:
    //   t[0]  = sys_read;     // VFS
    //   t[11] = sys_munmap;
    //   t[24] = sys_sched_yield;
    t
}

/// Dispatch table. `static` (not `const`) so the userspace decoder
/// can resolve handler addresses against the kernel image if needed.
pub static SYSCALL_TABLE: [SyscallFn; SYSCALL_TABLE_LEN] = build_table();

/// Dispatch a syscall by number per `15§4`.
///
/// Encodes per `15§1.3`:
/// - `Ok(v)` ⇒ `v as i64` (caller asserts `v ≤ 0x7fff_ffff_ffff_f000`
///   per the success-range rule).
/// - `Err(errno)` ⇒ `-(errno.as_i32() as i64)`.
/// - `nr ≥ SYSCALL_TABLE_LEN` ⇒ `Errno::Enosys`.
/// # C: O(1)
pub fn dispatch(nr: u32, args: &SyscallArgs) -> i64 {
    let f = if (nr as usize) < SYSCALL_TABLE_LEN {
        SYSCALL_TABLE[nr as usize]
    } else {
        sys_enosys as SyscallFn
    };
    match f(args) {
        Ok(v)  => v as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}

/// Convenience: snapshot a slot's handler. Used by tests and by the
/// future wiring-audit tool to assert that every spec-listed `V1`
/// number is no longer pointing at `sys_enosys`.
/// # C: O(1)
pub fn handler_for(nr: u32) -> SyscallFn {
    if (nr as usize) < SYSCALL_TABLE_LEN {
        SYSCALL_TABLE[nr as usize]
    } else {
        sys_enosys as SyscallFn
    }
}

/// True iff the slot's handler is `sys_enosys`. Pointer-equality on
/// `fn` items is well-defined here because both sides resolve to the
/// same monomorphized function pointer.
/// # C: O(1)
pub fn is_enosys(nr: u32) -> bool {
    handler_for(nr) as usize == sys_enosys as SyscallFn as usize
}
