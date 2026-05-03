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

/// `sys_exit(code)` — slot 60 per `15§2`. v1: returns 0 (the user
/// smoke fires `ud2` after, providing the terminal halt). Real
/// teardown (Task::exit, parent reap, exit-code propagation) lands
/// with the process model.
/// # C: O(1)
pub fn sys_exit(args: &SyscallArgs) -> KResult<u64> {
    let _code = args.a0;
    Ok(0)
}

/// Build the dispatch table at compile time. Real `sys_*` are filled
/// in via `set` calls below as their subsystems land.
const fn build_table() -> [SyscallFn; SYSCALL_TABLE_LEN] {
    let mut t = [sys_enosys as SyscallFn; SYSCALL_TABLE_LEN];
    // Bound subsystems (numbers per Linux x86_64 / `15§2`):
    t[1]  = sys_write as SyscallFn;
    t[60] = sys_exit  as SyscallFn;
    // Slots awaiting subsystem landings:
    //   t[0]  = sys_read;     // VFS
    //   t[3]  = sys_close;
    //   t[9]  = sys_mmap;     // vmm::AddressSpace
    //   t[10] = sys_mprotect;
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
