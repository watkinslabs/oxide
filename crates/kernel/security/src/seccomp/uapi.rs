// seccomp ABI numbers, plus the two kernel-internal values this kernel also
// needs on top of the UAPI set.
// Numbers only; no policy (`52` UAPI-is-not-policy).

/// `seccomp.mode` / `prctl(PR_SET_SECCOMP, <mode>)` values.
pub const SECCOMP_MODE_DISABLED: u32 = 0;
pub const SECCOMP_MODE_STRICT:   u32 = 1;
pub const SECCOMP_MODE_FILTER:   u32 = 2;
/// Internal-only mode, one past the highest UAPI mode value. Latched on a
/// `RET_KILL_*` so a task that somehow survives the kill is caught by the
/// dead-mode arm of the syscall-entry check.
pub const SECCOMP_MODE_DEAD:     u32 = SECCOMP_MODE_FILTER + 1;

/// `seccomp(2)` operations.
pub const SECCOMP_SET_MODE_STRICT:  u64 = 0;
pub const SECCOMP_SET_MODE_FILTER:  u64 = 1;
pub const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
pub const SECCOMP_GET_NOTIF_SIZES:  u64 = 3;

/// Filter return actions. The upper 16 bits are ordered least-permissive
/// first AS A SIGNED VALUE, which is what makes `KILL_PROCESS` (0x80000000,
/// negative as i32) beat every other action in `seccomp_run_filters`.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_KILL_THREAD:  u32 = 0x0000_0000;
/// Legacy alias — `SECCOMP_RET_KILL` IS `KILL_THREAD` (uapi header).
pub const SECCOMP_RET_KILL:         u32 = SECCOMP_RET_KILL_THREAD;
pub const SECCOMP_RET_TRAP:         u32 = 0x0003_0000;
pub const SECCOMP_RET_ERRNO:        u32 = 0x0005_0000;
pub const SECCOMP_RET_USER_NOTIF:   u32 = 0x7fc0_0000;
pub const SECCOMP_RET_TRACE:        u32 = 0x7ff0_0000;
pub const SECCOMP_RET_LOG:          u32 = 0x7ffc_0000;
pub const SECCOMP_RET_ALLOW:        u32 = 0x7fff_0000;

/// `SECCOMP_RET_ACTION_FULL` — the mask `__seccomp_filter` switches on. The
/// 16-bit-narrower `SECCOMP_RET_ACTION` (0x7fff0000) DROPS bit 31 and so
/// folds `KILL_PROCESS` onto `KILL_THREAD`; only the FULL mask may select
/// the action.
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// Kept because the uapi header still exports it; not usable for dispatch.
pub const SECCOMP_RET_ACTION:      u32 = 0x7fff_0000;
pub const SECCOMP_RET_DATA:        u32 = 0x0000_ffff;

/// `MAX_ERRNO` — `SECCOMP_RET_ERRNO` caps its 16-bit data at this before
/// negating it into the return register.
pub const MAX_ERRNO: u32 = 4095;

/// Max cBPF program length in instructions.
pub const BPF_MAXINSNS: usize = 4096;
/// cBPF scratch memory cell count.
pub const BPF_MEMWORDS: usize = 16;

/// `sizeof(struct sock_filter)`.
pub const SOCK_FILTER_BYTES: u64 = 8;
/// `sizeof(struct sock_fprog)` on 64-bit: `u16 len` + 6 pad + `void *filter`.
pub const SOCK_FPROG_BYTES: u64 = 16;
/// Byte offset of `sock_fprog::filter` (after `len` + its alignment padding).
pub const SOCK_FPROG_FILTER_OFF: u64 = 8;

/// `sizeof(struct seccomp_data)` — the bound `seccomp_check_filter` enforces
/// on every `BPF_LD|BPF_W|BPF_ABS` offset.
pub const SECCOMP_DATA_BYTES: u32 = 64;

/// `AUDIT_ARCH_*` tokens reported in `seccomp_data.arch`.
pub const AUDIT_ARCH_X86_64:  u32 = 0xc000_003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// `seccomp_data.arch` for the ABI this build's userspace calls with.
/// # C: O(1)
pub const fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]     { AUDIT_ARCH_X86_64 }
    #[cfg(not(target_arch = "x86_64"))] { AUDIT_ARCH_AARCH64 }
}

/// SECCOMP_MODE_STRICT's fixed allowed syscall set — `{read, write, exit,
/// sigreturn}` — in the CALLING ABI's numbering, which is what
/// `seccomp_data.nr` reports. Hard-coding the x86_64 values would kill every
/// syscall an aarch64 task makes.
#[cfg(target_arch = "x86_64")]
pub const MODE1_SYSCALLS: [u32; 4] = [0, 1, 60, 15];
/// aarch64 generic syscall ABI numbering for the same set.
#[cfg(not(target_arch = "x86_64"))]
pub const MODE1_SYSCALLS: [u32; 4] = [63, 64, 93, 139];

/// `si_code` for a seccomp-raised `SIGSYS` (`SYS_SECCOMP`).
pub const SYS_SECCOMP: i32 = 1;

/// `PTRACE_EVENT_SECCOMP` and the `PTRACE_O_TRACESECCOMP` option bit that
/// arms it. Tested against the tracer's enabled ptrace-event options on
/// every filter run when a tracer is attached.
pub const PTRACE_EVENT_SECCOMP: u32 = 7;
pub const PTRACE_O_TRACESECCOMP: u32 = 1 << PTRACE_EVENT_SECCOMP;
/// `PTRACE_O_SUSPEND_SECCOMP` — `__secure_computing` returns 0 (no filtering
/// at all) while a CAP_SYS_ADMIN tracer has this set on the tracee.
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;
