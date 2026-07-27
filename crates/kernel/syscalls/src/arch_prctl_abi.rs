// `arch_prctl(2)` decision core — Linux `arch/x86/kernel/process.c`
// (`SYSCALL_DEFINE2(arch_prctl)`, `set_cpuid_mode`, `get_cpuid_mode`) and
// `arch/x86/kernel/process_64.c` (`do_arch_prctl_64`).
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: slot file
// `158_arch_prctl.rs` is kernel-only, so every rule written inside it is
// invisible to `cargo test`. ARCH_SET_FS is how glibc installs the TLS
// pointer for every thread, and its address rule is exactly the kind of
// detail that regresses silently (Linux answers EPERM, not EFAULT), so the
// classification + address rule live here and the slot stays a thin shim
// (docs/53).
//
// Module manifest:
//   this file — sub-code classification, the TASK_SIZE_MAX address rule,
//               and the CPUID-faulting capability rule.
//   arch_prctl_abi/tests.rs — hosted unit tests.

use syscall::errno::Errno;
use syscall::nrs;

/// Linux `TASK_SIZE_MAX` — `arch/x86/include/asm/page_64.h:task_size_max()`
/// under 4-level paging: `(1 << 47) - PAGE_SIZE`. `hal::USER_VA_END` is the
/// `1 << 47` ceiling, so the last user page is excluded exactly as Linux
/// excludes it.
pub const TASK_SIZE_MAX: u64 = hal::USER_VA_END - PAGE_SIZE;
const PAGE_SIZE: u64 = 4096;

/// What `do_arch_prctl_64` / `SYSCALL_DEFINE2(arch_prctl)` resolve a sub-code
/// to once its argument rule has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchOp {
    /// `ARCH_SET_FS` — install `val` as this thread's FS base.
    SetFs(u64),
    /// `ARCH_GET_FS` — write the live FS base to the user `u64` at `val`.
    GetFs(u64),
    /// `ARCH_SET_GS` — install `val` as this thread's user GS base.
    SetGs(u64),
    /// `ARCH_GET_GS` — write the user GS base to the user `u64` at `val`.
    GetGs(u64),
    /// `ARCH_GET_CPUID` — report whether user-mode `cpuid` faults.
    GetCpuid,
    /// `ARCH_SET_CPUID` — enable/disable user-mode `cpuid` faulting.
    SetCpuid(bool),
    /// `ARCH_SHSTK_*` — CET shadow-stack control.
    Shstk,
}

/// Linux `do_arch_prctl_64` classification plus the shared address rule.
///
/// `ARCH_SET_FS` / `ARCH_SET_GS` reject `arg2 >= TASK_SIZE_MAX` with
/// **EPERM** — not EFAULT. A non-canonical base would `#GP` the `wrmsr`,
/// and Linux chose EPERM for it; a port that answers EFAULT there makes
/// every glibc TLS-bounds probe read as a bad-pointer error instead of a
/// permission error.
///
/// The `ARCH_GET_*` pointer is NOT checked here: Linux runs a plain
/// `put_user`, so its only failure is EFAULT raised by the copy itself.
/// # C: O(1)
pub fn classify(code: u64, arg2: u64) -> Result<ArchOp, Errno> {
    match code {
        nrs::ARCH_SET_FS => { check_base(arg2)?; Ok(ArchOp::SetFs(arg2)) }
        nrs::ARCH_SET_GS => { check_base(arg2)?; Ok(ArchOp::SetGs(arg2)) }
        nrs::ARCH_GET_FS => Ok(ArchOp::GetFs(arg2)),
        nrs::ARCH_GET_GS => Ok(ArchOp::GetGs(arg2)),
        nrs::ARCH_GET_CPUID => Ok(ArchOp::GetCpuid),
        nrs::ARCH_SET_CPUID => Ok(ArchOp::SetCpuid(arg2 != 0)),
        nrs::ARCH_SHSTK_ENABLE | nrs::ARCH_SHSTK_DISABLE | nrs::ARCH_SHSTK_LOCK
        | nrs::ARCH_SHSTK_UNLOCK | nrs::ARCH_SHSTK_STATUS => Ok(ArchOp::Shstk),
        _ => Err(Errno::Einval),
    }
}

/// Linux `if (unlikely(arg2 >= TASK_SIZE_MAX)) return -EPERM;`. # C: O(1)
pub fn check_base(base: u64) -> Result<(), Errno> {
    if base >= TASK_SIZE_MAX { Err(Errno::Eperm) } else { Ok(()) }
}

/// Linux `get_cpuid_mode()` — `!test_thread_flag(TIF_NOCPUID)`. This port
/// never arms CPUID faulting (see `cpuid_fault_supported`), so user-mode
/// `cpuid` is always enabled and the answer is always 1, exactly as on a
/// Linux host whose CPU lacks `X86_FEATURE_CPUID_FAULT`.
/// # C: O(1)
pub fn get_cpuid_mode() -> i64 { 1 }

/// Linux `set_cpuid_mode()`:
/// `if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT)) return -ENODEV;`
///
/// `supported` comes from the live `MSR_PLATFORM_INFO[31]` probe, which is
/// how Linux derives `X86_FEATURE_CPUID_FAULT` in the first place.
/// # C: O(1)
pub fn set_cpuid_mode(supported: bool) -> i64 {
    if !supported { -(Errno::Enodev.as_i32() as i64) } else { 0 }
}

/// Linux `shstk_prctl` built WITHOUT `CONFIG_X86_USER_SHADOW_STACK` — the
/// `arch/x86/include/asm/shstk.h` stub, `{ return -EINVAL; }`. This port
/// compiles no CET user shadow-stack support, so EINVAL is the matching
/// answer, not `EOPNOTSUPP` (which the real `shstk.c` only reaches when the
/// feature is configured in but the CPU lacks `X86_FEATURE_USER_SHSTK`).
/// # C: O(1)
pub fn shstk_prctl_unsupported() -> i64 { -(Errno::Einval.as_i32() as i64) }

#[cfg(test)]
#[path = "arch_prctl_abi/tests.rs"]
mod tests;
