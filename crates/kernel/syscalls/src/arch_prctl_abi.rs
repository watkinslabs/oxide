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
    /// `ARCH_GET_XCOMP_SUPP` — write the xstate feature mask the kernel
    /// supports for user state to the user `u64` at `val`.
    GetXcompSupp(u64),
    /// `ARCH_GET_XCOMP_PERM` / `ARCH_GET_XCOMP_GUEST_PERM` — write the mask
    /// this thread group is PERMITTED to use.
    GetXcompPerm(u64),
    /// `ARCH_REQ_XCOMP_PERM` / `ARCH_REQ_XCOMP_GUEST_PERM` — ask for a
    /// dynamically-enabled xstate component by its highest feature number.
    ReqXcompPerm(u64),
}

/// `XFEATURE_MAX` (`arch/x86/include/asm/fpu/types.h`) — the ceiling
/// `xstate_request_perm` compares the requested feature number against.
pub const XFEATURE_MAX: u64 = 19;

/// `XFEATURE_MASK_FPSSE` — x87 + SSE, the two components every XSAVE-capable
/// CPU has and the whole user mask on a kernel that fell back to FXSAVE.
pub const XFEATURE_MASK_FPSSE: u64 = 0b11;

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
        // The xstate-permission group is handled BEFORE the 64-bit switch in
        // Linux (`do_arch_prctl_common`), so `arg2` is a feature INDEX for the
        // REQ codes and a user pointer for the GET ones — neither is subject
        // to the TASK_SIZE_MAX rule above.
        nrs::ARCH_GET_XCOMP_SUPP => Ok(ArchOp::GetXcompSupp(arg2)),
        nrs::ARCH_GET_XCOMP_PERM | nrs::ARCH_GET_XCOMP_GUEST_PERM =>
            Ok(ArchOp::GetXcompPerm(arg2)),
        nrs::ARCH_REQ_XCOMP_PERM | nrs::ARCH_REQ_XCOMP_GUEST_PERM =>
            Ok(ArchOp::ReqXcompPerm(arg2)),
        // ARCH_MAP_VDSO_* (0x2001..0x2003), the CONFIG_ADDRESS_MASKING LAM
        // codes (ARCH_GET_UNTAG_MASK / ARCH_ENABLE_TAGGED_ADDR /
        // ARCH_GET_MAX_TAG_BITS / ARCH_FORCE_TAGGED_SVA, 0x4001..0x4004) and
        // every unknown code land here. EINVAL is what Linux answers for the
        // LAM group without CONFIG_ADDRESS_MASKING, and this port maps no LAM
        // bits into CR3, so accepting ARCH_ENABLE_TAGGED_ADDR would promise a
        // pointer-masking behaviour the MMU is not configured for.
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

/// The user-visible xstate mask, from the live XCR0 the FPU owner programmed.
///
/// Linux reports `fpu_user_cfg.max_features | fpu_user_cfg.legacy_features`.
/// On a kernel that fell back to FXSAVE there is no XCR0 and the answer is
/// the legacy x87+SSE pair, which is exactly the state such a kernel saves.
/// # C: O(1)
pub fn xcomp_supported(xsave_active: bool, xcr0: u64) -> u64 {
    if xsave_active { xcr0 | XFEATURE_MASK_FPSSE } else { XFEATURE_MASK_FPSSE }
}

/// `xstate_request_perm(idx, guest)`.
///
/// The index is the HIGHEST feature number of the facility being asked for,
/// and the permission table has exactly one non-zero entry (AMX's
/// `XFEATURE_XTILE_DATA`). So an index at or above `XFEATURE_MAX` is EINVAL,
/// and every valid index that names no dynamically-enabled facility — or one
/// the CPU/kernel does not offer — is **EOPNOTSUPP**, not EINVAL. This port
/// enables no AMX component (its XCR0 request stops below the tile bits) and
/// programs no XFD, so no index can succeed; a request that returned 0 would
/// tell a runtime it may execute AMX instructions that will `#UD`.
/// # C: O(1)
pub fn xcomp_request(idx: u64, supported: u64) -> i64 {
    if idx >= XFEATURE_MAX { return -(Errno::Einval.as_i32() as i64); }
    // `xstate_prctl_req[idx]` — zero for every index except XTILE_DATA(18).
    const XFEATURE_XTILE_DATA: u64 = 18;
    const XFEATURE_MASK_XTILE: u64 = (1 << 17) | (1 << 18);
    let requested = if idx == XFEATURE_XTILE_DATA { XFEATURE_MASK_XTILE } else { 0 };
    if requested == 0 || (supported & requested) != requested {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    0
}

#[cfg(test)]
#[path = "arch_prctl_abi/tests.rs"]
mod tests;
