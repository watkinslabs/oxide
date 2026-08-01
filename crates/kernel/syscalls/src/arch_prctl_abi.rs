// `arch_prctl(2)` decision core.
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
//   this file          — sub-code classification + the TASK_SIZE_MAX rule.
//   arch_prctl_abi/cpuid.rs — CPUID-faulting capability + per-task mode rules.
//   arch_prctl_abi/shstk.rs — CET shadow-stack (`ARCH_SHSTK_*`) rule ladder.
//   arch_prctl_abi/xcomp.rs — xstate support/permission rules.
//   arch_prctl_abi/lam.rs   — linear-address-masking (`0x4001..0x4004`) rules.
//   arch_prctl_abi/tests.rs — hosted unit tests (manifest of test modules).

use syscall::errno::Errno;
use syscall::nrs;

pub mod cpuid;
pub mod shstk;
pub mod xcomp;
pub mod lam;

pub use cpuid::{get_cpuid_mode, set_cpuid_mode, CpuidModeChange};
pub use shstk::{shstk_prctl, ShstkOutcome, ShstkState};
pub use xcomp::{xcomp_permitted, xcomp_request, xcomp_supported, XFEATURE_MASK_FPSSE, XFEATURE_MAX};
pub use lam::{lam_enable_tagged_addr, lam_max_tag_bits, lam_untag_mask, LAM_U57_BITS};

/// Linux `TASK_SIZE_MAX` under 4-level paging: `(1 << 47) - PAGE_SIZE`.
/// `hal::USER_VA_END` is the `1 << 47` ceiling, so the last user page is
/// excluded exactly as Linux excludes it.
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
    /// `ARCH_SHSTK_*` — CET shadow-stack control, carrying the sub-code
    /// itself because the five codes share one rule ladder.
    Shstk { option: u64, features: u64 },
    /// `ARCH_GET_XCOMP_SUPP` — write the xstate feature mask the kernel
    /// supports for user state to the user `u64` at `val`.
    GetXcompSupp(u64),
    /// `ARCH_GET_XCOMP_PERM` / `ARCH_GET_XCOMP_GUEST_PERM` — write the mask
    /// this thread group is PERMITTED to use. `guest` picks the group.
    GetXcompPerm { ptr: u64, guest: bool },
    /// `ARCH_REQ_XCOMP_PERM` / `ARCH_REQ_XCOMP_GUEST_PERM` — ask for a
    /// dynamically-enabled xstate component by its highest feature number.
    ReqXcompPerm { idx: u64, guest: bool },
    /// `ARCH_GET_UNTAG_MASK` — write this mm's pointer-untagging mask.
    GetUntagMask(u64),
    /// `ARCH_ENABLE_TAGGED_ADDR` — request `nr_bits` of address masking.
    EnableTaggedAddr(u64),
    /// `ARCH_GET_MAX_TAG_BITS` — write the largest tag width available.
    GetMaxTagBits(u64),
    /// `ARCH_FORCE_TAGGED_SVA` — allow masking despite a live PASID.
    ForceTaggedSva,
    /// `ARCH_MAP_VDSO_{X32,32,64}` — checkpoint/restore vDSO relocation.
    MapVdso(u64),
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
        | nrs::ARCH_SHSTK_UNLOCK | nrs::ARCH_SHSTK_STATUS =>
            Ok(ArchOp::Shstk { option: code, features: arg2 }),
        // The xstate-permission group is handled BEFORE the 64-bit switch in
        // Linux (`SYSCALL_DEFINE2(arch_prctl)` → `fpu_xstate_prctl`), so
        // `arg2` is a feature INDEX for the REQ codes and a user pointer for
        // the GET ones — neither is subject to the TASK_SIZE_MAX rule above.
        nrs::ARCH_GET_XCOMP_SUPP => Ok(ArchOp::GetXcompSupp(arg2)),
        nrs::ARCH_GET_XCOMP_PERM => Ok(ArchOp::GetXcompPerm { ptr: arg2, guest: false }),
        nrs::ARCH_GET_XCOMP_GUEST_PERM => Ok(ArchOp::GetXcompPerm { ptr: arg2, guest: true }),
        nrs::ARCH_REQ_XCOMP_PERM => Ok(ArchOp::ReqXcompPerm { idx: arg2, guest: false }),
        nrs::ARCH_REQ_XCOMP_GUEST_PERM => Ok(ArchOp::ReqXcompPerm { idx: arg2, guest: true }),
        nrs::ARCH_GET_UNTAG_MASK => Ok(ArchOp::GetUntagMask(arg2)),
        nrs::ARCH_ENABLE_TAGGED_ADDR => Ok(ArchOp::EnableTaggedAddr(arg2)),
        nrs::ARCH_GET_MAX_TAG_BITS => Ok(ArchOp::GetMaxTagBits(arg2)),
        nrs::ARCH_FORCE_TAGGED_SVA => Ok(ArchOp::ForceTaggedSva),
        nrs::ARCH_MAP_VDSO_X32 | nrs::ARCH_MAP_VDSO_32 | nrs::ARCH_MAP_VDSO_64 =>
            Ok(ArchOp::MapVdso(code)),
        // Every code the uapi header does not assign. Linux's `default:`.
        _ => Err(Errno::Einval),
    }
}

/// Linux `if (unlikely(arg2 >= TASK_SIZE_MAX)) return -EPERM;`. # C: O(1)
pub fn check_base(base: u64) -> Result<(), Errno> {
    if base >= TASK_SIZE_MAX { Err(Errno::Eperm) } else { Ok(()) }
}

/// `ARCH_MAP_VDSO_*` on a kernel built without checkpoint/restore support:
/// the sub-code falls through `do_arch_prctl_64`'s `default:` to EINVAL.
/// This port relocates no vDSO mapping, so promising success would hand a
/// restoring CRIU image a vDSO that never moved.
/// # C: O(1)
pub fn map_vdso_unsupported() -> i64 { -(Errno::Einval.as_i32() as i64) }

#[cfg(test)]
#[path = "arch_prctl_abi/tests.rs"]
mod tests;
