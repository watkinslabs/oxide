// `ARCH_GET_CPUID` / `ARCH_SET_CPUID` rules — Linux `get_cpuid_mode()`,
// `set_cpuid_mode()`, `enable_cpuid()`, `disable_cpuid()`.
//
// Ungated on purpose: the slot file is kernel-only, so a rule written there
// is never compiled by `cargo test`.

use syscall::errno::Errno;

/// `MSR_PLATFORM_INFO`. Bit 31 is the CPUID-faulting capability bit Linux
/// probes to derive `X86_FEATURE_CPUID_FAULT` on an Intel part.
pub const MSR_PLATFORM_INFO: u32 = 0x0000_00CE;
/// `MSR_PLATFORM_INFO_CPUID_FAULT_BIT`.
pub const MSR_PLATFORM_INFO_CPUID_FAULT_BIT: u32 = 31;

/// `MSR_MISC_FEATURES_ENABLES` — the Intel MSR whose bit 0 arms the fault.
pub const MSR_MISC_FEATURES_ENABLES: u32 = 0x0000_0140;
/// `MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT`.
pub const MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT: u32 = 0;

/// `MSR_K7_HWCR` — the AMD MSR whose `CPUID_USER_DIS` bit arms the fault.
pub const MSR_K7_HWCR: u32 = 0xC001_0015;
/// `MSR_K7_HWCR_CPUID_USER_DIS_BIT`.
pub const MSR_K7_HWCR_CPUID_USER_DIS_BIT: u32 = 35;

/// Which vendor mechanism arms CPUID faulting on this CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuidFaultMsr {
    /// No mechanism — `X86_FEATURE_CPUID_FAULT` is clear.
    None,
    /// Intel: `MSR_MISC_FEATURES_ENABLES[0]`, gated on `MSR_PLATFORM_INFO[31]`.
    Intel,
    /// AMD: `MSR_K7_HWCR[35]`, gated on `X86_FEATURE_GP_ON_USER_CPUID`.
    Amd,
}

impl CpuidFaultMsr {
    /// Whether `boot_cpu_has(X86_FEATURE_CPUID_FAULT)` would be true.
    /// # C: O(1)
    pub fn supported(self) -> bool { !matches!(self, CpuidFaultMsr::None) }
}

/// `probe_cpuid_fault` on an Intel part: the capability is `MSR_PLATFORM_INFO`
/// bit 31. Linux runs this only after the vendor check, because the MSR does
/// not exist on other vendors and reading it there `#GP`s.
/// # C: O(1)
pub fn intel_platform_info_has_cpuid_fault(platform_info: u64) -> bool {
    platform_info & (1u64 << MSR_PLATFORM_INFO_CPUID_FAULT_BIT) != 0
}

/// The MSR value `set_cpuid_faulting(on)` writes on an Intel part: a
/// read-modify-write of `MSR_MISC_FEATURES_ENABLES` that touches only bit 0.
/// # C: O(1)
pub fn intel_misc_features_with_fault(prev: u64, on: bool) -> u64 {
    let bit = 1u64 << MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT;
    if on { prev | bit } else { prev & !bit }
}

/// The MSR value `set_cpuid_faulting(on)` writes on an AMD part: a
/// set/clear of `MSR_K7_HWCR[CPUID_USER_DIS]`, leaving every other bit alone.
/// # C: O(1)
pub fn amd_hwcr_with_fault(prev: u64, on: bool) -> u64 {
    let bit = 1u64 << MSR_K7_HWCR_CPUID_USER_DIS_BIT;
    if on { prev | bit } else { prev & !bit }
}

/// Linux `get_cpuid_mode()` — `!test_thread_flag(TIF_NOCPUID)`. 1 means
/// user-mode `cpuid` executes; 0 means it faults.
///
/// The answer is per-TASK state, not a CPU capability: a task that never
/// called `ARCH_SET_CPUID(0)` reads 1 even on a CPU that can fault, and a
/// task that did reads 0. Reporting a constant would make the round-trip
/// `arch_prctl(ARCH_SET_CPUID, 0); arch_prctl(ARCH_GET_CPUID)` lie.
/// # C: O(1)
pub fn get_cpuid_mode(nocpuid: bool) -> i64 { if nocpuid { 0 } else { 1 } }

/// What `set_cpuid_mode` asks the caller to do to the live CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuidModeChange {
    /// `-ENODEV`: `!boot_cpu_has(X86_FEATURE_CPUID_FAULT)`.
    Enodev,
    /// The requested mode already holds; Linux's `test_and_set_thread_flag`
    /// returned the same value, so no MSR write happens.
    AlreadySet,
    /// Store `nocpuid` in the task AND write the vendor MSR with this arming
    /// state, synchronously, before returning to user.
    Arm { nocpuid: bool },
}

/// Linux `set_cpuid_mode()`:
/// `if (!boot_cpu_has(X86_FEATURE_CPUID_FAULT)) return -ENODEV;` then
/// `enable_cpuid()` / `disable_cpuid()`, each of which flips the MSR only
/// when the thread flag actually changed.
///
/// `no_new_privs` does NOT gate this: CPUID faulting removes a capability
/// from the task rather than granting one, and Linux applies no credential
/// or `nnp` check on either sub-code. A port that added one would break
/// seccomp-confined runtimes that disable `cpuid` for determinism.
/// # C: O(1)
pub fn set_cpuid_mode(msr: CpuidFaultMsr, enable: bool, cur_nocpuid: bool) -> CpuidModeChange {
    if !msr.supported() { return CpuidModeChange::Enodev; }
    let want_nocpuid = !enable;
    if want_nocpuid == cur_nocpuid { return CpuidModeChange::AlreadySet; }
    CpuidModeChange::Arm { nocpuid: want_nocpuid }
}

/// The errno `CpuidModeChange::Enodev` encodes, as a syscall return value.
/// # C: O(1)
pub fn enodev() -> i64 { -(Errno::Enodev.as_i32() as i64) }

/// Linux `arch_setup_new_exec()`: "If cpuid was previously disabled for this
/// task, re-enable it." A fresh exec image never inherits the fault.
/// # C: O(1)
pub fn nocpuid_after_exec() -> bool { false }
