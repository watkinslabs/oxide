// CPUID-faulting capability probe + arming, the substrate behind
// `arch_prctl(ARCH_SET_CPUID)`.
//
// Two unrelated vendor mechanisms answer the same question "may ring 3
// execute `cpuid`?":
//   Intel — capability advertised in `MSR_PLATFORM_INFO[31]`, armed by
//           `MSR_MISC_FEATURES_ENABLES[0]`.
//   AMD   — capability advertised in CPUID.(EAX=0x80000021):EAX[17], armed by
//           `MSR_K7_HWCR[35]`.
// Neither MSR exists on the other vendor, and `MSR_PLATFORM_INFO` is absent
// on several hypervisor CPU models even for an Intel-branded guest, so the
// probe reads it through the `__ex_table` recovery path rather than assuming.

use core::sync::atomic::{AtomicU8, Ordering};

/// `cpuid_fault_kind()` results. Kept as plain integers so the ABI crate can
/// map them without this crate learning about syscall types.
pub const CPUID_FAULT_NONE:  u8 = 0;
pub const CPUID_FAULT_INTEL: u8 = 1;
pub const CPUID_FAULT_AMD:   u8 = 2;
/// Sentinel meaning "not probed yet".
const CPUID_FAULT_UNPROBED: u8 = 0xff;

/// The vendor MSR numbers and bits this module reads and writes. Gated as a
/// unit rather than per-item: none of it is reachable off the x86 kernel
/// target, where the probe and the arming path are both compiled out.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
mod msr {
    pub const PLATFORM_INFO: u32 = 0x0000_00CE;
    pub const PLATFORM_INFO_CPUID_FAULT: u64 = 1 << 31;
    pub const MISC_FEATURES_ENABLES: u32 = 0x0000_0140;
    pub const MISC_FEATURES_ENABLES_CPUID_FAULT: u64 = 1 << 0;
    pub const K7_HWCR: u32 = 0xC001_0015;
    pub const K7_HWCR_CPUID_USER_DIS: u64 = 1 << 35;
    /// CPUID leaf carrying AMD's `GP_ON_USER_CPUID` bit, and the bit itself.
    pub const CPUID_LEAF_AMD_EXT_FEATURES: u32 = 0x8000_0021;
    pub const CPUID_AMD_GP_ON_USER_CPUID: u32 = 1 << 17;
}

/// Probed once; every CPU in a package reports the same capability, which is
/// why Linux keys the feature off `boot_cpu_has` rather than a per-CPU test.
static KIND: AtomicU8 = AtomicU8::new(CPUID_FAULT_UNPROBED);

/// Which CPUID-faulting mechanism this CPU offers, probing on first call.
/// `CPUID_FAULT_NONE` is Linux's `!boot_cpu_has(X86_FEATURE_CPUID_FAULT)`,
/// the condition `ARCH_SET_CPUID` answers ENODEV for.
/// # C: O(1) amortised — one `cpuid` + at most one `rdmsr` on first call
pub fn cpuid_fault_kind() -> u8 {
    let cached = KIND.load(Ordering::Acquire);
    if cached != CPUID_FAULT_UNPROBED { return cached; }
    let kind = probe();
    KIND.store(kind, Ordering::Release);
    kind
}

/// Linux `boot_cpu_has(X86_FEATURE_CPUID_FAULT)`.
/// # C: O(1)
pub fn cpuid_fault_supported() -> bool { cpuid_fault_kind() != CPUID_FAULT_NONE }

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn probe() -> u8 {
    // SAFETY: `cpuid` is unprivileged with no memory effect; leaf 0 returns
    // the vendor string in EBX/EDX/ECX.
    let (_, ebx, ecx, edx) = unsafe { crate::cpuid::cpuid(0) };
    // "GenuineIntel" / "AuthenticAMD" in EBX,EDX,ECX order.
    let intel = ebx == 0x756e_6547 && edx == 0x4965_6e69 && ecx == 0x6c65_746e;
    let amd = ebx == 0x6874_7541 && edx == 0x6974_6e65 && ecx == 0x444d_4163;
    if intel {
        // SAFETY: `rdmsr_safe` recovers through `__ex_table` if the MSR is
        // unimplemented; it reads no memory and writes no CPU state.
        if let Some(v) = unsafe { rdmsr_safe(msr::PLATFORM_INFO) } {
            if v & msr::PLATFORM_INFO_CPUID_FAULT != 0 { return CPUID_FAULT_INTEL; }
        }
        return CPUID_FAULT_NONE;
    }
    if amd {
        // SAFETY: `cpuid` is unprivileged; leaf 0x80000000 reports the highest
        // extended leaf, which must be checked before reading 0x80000021.
        let (max_ext, _, _, _) = unsafe { crate::cpuid::cpuid(0x8000_0000) };
        if max_ext >= msr::CPUID_LEAF_AMD_EXT_FEATURES {
            // SAFETY: leaf is within the CPU-reported extended range.
            let (eax, _, _, _) = unsafe { crate::cpuid::cpuid(msr::CPUID_LEAF_AMD_EXT_FEATURES) };
            if eax & msr::CPUID_AMD_GP_ON_USER_CPUID != 0 { return CPUID_FAULT_AMD; }
        }
    }
    CPUID_FAULT_NONE
}

#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
fn probe() -> u8 { CPUID_FAULT_NONE }

/// Program this CPU so ring-3 `cpuid` does (`on`) or does not raise #GP.
///
/// Read-modify-write in both vendor arms: the same MSRs carry unrelated
/// controls (`RING3MWAIT` on Intel, a pile of erratum workarounds on AMD),
/// and a blind write would clear whatever firmware or an earlier boot step
/// left there.
///
/// # SAFETY: privileged MSR access, legal at CPL=0. Caller must be running on
/// the CPU whose state is being changed, with preemption disabled, so the
/// MSR and the owning task's flag cannot diverge across a migration.
/// # C: O(1)
/// # Ctx: syscall or context-switch tail; preempt-off
pub unsafe fn set_cpuid_faulting(on: bool) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    match cpuid_fault_kind() {
        CPUID_FAULT_INTEL => {
            // SAFETY: MSR_MISC_FEATURES_ENABLES exists — the probe read
            // MSR_PLATFORM_INFO's capability bit on this same CPU.
            unsafe {
                let prev = rdmsr(msr::MISC_FEATURES_ENABLES);
                let next = if on { prev | msr::MISC_FEATURES_ENABLES_CPUID_FAULT }
                           else { prev & !msr::MISC_FEATURES_ENABLES_CPUID_FAULT };
                wrmsr(msr::MISC_FEATURES_ENABLES, next);
            }
        }
        CPUID_FAULT_AMD => {
            // SAFETY: MSR_K7_HWCR exists on every AMD part that reports
            // GP_ON_USER_CPUID, which the probe confirmed.
            unsafe {
                let prev = rdmsr(msr::K7_HWCR);
                let next = if on { prev | msr::K7_HWCR_CPUID_USER_DIS }
                           else { prev & !msr::K7_HWCR_CPUID_USER_DIS };
                wrmsr(msr::K7_HWCR, next);
            }
        }
        _ => {}
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = on; }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: `rdmsr` is privileged and legal at CPL=0; the caller has
    // established that `msr` is implemented on this CPU.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn wrmsr(msr: u32, val: u64) {
    // SAFETY: `wrmsr` is privileged and legal at CPL=0; the caller has
    // established that `msr` is implemented and that `val` preserves every
    // bit it does not own.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") val as u32,
                         in("edx") (val >> 32) as u32,
                         options(nomem, nostack, preserves_flags));
    }
}

/// `rdmsr` that returns `None` instead of dying when the MSR is not
/// implemented. The `__ex_table` entry points the #GP at the `3:` label,
/// where `edx:eax` are zeroed and the carry-style flag register reports the
/// fault — the same recovery shape `oxide_raw_copy_from_user` uses.
///
/// # SAFETY: privileged instruction, legal at CPL=0. Reads no memory. A #GP
/// from an unimplemented MSR is recovered by the fixup, so the only
/// requirement on the caller is that a fault here is acceptable.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn rdmsr_safe(msr: u32) -> Option<u64> {
    let lo: u32; let hi: u32; let ok: u32;
    // SAFETY: per fn contract — the `__ex_table` entry recovers the #GP an
    // unimplemented `msr` raises, landing at `3:` with ok = 0.
    unsafe {
        core::arch::asm!(
            "mov {ok:e}, 1",
            "2: rdmsr",
            "   jmp 4f",
            "3: xor eax, eax",
            "   xor edx, edx",
            "   mov {ok:e}, 0",
            "4:",
            ".pushsection __ex_table,\"a\"",
            ".balign 8",
            ".long 2b - .",
            ".long 3b - .",
            ".popsection",
            ok = out(reg) ok,
            in("ecx") msr, out("eax") lo, out("edx") hi,
            options(nostack),
        );
    }
    if ok == 0 { None } else { Some(((hi as u64) << 32) | (lo as u64)) }
}
