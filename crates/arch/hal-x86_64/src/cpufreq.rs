//! x86 fixed-hardware ACPI performance-state access.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use crate::cpuid::cpuid;

/// Fixed-hardware interface the processor advertises for ACPI P-state control.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PstateBackend { Intel, Amd }

#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const INTEL_VENDOR: [u8; 12] = *b"GenuineIntel";
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const AMD_VENDOR: [u8; 12] = *b"AuthenticAMD";
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const CPUID_EIST: u32 = 1 << 7;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const CPUID_AMD_POWER: u32 = 0x8000_0007;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const CPUID_AMD_HW_PSTATE: u32 = 1 << 7;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const IA32_PERF_CTL: u32 = 0x0000_0199;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const AMD_PERF_CTL: u32 = 0xC001_0062;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const INTEL_CONTROL_MASK: u64 = 0xffff;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const AMD_CONTROL_MASK: u64 = 0x7;

/// ACPI fixed-hardware P-state backend this CPU advertises, if any. # C: O(1)
pub fn pstate_backend() -> Option<PstateBackend> {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: CPUID is unprivileged and has no memory side effects.
        let (max_std, ebx, ecx, edx) = unsafe { cpuid(0) };
        let vendor = vendor_bytes(ebx, ecx, edx);
        // SAFETY: leaf 1 exists on every x86_64 processor.
        let (_, _, leaf1_ecx, _) = unsafe { cpuid(1) };
        // SAFETY: the extended-root leaf exists on every x86_64 processor.
        let (max_extended, _, _, _) = unsafe { cpuid(0x8000_0000) };
        let amd_power_edx = if max_extended >= CPUID_AMD_POWER {
            // SAFETY: the preceding maximum-leaf query admitted this leaf.
            let (_, _, _, edx) = unsafe { cpuid(CPUID_AMD_POWER) };
            edx
        } else { 0 };
        return backend_from_cpuid(vendor, max_std, leaf1_ecx, max_extended, amd_power_edx);
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { None }
}

/// Program one control value through an already-validated fixed-hardware
/// backend. Returns false outside the kernel target. # C: O(1)
pub fn write_pstate(backend: PstateBackend, control: u32) -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `pstate_backend` admitted the selected vendor feature, so
        // its performance-control MSR exists and this runs at kernel CPL.
        unsafe {
            match backend {
                PstateBackend::Intel => {
                    let previous = rdmsr(IA32_PERF_CTL);
                    wrmsr(IA32_PERF_CTL, (previous & !INTEL_CONTROL_MASK)
                        | (u64::from(control) & INTEL_CONTROL_MASK));
                }
                PstateBackend::Amd => wrmsr(AMD_PERF_CTL, u64::from(control)),
            }
        }
        return true;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = (backend, control); false }
}

/// Read the control value through an already-validated fixed-hardware
/// backend. `None` outside the kernel target. # C: O(1)
pub fn read_pstate(backend: PstateBackend) -> Option<u32> {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `pstate_backend` admitted the selected vendor feature, so
        // its performance-control MSR exists and this runs at kernel CPL.
        let value = unsafe {
            match backend {
                PstateBackend::Intel => rdmsr(IA32_PERF_CTL) & INTEL_CONTROL_MASK,
                PstateBackend::Amd => rdmsr(AMD_PERF_CTL) & AMD_CONTROL_MASK,
            }
        };
        return u32::try_from(value).ok();
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = backend; None }
}

/// Identify a supported backend from the CPUID leaves the architecture reads.
/// # C: O(1)
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
fn backend_from_cpuid(vendor: [u8; 12], max_std: u32, leaf1_ecx: u32,
                      max_extended: u32, amd_power_edx: u32) -> Option<PstateBackend>
{
    if vendor == INTEL_VENDOR && max_std >= 1 && leaf1_ecx & CPUID_EIST != 0 {
        return Some(PstateBackend::Intel);
    }
    if vendor == AMD_VENDOR && max_extended >= CPUID_AMD_POWER
        && amd_power_edx & CPUID_AMD_HW_PSTATE != 0 {
        return Some(PstateBackend::Amd);
    }
    None
}

/// CPUID vendor text is EBX, EDX, ECX rather than register-order text.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn vendor_bytes(ebx: u32, ecx: u32, edx: u32) -> [u8; 12] {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&ebx.to_le_bytes());
    value[4..8].copy_from_slice(&edx.to_le_bytes());
    value[8..12].copy_from_slice(&ecx.to_le_bytes());
    value
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: caller admits an implemented performance-control MSR at CPL0.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
                         options(nomem, nostack, preserves_flags));
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: caller admits an implemented performance-control MSR at CPL0.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32,
                         in("edx") (value >> 32) as u32,
                         options(nomem, nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_eist_selects_the_intel_backend() {
        assert_eq!(backend_from_cpuid(INTEL_VENDOR, 1, CPUID_EIST, 0, 0),
                   Some(PstateBackend::Intel));
    }

    #[test]
    fn amd_hardware_pstates_need_the_extended_leaf_and_feature_bit() {
        assert_eq!(backend_from_cpuid(AMD_VENDOR, 1, 0, CPUID_AMD_POWER,
                                      CPUID_AMD_HW_PSTATE), Some(PstateBackend::Amd));
        assert_eq!(backend_from_cpuid(AMD_VENDOR, 1, 0, CPUID_AMD_POWER - 1,
                                      CPUID_AMD_HW_PSTATE), None);
    }

    #[test]
    fn a_vendor_match_without_the_capability_is_not_enough() {
        assert_eq!(backend_from_cpuid(INTEL_VENDOR, 1, 0, 0, 0), None);
        assert_eq!(backend_from_cpuid(*b"KVMKVMKVM\0\0\0", 1, CPUID_EIST, 0, 0), None);
    }
}
