// PSCI (Power State Coordination Interface) per ARM DEN 0022D.
// v1: just CPU_ON, the entry point AP startup needs. Other PSCI
// services (CPU_OFF, SYSTEM_RESET) ride alongside the power
// subsystem in `docs/32`.
//
// PSCI invocation: SMC #0 (or HVC depending on conduit). EDK2 +
// QEMU virt expose SMC. Function ID 0xC4000003 = CPU_ON 64-bit.
// Args: function_id, target_mpidr, entry_pa, context_id.
// Return: status in x0 per ARM DEN 0022D Table 5.

#![cfg(target_arch = "aarch64")]

/// SMC32 / SMC64 function IDs per ARM DEN 0022D Table 4.
pub const PSCI_VERSION:    u32 = 0x8400_0000;
pub const PSCI_CPU_OFF:    u32 = 0x8400_0002;
pub const PSCI_CPU_ON_64:  u32 = 0xC400_0003;
pub const PSCI_AFFINITY_INFO_64: u32 = 0xC400_0004;

/// Status codes per ARM DEN 0022D Table 5.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsciStatus {
    Success           = 0,
    NotSupported      = -1,
    InvalidParameters = -2,
    Denied            = -3,
    AlreadyOn         = -4,
    OnPending         = -5,
    InternalFailure   = -6,
    NotPresent        = -7,
    Disabled          = -8,
    InvalidAddress    = -9,
    Other             = -100,
}

/// Decode an i32 PSCI status into the enum. Pure helper —
/// hosted-testable.
/// # C: O(1)
pub fn decode_status(raw: i32) -> PsciStatus {
    match raw {
         0 => PsciStatus::Success,
        -1 => PsciStatus::NotSupported,
        -2 => PsciStatus::InvalidParameters,
        -3 => PsciStatus::Denied,
        -4 => PsciStatus::AlreadyOn,
        -5 => PsciStatus::OnPending,
        -6 => PsciStatus::InternalFailure,
        -7 => PsciStatus::NotPresent,
        -8 => PsciStatus::Disabled,
        -9 => PsciStatus::InvalidAddress,
        _  => PsciStatus::Other,
    }
}

/// Issue an SMC instruction with up to 4 arguments and return x0.
///
/// # SAFETY: caller asserts the SMC conduit is configured (EDK2 /
/// firmware exposes it; v1 boot relies on this); IRQs masked
/// because secure-world entry is non-reentrant on most PSCI impls.
/// # C: O(SMC round-trip)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn smc(fn_id: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    // SAFETY: SMC #0 is the standard PSCI conduit on EDK2 / QEMU
    // virt. Inputs go in x0..x3 per ARM DEN 0022D §5.1 calling
    // convention; the secure monitor returns the status code in x0.
    unsafe {
        // `smc #0` requires the `sec` arch extension to assemble;
        // many AArch64 assembler defaults reject it. Emit the
        // instruction encoding directly via `.inst` (0xd4000003)
        // — same opcode, no arch-extension dance.
        core::arch::asm!(
            ".inst 0xd4000003",
            inout("x0") fn_id as u64 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret
}

/// Hosted stub for SMC — returns NotSupported. Lets hosted tests
/// run without a real secure monitor.
/// # SAFETY: trivially safe; no asm.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn smc(_fn_id: u32, _a1: u64, _a2: u64, _a3: u64) -> i64 { -1 }

/// PSCI_CPU_ON_64: bring up the CPU identified by `target_mpidr`,
/// which on cold-power-on jumps to `entry_pa` with `context_id`
/// passed in x0 (see ARM DEN 0022D §5.1.4).
///
/// # SAFETY: caller is the boot path on the boot CPU; SMC conduit
/// is configured; `entry_pa` points at trampoline code that has
/// been published with the right cache/coherency state for AP
/// fetch.
/// # C: O(SMC round-trip)
pub unsafe fn cpu_on(target_mpidr: u64, entry_pa: u64, context_id: u64) -> PsciStatus {
    // SAFETY: per fn contract — secure-monitor SMC; PSCI_CPU_ON_64 is the canonical bring-up call.
    let raw = unsafe { smc(PSCI_CPU_ON_64, target_mpidr, entry_pa, context_id) };
    decode_status(raw as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_known_codes() {
        assert_eq!(decode_status(0),  PsciStatus::Success);
        assert_eq!(decode_status(-1), PsciStatus::NotSupported);
        assert_eq!(decode_status(-4), PsciStatus::AlreadyOn);
        assert_eq!(decode_status(-9), PsciStatus::InvalidAddress);
    }

    #[test]
    fn decode_unknown_falls_to_other() {
        assert_eq!(decode_status(-42),  PsciStatus::Other);
        assert_eq!(decode_status(1234), PsciStatus::Other);
    }
}
