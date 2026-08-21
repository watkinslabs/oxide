// Function-ID arithmetic, status decode and version-field tests. Hosted: this
// module's parent carries no target gate, so these run on every `cargo test`.

use super::*;

#[test]
fn function_ids_match_the_interface_assignment() {
    assert_eq!(PSCI_VERSION,            0x8400_0000);
    assert_eq!(PSCI_CPU_SUSPEND_64,     0xC400_0001);
    assert_eq!(PSCI_CPU_OFF,            0x8400_0002);
    assert_eq!(PSCI_CPU_ON_64,          0xC400_0003);
    assert_eq!(PSCI_AFFINITY_INFO_64,   0xC400_0004);
    assert_eq!(PSCI_SYSTEM_OFF,         0x8400_0008);
    assert_eq!(PSCI_SYSTEM_RESET,       0x8400_0009);
    assert_eq!(PSCI_FEATURES,           0x8400_000A);
    assert_eq!(PSCI_SYSTEM_SUSPEND_64,  0xC400_000E);
}

#[test]
fn affinity_info_distinguishes_on_off_and_on_pending() {
    assert!(!affinity_level_is_off(PSCI_AFFINITY_LEVEL_ON));
    assert!(affinity_level_is_off(PSCI_AFFINITY_LEVEL_OFF));
    assert!(!affinity_level_is_off(PSCI_AFFINITY_LEVEL_ON_PENDING));
    assert!(!affinity_level_is_off(PsciStatus::Denied as i64));
}

#[test]
fn smc64_ids_carry_the_calling_convention_bit_and_smc32_ids_do_not() {
    assert_ne!(PSCI_SYSTEM_SUSPEND_64 & PSCI_FN_64BIT, 0);
    assert_ne!(PSCI_CPU_ON_64 & PSCI_FN_64BIT, 0);
    assert_eq!(PSCI_FEATURES & PSCI_FN_64BIT, 0);
    assert_eq!(PSCI_VERSION & PSCI_FN_64BIT, 0);
}

#[test]
fn decode_known_codes() {
    assert_eq!(decode_status(0),  PsciStatus::Success);
    assert_eq!(decode_status(-1), PsciStatus::NotSupported);
    assert_eq!(decode_status(-2), PsciStatus::InvalidParameters);
    assert_eq!(decode_status(-3), PsciStatus::Denied);
    assert_eq!(decode_status(-4), PsciStatus::AlreadyOn);
    assert_eq!(decode_status(-9), PsciStatus::InvalidAddress);
}

#[test]
fn decode_unknown_falls_to_other() {
    assert_eq!(decode_status(-42),  PsciStatus::Other);
    assert_eq!(decode_status(1234), PsciStatus::Other);
}

#[test]
fn not_supported_constant_agrees_with_the_enum() {
    assert_eq!(PSCI_RET_NOT_SUPPORTED, -1);
    assert_eq!(decode_status(PSCI_RET_NOT_SUPPORTED as i32), PsciStatus::NotSupported);
}

#[test]
fn version_fields_round_trip() {
    let v = psci_version(1, 1);
    assert_eq!(version_major(v), 1);
    assert_eq!(version_minor(v), 1);
    assert_eq!(v, 0x0001_0001);
    assert_eq!(PSCI_VERSION_1_0, 0x0001_0000);
    assert_eq!(version_major(psci_version(0, 2)), 0);
    assert_eq!(version_minor(psci_version(0, 2)), 2);
}

#[test]
fn cpu_suspend_format_and_state_masks_follow_the_firmware_feature_word() {
    assert_eq!(cpu_suspend_format(psci_version(0, 1), 0), CpuSuspendFormat::Unsupported);
    assert_eq!(cpu_suspend_format(psci_version(0, 2), 0), CpuSuspendFormat::Original);
    assert_eq!(cpu_suspend_format(psci_version(1, 0), -1), CpuSuspendFormat::Unsupported);
    assert_eq!(cpu_suspend_format(psci_version(1, 0), 0), CpuSuspendFormat::Original);
    assert_eq!(cpu_suspend_format(psci_version(1, 0), 2), CpuSuspendFormat::Extended);
    assert!(power_state_valid(0x0301_FFFF, CpuSuspendFormat::Original));
    assert!(!power_state_valid(0x0400_0000, CpuSuspendFormat::Original));
    assert!(power_state_loses_context(0x0001_0000, CpuSuspendFormat::Original));
    assert!(!power_state_loses_context(0, CpuSuspendFormat::Original));
    assert!(power_state_valid(0x4FFF_FFFF, CpuSuspendFormat::Extended));
    assert!(!power_state_valid(0x8000_0000, CpuSuspendFormat::Extended));
    assert!(power_state_loses_context(0x4000_0000, CpuSuspendFormat::Extended));
}
