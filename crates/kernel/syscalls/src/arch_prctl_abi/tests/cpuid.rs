use crate::arch_prctl_abi::cpuid::*;
use syscall::errno::Errno;

#[test]
fn cpuid_fault_capability_comes_from_the_platform_info_bit() {
    // Linux derives `X86_FEATURE_CPUID_FAULT` on an Intel part from
    // `MSR_PLATFORM_INFO` bit 31 and nothing else.
    assert!(intel_platform_info_has_cpuid_fault(1u64 << 31));
    assert!(intel_platform_info_has_cpuid_fault(u64::MAX));
    assert!(!intel_platform_info_has_cpuid_fault(0));
    assert!(!intel_platform_info_has_cpuid_fault(!(1u64 << 31)));
    // A neighbouring bit must not be mistaken for it.
    assert!(!intel_platform_info_has_cpuid_fault(1u64 << 30));
    assert!(!intel_platform_info_has_cpuid_fault(1u64 << 32));
}

#[test]
fn get_cpuid_mode_reports_per_task_state_not_a_constant() {
    assert_eq!(get_cpuid_mode(false), 1, "cpuid executable -> 1");
    assert_eq!(get_cpuid_mode(true), 0, "cpuid faulting -> 0");
}

#[test]
fn set_cpuid_is_enodev_without_the_capability() {
    for enable in [false, true] {
        for cur in [false, true] {
            assert_eq!(set_cpuid_mode(CpuidFaultMsr::None, enable, cur), CpuidModeChange::Enodev);
        }
    }
    assert_eq!(enodev(), -(Errno::Enodev.as_i32() as i64));
}

#[test]
fn set_cpuid_arms_the_msr_only_when_the_flag_actually_flips() {
    // Linux `disable_cpuid()` writes the MSR only if
    // `test_and_set_thread_flag(TIF_NOCPUID)` returned 0.
    for msr in [CpuidFaultMsr::Intel, CpuidFaultMsr::Amd] {
        assert_eq!(set_cpuid_mode(msr, false, false), CpuidModeChange::Arm { nocpuid: true });
        assert_eq!(set_cpuid_mode(msr, false, true), CpuidModeChange::AlreadySet);
        assert_eq!(set_cpuid_mode(msr, true, true), CpuidModeChange::Arm { nocpuid: false });
        assert_eq!(set_cpuid_mode(msr, true, false), CpuidModeChange::AlreadySet);
    }
}

#[test]
fn set_then_get_cpuid_round_trips() {
    // The whole point of holding the mode per task: what SET stored is what
    // GET reports back. A hard-coded GET breaks exactly this.
    let mut nocpuid = false;
    assert_eq!(get_cpuid_mode(nocpuid), 1);
    match set_cpuid_mode(CpuidFaultMsr::Intel, false, nocpuid) {
        CpuidModeChange::Arm { nocpuid: n } => nocpuid = n,
        other => panic!("expected Arm, got {other:?}"),
    }
    assert_eq!(get_cpuid_mode(nocpuid), 0, "after ARCH_SET_CPUID(0)");
    match set_cpuid_mode(CpuidFaultMsr::Intel, true, nocpuid) {
        CpuidModeChange::Arm { nocpuid: n } => nocpuid = n,
        other => panic!("expected Arm, got {other:?}"),
    }
    assert_eq!(get_cpuid_mode(nocpuid), 1, "after ARCH_SET_CPUID(1)");
}

#[test]
fn intel_arming_touches_only_the_cpuid_fault_bit() {
    // `set_cpuid_faulting` read-modify-writes MSR_MISC_FEATURES_ENABLES; the
    // neighbouring RING3MWAIT bit must survive both directions.
    let ring3mwait = 1u64 << 1;
    assert_eq!(intel_misc_features_with_fault(ring3mwait, true), ring3mwait | 1);
    assert_eq!(intel_misc_features_with_fault(ring3mwait | 1, false), ring3mwait);
    assert_eq!(intel_misc_features_with_fault(0, true), 1);
    assert_eq!(intel_misc_features_with_fault(1, false), 0);
}

#[test]
fn amd_arming_uses_hwcr_bit_35() {
    let other = 1u64 << 18;
    assert_eq!(amd_hwcr_with_fault(other, true), other | (1 << 35));
    assert_eq!(amd_hwcr_with_fault(other | (1 << 35), false), other);
    assert_eq!(MSR_K7_HWCR_CPUID_USER_DIS_BIT, 35);
}

#[test]
fn the_msr_numbers_are_the_architectural_ones() {
    assert_eq!(MSR_PLATFORM_INFO, 0xCE);
    assert_eq!(MSR_MISC_FEATURES_ENABLES, 0x140);
    assert_eq!(MSR_K7_HWCR, 0xC001_0015);
    assert_eq!(MSR_PLATFORM_INFO_CPUID_FAULT_BIT, 31);
    assert_eq!(MSR_MISC_FEATURES_ENABLES_CPUID_FAULT_BIT, 0);
}

#[test]
fn exec_re_enables_cpuid() {
    // Linux `arch_setup_new_exec()` clears TIF_NOCPUID unconditionally, so a
    // setuid helper cannot inherit a faulting `cpuid` from its caller.
    assert!(!nocpuid_after_exec());
    assert_eq!(get_cpuid_mode(nocpuid_after_exec()), 1);
}

#[test]
fn cpuid_fault_msr_supported_predicate() {
    assert!(!CpuidFaultMsr::None.supported());
    assert!(CpuidFaultMsr::Intel.supported());
    assert!(CpuidFaultMsr::Amd.supported());
}
