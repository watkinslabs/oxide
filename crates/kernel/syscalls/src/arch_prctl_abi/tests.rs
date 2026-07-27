// Hosted coverage for the `arch_prctl(2)` decision core. These run under
// `cargo test` on the HOST target — the slot file that consumes them is
// `#[cfg(target_os = "oxide-kernel")]` and therefore untestable.

use super::*;

#[test]
fn set_fs_accepts_a_normal_tls_base() {
    // What every glibc thread does: `arch_prctl(ARCH_SET_FS, &pthread)`.
    assert_eq!(classify(nrs::ARCH_SET_FS, 0x7f00_1234_5000), Ok(ArchOp::SetFs(0x7f00_1234_5000)));
}

#[test]
fn set_fs_rejects_non_canonical_with_eperm_not_efault() {
    // Linux `do_arch_prctl_64`: `if (unlikely(arg2 >= TASK_SIZE_MAX)) return -EPERM;`
    for bad in [TASK_SIZE_MAX, TASK_SIZE_MAX + 1, hal::USER_VA_END,
                0xffff_ffff_8000_0000, u64::MAX] {
        assert_eq!(classify(nrs::ARCH_SET_FS, bad), Err(Errno::Eperm),
            "ARCH_SET_FS({bad:#x}) must be EPERM");
        assert_eq!(classify(nrs::ARCH_SET_GS, bad), Err(Errno::Eperm),
            "ARCH_SET_GS({bad:#x}) must be EPERM");
    }
}

#[test]
fn task_size_max_excludes_exactly_the_last_user_page() {
    assert_eq!(TASK_SIZE_MAX, hal::USER_VA_END - 4096);
    assert_eq!(classify(nrs::ARCH_SET_FS, TASK_SIZE_MAX - 1),
               Ok(ArchOp::SetFs(TASK_SIZE_MAX - 1)));
}

#[test]
fn set_fs_accepts_zero() {
    // Linux has no lower bound here; a zero FS base is legal and glibc's
    // static-binary bootstrap installs one transiently.
    assert_eq!(classify(nrs::ARCH_SET_FS, 0), Ok(ArchOp::SetFs(0)));
}

#[test]
fn get_codes_do_not_pre_validate_the_pointer() {
    // Linux runs a plain `put_user` for ARCH_GET_FS/ARCH_GET_GS, so a kernel
    // address is EFAULT from the copy, never EPERM from an address rule.
    assert_eq!(classify(nrs::ARCH_GET_FS, 0xffff_ffff_8000_0000),
               Ok(ArchOp::GetFs(0xffff_ffff_8000_0000)));
    assert_eq!(classify(nrs::ARCH_GET_GS, 0), Ok(ArchOp::GetGs(0)));
}

#[test]
fn cpuid_sub_codes_classify() {
    assert_eq!(classify(nrs::ARCH_GET_CPUID, 0), Ok(ArchOp::GetCpuid));
    assert_eq!(classify(nrs::ARCH_SET_CPUID, 0), Ok(ArchOp::SetCpuid(false)));
    assert_eq!(classify(nrs::ARCH_SET_CPUID, 1), Ok(ArchOp::SetCpuid(true)));
    // Linux passes `arg2` straight to `set_cpuid_mode(unsigned long)` and
    // tests it for truth, so any non-zero enables.
    assert_eq!(classify(nrs::ARCH_SET_CPUID, 0xdead), Ok(ArchOp::SetCpuid(true)));
}

#[test]
fn get_cpuid_reports_cpuid_enabled() {
    // `!test_thread_flag(TIF_NOCPUID)` — never armed on this port.
    assert_eq!(get_cpuid_mode(), 1);
}

#[test]
fn set_cpuid_is_enodev_without_the_cpu_feature() {
    assert_eq!(set_cpuid_mode(false), -(Errno::Enodev.as_i32() as i64));
    assert_eq!(set_cpuid_mode(true), 0);
}

#[test]
fn shstk_sub_codes_classify_and_refuse_like_the_unconfigured_stub() {
    for code in [nrs::ARCH_SHSTK_ENABLE, nrs::ARCH_SHSTK_DISABLE, nrs::ARCH_SHSTK_LOCK,
                 nrs::ARCH_SHSTK_UNLOCK, nrs::ARCH_SHSTK_STATUS] {
        assert_eq!(classify(code, 0), Ok(ArchOp::Shstk));
    }
    assert_eq!(shstk_prctl_unsupported(), -(Errno::Einval.as_i32() as i64));
}

#[test]
fn unknown_sub_code_is_einval() {
    for code in [0, 1, 0x1000, 0x1005, 0x1010, 0x1013, 0x5000, 0x5006, u64::MAX] {
        assert_eq!(classify(code, 0), Err(Errno::Einval), "code {code:#x}");
    }
}
