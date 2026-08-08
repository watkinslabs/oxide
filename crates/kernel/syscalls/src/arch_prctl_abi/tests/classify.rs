use crate::arch_prctl_abi::*;
use syscall::errno::Errno;
use syscall::nrs;

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
fn every_get_code_leaves_its_pointer_unvalidated() {
    // Linux applies the TASK_SIZE_MAX rule to the two SET-base codes ONLY.
    // Every other sub-code's `arg2` is a pointer or an index, so an
    // above-TASK_SIZE_MAX value must reach the copy (EFAULT) or the range
    // check — never come back as EPERM.
    let high = TASK_SIZE_MAX + 1;
    for code in [nrs::ARCH_GET_FS, nrs::ARCH_GET_GS,
                 nrs::ARCH_GET_XCOMP_SUPP, nrs::ARCH_GET_XCOMP_PERM,
                 nrs::ARCH_GET_XCOMP_GUEST_PERM, nrs::ARCH_REQ_XCOMP_PERM,
                 nrs::ARCH_REQ_XCOMP_GUEST_PERM, nrs::ARCH_SHSTK_STATUS,
                 nrs::ARCH_GET_UNTAG_MASK, nrs::ARCH_GET_MAX_TAG_BITS] {
        assert_ne!(classify(code, high), Err(Errno::Eperm), "code {code:#x}");
        assert!(classify(code, high).is_ok(), "code {code:#x} must classify");
    }
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
fn shstk_sub_codes_carry_their_option_and_feature_word() {
    for code in [nrs::ARCH_SHSTK_ENABLE, nrs::ARCH_SHSTK_DISABLE, nrs::ARCH_SHSTK_LOCK,
                 nrs::ARCH_SHSTK_UNLOCK, nrs::ARCH_SHSTK_STATUS] {
        assert_eq!(classify(code, nrs::ARCH_SHSTK_SHSTK),
                   Ok(ArchOp::Shstk { option: code, features: nrs::ARCH_SHSTK_SHSTK }));
    }
}

#[test]
fn xcomp_codes_split_host_from_guest() {
    assert_eq!(classify(nrs::ARCH_GET_XCOMP_SUPP, 0x1000), Ok(ArchOp::GetXcompSupp(0x1000)));
    assert_eq!(classify(nrs::ARCH_GET_XCOMP_PERM, 0x1000),
               Ok(ArchOp::GetXcompPerm { ptr: 0x1000, guest: false }));
    assert_eq!(classify(nrs::ARCH_GET_XCOMP_GUEST_PERM, 0x1000),
               Ok(ArchOp::GetXcompPerm { ptr: 0x1000, guest: true }));
    assert_eq!(classify(nrs::ARCH_REQ_XCOMP_PERM, 18),
               Ok(ArchOp::ReqXcompPerm { idx: 18, guest: false }));
    assert_eq!(classify(nrs::ARCH_REQ_XCOMP_GUEST_PERM, 18),
               Ok(ArchOp::ReqXcompPerm { idx: 18, guest: true }));
}

#[test]
fn address_masking_codes_classify_instead_of_falling_to_the_default_arm() {
    assert_eq!(classify(nrs::ARCH_GET_UNTAG_MASK, 0x2000), Ok(ArchOp::GetUntagMask(0x2000)));
    assert_eq!(classify(nrs::ARCH_ENABLE_TAGGED_ADDR, 6), Ok(ArchOp::EnableTaggedAddr(6)));
    assert_eq!(classify(nrs::ARCH_GET_MAX_TAG_BITS, 0x2000), Ok(ArchOp::GetMaxTagBits(0x2000)));
    assert_eq!(classify(nrs::ARCH_FORCE_TAGGED_SVA, 0), Ok(ArchOp::ForceTaggedSva));
}

#[test]
fn vdso_codes_are_classified_deliberately_not_by_accident() {
    // Named, so the EINVAL they get is the "no checkpoint/restore support"
    // answer rather than "this code number was never considered".
    for code in [nrs::ARCH_MAP_VDSO_X32, nrs::ARCH_MAP_VDSO_32, nrs::ARCH_MAP_VDSO_64] {
        assert_eq!(classify(code, 0), Ok(ArchOp::MapVdso(code)));
    }
    assert_eq!(map_vdso_unsupported(), -(Errno::Einval.as_i32() as i64));
}

#[test]
fn every_code_the_uapi_header_assigns_is_classified() {
    // The full arch-prctl UAPI code assignment list. A code
    // that reaches the `default:` arm here is one this port forgot.
    for code in [0x1001u64, 0x1002, 0x1003, 0x1004, 0x1011, 0x1012,
                 0x1021, 0x1022, 0x1023, 0x1024, 0x1025,
                 0x2001, 0x2002, 0x2003,
                 0x4001, 0x4002, 0x4003, 0x4004,
                 0x5001, 0x5002, 0x5003, 0x5004, 0x5005] {
        assert!(classify(code, 0).is_ok(), "uapi code {code:#x} fell to the default arm");
    }
}

#[test]
fn unknown_sub_code_is_einval() {
    // Including 0x3001..0x3004, which the header reserves permanently
    // ("Don't use ... because of old glibcs") and Linux never assigns.
    for code in [0, 1, 0x1000, 0x1005, 0x1010, 0x1013, 0x1026, 0x2000, 0x2004,
                 0x3001, 0x3002, 0x3003, 0x3004, 0x4000, 0x4005,
                 0x5000, 0x5006, u64::MAX] {
        assert_eq!(classify(code, 0), Err(Errno::Einval), "code {code:#x}");
    }
}

#[test]
fn every_accepted_gs_base_keeps_bit_63_clear() {
    // Cross-module invariant, and the reason ARCH_SET_GS can exist at all on
    // this port: the paranoid exception entry decides whether it must
    // `swapgs` by testing the sign of the live GS base. That test is only
    // sound while no value userspace can install has bit 63 set. The
    // TASK_SIZE_MAX rule is what guarantees it — so anything `classify`
    // accepts for ARCH_SET_GS must read as a USER base.
    for v in [0u64, 1, 4096, 0x7f00_1234_5000, TASK_SIZE_MAX - 1] {
        assert_eq!(classify(nrs::ARCH_SET_GS, v), Ok(ArchOp::SetGs(v)));
        assert!(!hal_x86_64::msr::gs_base_is_kernel(v),
            "ARCH_SET_GS({v:#x}) would forge a kernel-looking GS base");
    }
    // And every value that WOULD forge one is refused before the write.
    for v in [1u64 << 63, 0xffff_8000_0000_0000, 0xffff_ffff_8100_0000, u64::MAX] {
        assert!(hal_x86_64::msr::gs_base_is_kernel(v));
        assert_eq!(classify(nrs::ARCH_SET_GS, v), Err(Errno::Eperm));
    }
}
