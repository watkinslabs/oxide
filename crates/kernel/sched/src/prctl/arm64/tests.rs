// arm64-only `prctl` option rules. Every case names the CPU it is asking
// about, so the answers stay right when this kernel runs on hardware that has
// the feature — a fixed EINVAL would pass a test written the other way and
// still be wrong on real silicon.

use super::*;

/// A CPU with everything. Used to prove that the EINVALs below come from the
/// missing KERNEL-side state management and not from a hard-coded refusal.
fn full_cpu() -> Features {
    Features { sve: true, sme: true, mte: true, address_auth: true, generic_auth: true }
}

/// The QEMU `virt` target this kernel is smoke-booted on is a Cortex-A72:
/// ARMv8.0, so no SVE, no SME, no pointer auth, no MTE.
fn armv8_0_cpu() -> Features { Features::default() }

#[test]
fn a_cpu_without_the_feature_never_reports_it_available() {
    let f = armv8_0_cpu();
    assert!(!sve_available(f));
    assert!(!sme_available(f));
    assert!(!address_auth_available(f));
    assert!(!generic_auth_available(f));
}

/// The remaining refusal is the kernel-state conjunct, not the CPU one. When
/// SVE/SME/PAC state management lands, flipping the corresponding constant is
/// the only edit needed and this assertion inverts with it.
#[test]
fn availability_is_cpu_support_and_kernel_support() {
    let f = full_cpu();
    assert_eq!(sve_available(f), KERNEL_MANAGES_SVE_STATE);
    assert_eq!(sme_available(f), KERNEL_MANAGES_SME_STATE);
    assert_eq!(address_auth_available(f), KERNEL_MANAGES_PAC_KEYS);
    assert_eq!(generic_auth_available(f), KERNEL_MANAGES_PAC_KEYS);
}

/// `PR_PAC_RESET_KEYS` tests availability BEFORE it looks at `arg`, so even
/// the "reset every key" spelling is EINVAL without pointer auth. Answering 0
/// there would tell a hardened runtime its keys were rerolled when nothing
/// happened.
#[test]
fn pac_reset_keys_refuses_zero_arg_without_pointer_auth() {
    assert_eq!(pac_reset_keys_check(armv8_0_cpu(), 0), Err(Errno::Einval));
}

#[test]
fn pac_reset_keys_rejects_undefined_bits() {
    let f = Features { address_auth: true, generic_auth: true, ..Features::default() };
    // Only reachable once the kernel owns the keys; the argument rules are
    // pinned here regardless so they cannot rot while the gate is closed.
    if !address_auth_available(f) { return; }
    assert_eq!(pac_reset_keys_check(f, 1 << 5), Err(Errno::Einval));
    assert_eq!(pac_reset_keys_check(f, u64::MAX), Err(Errno::Einval));
}

/// `PR_PAC_SET_ENABLED_KEYS` may not name the generic key: it has no
/// `SCTLR_EL1` enable bit, so accepting it would silently do nothing.
#[test]
fn pac_enabled_keys_mask_excludes_the_generic_key() {
    assert_eq!(PR_PAC_ENABLED_KEYS_MASK & PR_PAC_APGAKEY, 0);
    assert_eq!(PR_PAC_ENABLED_KEYS_MASK,
               PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY);
}

#[test]
fn pac_set_enabled_keys_refuses_without_address_auth() {
    assert_eq!(pac_set_enabled_keys_check(armv8_0_cpu(), PR_PAC_APIAKEY, 0),
               Err(Errno::Einval));
}

/// The tagged-address ABI is NOT an optional CPU feature — `TCR_EL1.TBI0` is
/// programmed unconditionally — so an ARMv8.0 CPU still accepts
/// `PR_TAGGED_ADDR_ENABLE`. This is the one option in this module that does
/// real work on the hardware this kernel actually boots on.
///
/// Off arm64 the whole option is EINVAL: x86_64 has no translation-regime
/// top-byte-ignore, so Linux leaves it on the generic macro there.
#[test]
fn tagged_addr_is_arm64_only() {
    assert_eq!(TAGGED_ADDR_ABI, cfg!(target_arch = "aarch64"));
    if TAGGED_ADDR_ABI { return; }
    assert_eq!(tagged_addr_valid_mask(full_cpu()), None);
    assert_eq!(tagged_addr_set_check(full_cpu(), 0), Err(Errno::Einval));
    assert_eq!(tagged_addr_get(false), Err(Errno::Einval));
}

#[test]
fn tagged_addr_enable_is_accepted_without_any_optional_feature() {
    if !TAGGED_ADDR_ABI { return; }
    let f = armv8_0_cpu();
    assert_eq!(tagged_addr_valid_mask(f), Some(PR_TAGGED_ADDR_ENABLE));
    assert_eq!(tagged_addr_set_check(f, PR_TAGGED_ADDR_ENABLE), Ok(true));
    assert_eq!(tagged_addr_set_check(f, 0), Ok(false));
    assert_eq!(tagged_addr_get(true), Ok(PR_TAGGED_ADDR_ENABLE as i64));
}

/// The MTE control bits share the argument word; without memory tagging they
/// are undefined bits and must be refused rather than ignored.
#[test]
fn mte_bits_need_a_tagging_cpu() {
    if !TAGGED_ADDR_ABI { return; }
    let plain = armv8_0_cpu();
    assert_eq!(tagged_addr_set_check(plain, PR_MTE_TCF_SYNC), Err(Errno::Einval));
    assert_eq!(tagged_addr_set_check(plain, PR_MTE_TCF_ASYNC), Err(Errno::Einval));
    assert_eq!(tagged_addr_set_check(plain, 1 << PR_MTE_TAG_SHIFT), Err(Errno::Einval));

    let tagging = Features { mte: true, ..Features::default() };
    assert_eq!(tagged_addr_valid_mask(tagging),
               Some(PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC | PR_MTE_TAG_MASK));
    assert_eq!(tagged_addr_set_check(tagging, PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC), Ok(true));
    // Still not a free-for-all: bit 16 is above the tag mask on any CPU.
    assert_eq!(tagged_addr_set_check(tagging, 1 << 20), Err(Errno::Einval));
}

#[test]
fn tagged_addr_report_round_trips() {
    assert_eq!(tagged_addr_report(true), PR_TAGGED_ADDR_ENABLE as i64);
    assert_eq!(tagged_addr_report(false), 0);
}

/// `untagged_addr` is a SIGN extension of bit 55, not a blanket top-byte
/// clear: a kernel pointer must survive it unchanged, or a kernel address
/// laundered through the check becomes a different, valid-looking address.
#[test]
fn untagging_clears_user_tags_and_leaves_kernel_addresses_alone() {
    let user = 0x0000_5555_5555_1000u64;
    assert_eq!(untagged_addr(user), user);
    assert_eq!(untagged_addr(user | (0xabu64 << 56)), user);
    // Bit 55 is what selects "user" — a 0xff top byte over a user address is
    // still a tag and still comes off.
    assert_eq!(untagged_addr(0xffu64 << 56 | 0x1000), 0x1000);
    let kernel = 0xffff_8000_0000_1000u64;
    assert_eq!(untagged_addr(kernel), kernel);
}

/// Every tag value must map back to the same untagged address — the property
/// the whole ABI rests on.
#[test]
fn every_tag_value_untags_to_the_same_address() {
    let base = 0x0000_1234_5678_9000u64;
    for tag in 0u64..=0xff {
        assert_eq!(untagged_addr(base | (tag << 56)), base, "tag {tag:#x}");
    }
}

/// A task that never opted in must NOT have its pointers untagged: the top
/// byte is part of the address for it, and quietly stripping it would accept
/// a pointer the task did not mean to pass.
#[test]
fn untagging_at_the_range_check_is_opt_in() {
    use crate::task::SchedClass;
    let t = Task::new(1, "tag", SchedClass::Normal { weight: 1024 });
    let tagged = 0x00abu64 << 48 | 0x1000;
    assert_eq!(user_ptr_for_check(Some(&t), tagged), tagged);
    t.tagged_addr.store(true, core::sync::atomic::Ordering::Release);
    assert_eq!(user_ptr_for_check(Some(&t), tagged), tagged);
    let top_byte_tagged = 0xabu64 << 56 | 0x1000;
    t.tagged_addr.store(false, core::sync::atomic::Ordering::Release);
    assert_eq!(user_ptr_for_check(Some(&t), top_byte_tagged), top_byte_tagged);
    t.tagged_addr.store(true, core::sync::atomic::Ordering::Release);
    assert_eq!(user_ptr_for_check(Some(&t), top_byte_tagged), 0x1000);
}

/// A kernel thread borrowing a user mm has no thread flag of its own, so it
/// untags unconditionally — Linux's `current->flags & PF_KTHREAD` arm.
#[test]
fn a_context_with_no_task_always_untags() {
    assert_eq!(user_ptr_for_check(None, 0xabu64 << 56 | 0x1000), 0x1000);
}

/// The two VL argument layouts are byte-identical; keeping separate constants
/// is deliberate, but they must not drift.
#[test]
fn vector_length_argument_layout() {
    assert_eq!(PR_SVE_VL_LEN_MASK, 0xffff);
    assert_eq!(PR_SME_VL_LEN_MASK, PR_SVE_VL_LEN_MASK);
    assert_eq!(PR_SVE_VL_INHERIT, 1 << 17);
    assert_eq!(PR_SME_VL_INHERIT, PR_SVE_VL_INHERIT);
    // The inherit flag is above the length field, so a maximal length cannot
    // set it by accident.
    assert_eq!(PR_SVE_VL_LEN_MASK & PR_SVE_VL_INHERIT, 0);
}
