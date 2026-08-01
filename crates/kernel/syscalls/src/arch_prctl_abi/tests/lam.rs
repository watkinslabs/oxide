use crate::arch_prctl_abi::lam::*;
use syscall::errno::Errno;

#[test]
fn untag_mask_defaults_to_the_identity() {
    // `mm_reset_untag_mask()` sets -1UL, and a kernel that never enables LAM
    // keeps it — so untagging a pointer is a no-op, which is the truth.
    assert_eq!(lam_untag_mask(0), u64::MAX);
}

#[test]
fn untag_mask_for_lam_u57_clears_bits_57_through_62() {
    let m = lam_untag_mask(LAM_U57_BITS);
    for bit in 57..=62 {
        assert_eq!(m & (1u64 << bit), 0, "bit {bit} must be masked out");
    }
    assert_ne!(m & (1u64 << 63), 0, "the sign bit is not a tag bit");
    assert_ne!(m & (1u64 << 56), 0, "bit 56 stays inside the address");
}

#[test]
fn max_tag_bits_is_zero_without_kernel_lam_support() {
    // Answering 0 is materially different from EINVAL: it tells a runtime
    // "this kernel understands tagged addressing and offers none", so it
    // stops probing instead of retrying the code elsewhere.
    assert_eq!(lam_max_tag_bits(false), 0);
    assert_eq!(lam_max_tag_bits(true), LAM_U57_BITS);
    assert_eq!(LAM_U57_BITS, 6);
}

#[test]
fn enable_tagged_addr_is_enodev_before_any_range_check() {
    // The capability test precedes the `nr_bits` test, so an out-of-range
    // width on a LAM-less CPU still reports ENODEV — a caller must not be
    // able to infer "the feature exists, my width was wrong".
    let enodev = -(Errno::Enodev.as_i32() as i64);
    for bits in [0u64, 1, LAM_U57_BITS, LAM_U57_BITS + 1, u64::MAX] {
        assert_eq!(lam_enable_tagged_addr(false, bits), enodev, "nr_bits {bits}");
    }
}

#[test]
fn enable_tagged_addr_range_rules_on_a_capable_kernel() {
    let einval = -(Errno::Einval.as_i32() as i64);
    assert_eq!(lam_enable_tagged_addr(true, 0), einval, "zero bits is not a request");
    assert_eq!(lam_enable_tagged_addr(true, LAM_U57_BITS + 1), einval);
    assert_eq!(lam_enable_tagged_addr(true, u64::MAX), einval);
    for bits in 1..=LAM_U57_BITS {
        assert_eq!(lam_enable_tagged_addr(true, bits), 0, "nr_bits {bits}");
    }
}

#[test]
fn a_kernel_that_reports_zero_tag_bits_never_reports_a_masking_untag_mask() {
    // The two GET codes must agree: if MAX_TAG_BITS is 0 then UNTAG_MASK
    // must be the identity, or userspace would strip bits off a pointer the
    // kernel never told it were tags.
    let bits = lam_max_tag_bits(false);
    assert_eq!(bits, 0);
    assert_eq!(lam_untag_mask(bits), u64::MAX);
}
