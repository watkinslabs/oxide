// Linear-address-masking rules (`ARCH_GET_UNTAG_MASK`,
// `ARCH_ENABLE_TAGGED_ADDR`, `ARCH_GET_MAX_TAG_BITS`,
// `ARCH_FORCE_TAGGED_SVA`) — Linux `prctl_enable_tagged_addr`,
// `mm_reset_untag_mask` and the `ARCH_GET_MAX_TAG_BITS` arm of
// `do_arch_prctl_64`.
//
// These are answered rather than refused. A kernel that knows the codes but
// has no LAM reports "zero tag bits available" and fails the enable with
// ENODEV; a kernel that has never heard of them answers EINVAL. The two are
// distinguishable by userspace and mean different things — EINVAL invites a
// caller to retry on a different code number, a zero max-tag-bits does not.

use syscall::errno::Errno;

/// `LAM_U57_BITS` — the tag width LAM_U57 makes available (bits 62:57).
pub const LAM_U57_BITS: u64 = 6;

/// `mm_reset_untag_mask()`: `mm->context.untag_mask = -1UL`. Every process
/// starts with no masking, and a kernel that never enables LAM keeps it, so
/// `ARCH_GET_UNTAG_MASK` reports the all-ones identity mask — "untagging a
/// pointer changes nothing".
/// # C: O(1)
pub fn lam_untag_mask(lam_bits: u64) -> u64 {
    if lam_bits == 0 { return u64::MAX; }
    // Linux clears the tag bits directly below the top canonical bit.
    !(((1u64 << lam_bits) - 1) << (63 - lam_bits))
}

/// `ARCH_GET_MAX_TAG_BITS`: `LAM_U57_BITS` when
/// `cpu_feature_enabled(X86_FEATURE_LAM)`, else 0. The gate is the KERNEL's
/// feature enablement, not raw CPUID — a kernel that programs no LAM bits
/// into CR3 must report 0 even on hardware that has LAM, or a runtime will
/// hand tagged pointers to syscalls that reject them as non-canonical.
/// # C: O(1)
pub fn lam_max_tag_bits(lam_enabled: bool) -> u64 {
    if lam_enabled { LAM_U57_BITS } else { 0 }
}

/// `prctl_enable_tagged_addr(mm, nr_bits)`, single-threaded caller.
///
/// The capability test comes FIRST — before the `nr_bits` range test — so a
/// caller on a LAM-less CPU sees ENODEV regardless of what it asked for, and
/// cannot mistake a rejected width for an unsupported feature.
/// # C: O(1)
pub fn lam_enable_tagged_addr(lam_enabled: bool, nr_bits: u64) -> i64 {
    if !lam_enabled { return -(Errno::Enodev.as_i32() as i64); }
    if nr_bits == 0 || nr_bits > LAM_U57_BITS { return -(Errno::Einval.as_i32() as i64); }
    0
}
