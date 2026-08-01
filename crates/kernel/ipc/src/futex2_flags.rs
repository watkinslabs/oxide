// futex2 (`futex_wait`/`futex_wake`/`futex_waitv`/`futex_requeue`) flag and
// operand validation. Non-gated so the accept/reject ladder is hosted-tested;
// the syscall shims are `#[cfg(target_os = "oxide-kernel")]` and compile their
// own test modules away.
//
// The rules mirror `futex2_to_flags` + `futex_flags_valid` +
// `futex_validate_input`: a futex2 caller passes a size class, an optional
// private bit, and optional NUMA/MPOL bits, and the kernel rejects every
// combination it cannot serve — it never silently downgrades one.

/// `FUTEX2_SIZE_U8` — 1-byte futex.
pub const FUTEX2_SIZE_U8: u32 = 0x00;
/// `FUTEX2_SIZE_U16` — 2-byte futex.
pub const FUTEX2_SIZE_U16: u32 = 0x01;
/// `FUTEX2_SIZE_U32` — the only size any futex implementation serves today.
pub const FUTEX2_SIZE_U32: u32 = 0x02;
/// `FUTEX2_SIZE_U64` — 8-byte futex.
pub const FUTEX2_SIZE_U64: u32 = 0x03;
/// Size class occupies bits [1:0].
pub const FUTEX2_SIZE_MASK: u32 = 0x03;
/// `FUTEX2_NUMA` — the futex word is followed by a node-id word.
pub const FUTEX2_NUMA: u32 = 0x04;
/// `FUTEX2_MPOL` — key the futex by the caller's memory policy.
pub const FUTEX2_MPOL: u32 = 0x08;
/// `FUTEX2_PRIVATE` — numerically identical to `FUTEX_PRIVATE_FLAG`.
pub const FUTEX2_PRIVATE: u32 = 0x80;
/// Every bit a futex2 caller may set. Anything outside is `EINVAL`.
pub const FUTEX2_VALID_MASK: u32 =
    FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE;

/// Why a futex2 flag word was rejected. Every variant maps to `EINVAL` at the
/// ABI boundary; the split exists so tests name the rule that fired.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Futex2Reject {
    /// A bit outside `FUTEX2_VALID_MASK` was set.
    UnknownBit,
    /// A size class other than 32-bit. Only 32-bit futexes are implemented.
    UnsupportedSize,
    /// NUMA-keyed futexes need a per-node key derivation and a second futex
    /// word; no NUMA topology exists here, so the request cannot be served.
    Numa,
    /// Memory-policy-keyed futexes need an mbind policy attached to the key.
    Mpol,
}

/// Decoded, accepted futex2 flags.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Futex2Flags {
    /// Futex word width in bytes (`1 << (flags & FUTEX2_SIZE_MASK)`).
    pub size_bytes: u32,
    /// `FUTEX2_PRIVATE`: key on `(mm, addr)` rather than the shared mapping.
    pub private: bool,
}

/// Validate a futex2 `flags` word.
/// # C: O(1)
pub const fn validate_futex2_flags(flags: u32) -> Result<Futex2Flags, Futex2Reject> {
    if flags & !FUTEX2_VALID_MASK != 0 { return Err(Futex2Reject::UnknownBit); }
    if flags & FUTEX2_NUMA != 0 { return Err(Futex2Reject::Numa); }
    if flags & FUTEX2_MPOL != 0 { return Err(Futex2Reject::Mpol); }
    if flags & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32 { return Err(Futex2Reject::UnsupportedSize); }
    Ok(Futex2Flags { size_bytes: 1 << (flags & FUTEX2_SIZE_MASK), private: flags & FUTEX2_PRIVATE != 0 })
}

/// `futex_validate_input`: a value or mask passed as `unsigned long` must fit
/// the futex word width. A 32-bit futex handed `val = 1 << 40` is `EINVAL`,
/// never a silent truncation to `0` — truncating would make a caller's
/// mismatched compare-value look like a match and park it forever.
/// # C: O(1)
pub const fn validate_futex2_input(size_bytes: u32, val: u64) -> bool {
    let bits = 8 * size_bytes;
    if bits >= 64 { return true; }
    (val >> bits) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_32_bit_size_class_is_served() {
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32),
                   Ok(Futex2Flags { size_bytes: 4, private: false }));
        for sz in [FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U64] {
            assert_eq!(validate_futex2_flags(sz), Err(Futex2Reject::UnsupportedSize));
        }
    }

    #[test]
    fn private_bit_is_decoded_not_rejected() {
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_PRIVATE),
                   Ok(Futex2Flags { size_bytes: 4, private: true }));
    }

    #[test]
    fn bits_outside_the_valid_mask_are_rejected() {
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x10), Err(Futex2Reject::UnknownBit));
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x8000_0000), Err(Futex2Reject::UnknownBit));
    }

    #[test]
    fn numa_and_mpol_are_rejected_not_ignored() {
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_NUMA), Err(Futex2Reject::Numa));
        assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_MPOL), Err(Futex2Reject::Mpol));
    }

    #[test]
    fn a_value_wider_than_the_futex_word_is_rejected_not_truncated() {
        assert!(validate_futex2_input(4, 0xffff_ffff));
        assert!(!validate_futex2_input(4, 0x1_0000_0000),
                "a 33-bit val on a 32-bit futex must be EINVAL, not a silent truncation to 0");
        assert!(!validate_futex2_input(4, 1u64 << 40));
        assert!(validate_futex2_input(8, u64::MAX));
    }
}
