// Linux `mm_struct::saved_auxv` — the fixed-size copy of the auxiliary vector
// the ELF loader wrote onto the new process' stack. Two readers depend on it:
// `prctl(PR_GET_AUXV)` and `/proc/<pid>/auxv`.
//
// It lives with the mm rather than with either reader because it is mm state:
// `PR_SET_MM_AUXV` overwrites the same array, and a second copy anywhere else
// would be a split source of truth for what this process' auxv is.

use alloc::vec::Vec;

/// Bytes in `saved_auxv`: `AT_VECTOR_SIZE * sizeof(long)` with
/// `AT_VECTOR_SIZE = 2 * (AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1)`.
/// The base term is 24 everywhere; the arch term is 3 on x86_64 and 2 on
/// arm64, so the array is genuinely a different size per architecture and
/// `PR_GET_AUXV`'s return value differs with it.
#[cfg(target_arch = "aarch64")]
pub const SAVED_AUXV_BYTES: usize = 2 * (2 + 24 + 1) * 8;
#[cfg(not(target_arch = "aarch64"))]
pub const SAVED_AUXV_BYTES: usize = 2 * (3 + 24 + 1) * 8;

/// Pack `(type, value)` pairs into the fixed-size array, zero-filling the
/// remainder. The trailing zeros ARE the `AT_NULL` terminator both readers
/// stop at, so the last pair slot is always left clear even when the caller
/// supplies more entries than fit.
/// # C: O(SAVED_AUXV_BYTES)
pub fn saved_auxv_blob(entries: &[(u64, u64)]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; SAVED_AUXV_BYTES];
    let mut off = 0usize;
    for &(k, v) in entries {
        if off + 32 > SAVED_AUXV_BYTES { break; }
        out[off..off + 8].copy_from_slice(&k.to_ne_bytes());
        out[off + 8..off + 16].copy_from_slice(&v.to_ne_bytes());
        off += 16;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_is_fixed_size_forward_ordered_and_at_null_terminated() {
        let blob = saved_auxv_blob(&[(3, 0x400040), (5, 13), (6, 4096)]);
        assert_eq!(blob.len(), SAVED_AUXV_BYTES);
        assert_eq!(u64::from_ne_bytes(blob[0..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_ne_bytes(blob[8..16].try_into().unwrap()), 0x400040);
        assert_eq!(u64::from_ne_bytes(blob[32..40].try_into().unwrap()), 6);
        assert!(blob[48..].iter().all(|b| *b == 0), "AT_NULL then zero fill");
    }

    #[test]
    fn an_oversized_vector_is_truncated_with_the_terminator_intact() {
        let many: Vec<(u64, u64)> = (0..1024u64).map(|i| (i + 1, i)).collect();
        let blob = saved_auxv_blob(&many);
        assert_eq!(blob.len(), SAVED_AUXV_BYTES);
        assert!(blob[SAVED_AUXV_BYTES - 16..].iter().all(|b| *b == 0));
    }
}
