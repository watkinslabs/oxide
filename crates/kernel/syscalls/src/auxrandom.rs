// AT_RANDOM auxiliary-vector entropy, per Linux `fs/binfmt_elf.c`
// `create_elf_tables()`:
//
//     unsigned char k_rand_bytes[16];                      /* :179 */
//     get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes)); /* :226 */
//
// Drawn from the CSPRNG, per exec — not per boot, not per task. glibc reads
// these 16 bytes to derive `__stack_chk_guard` (the stack canary) and the
// `PTR_MANGLE`/`PTR_DEMANGLE` pointer guard, so any predictability here
// defeats both mitigations outright.
//
// Not kernel-cfg'd: the `059_execve` slot files are
// `#![cfg(target_os = "oxide-kernel")]` and cannot be exercised by the hosted
// suite, which would leave this property untested. Both arches call
// `at_random_bytes` so the entropy source cannot drift between them.

/// Size of the AT_RANDOM block (Linux `k_rand_bytes[16]`).
pub const AT_RANDOM_BYTES: usize = 16;

/// Fresh CSPRNG bytes for one exec's AT_RANDOM. # C: O(1)
pub fn at_random_bytes() -> [u8; AT_RANDOM_BYTES] {
    let mut r = [0u8; AT_RANDOM_BYTES];
    crng::fill(&mut r);
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Number of samples each structural check draws.
    const SAMPLES: usize = 64;

    /// The pre-F768 generator, kept only to prove the checks below have teeth.
    /// All 16 bytes came from one `monotonic_ns()` reading, so bytes 8..15 were
    /// a re-derivation of the same 64-bit word.
    fn clock_derived(ns: u64) -> [u8; AT_RANDOM_BYTES] {
        let mut r = [0u8; AT_RANDOM_BYTES];
        // `wrapping_mul` reproduces the released kernel's overflow-unchecked `*`.
        for i in 0..AT_RANDOM_BYTES { r[i] = (ns >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(0x9b); }
        r
    }

    /// True when the upper half is a fixed byte-wise transform of the lower
    /// half — i.e. the block carries only 64 bits of variation. `r[i] ^ r[i+8]`
    /// is then the same mask in every sample regardless of the input.
    fn upper_half_derivable(s: &[[u8; AT_RANDOM_BYTES]]) -> bool {
        let first: Vec<u8> = (0..8).map(|i| s[0][i] ^ s[0][i + 8]).collect();
        s.iter().all(|r| (0..8).all(|i| r[i] ^ r[i + 8] == first[i]))
    }

    #[test]
    fn checks_reject_the_clock_derived_generator() {
        // Distinct "boot times": the old formula's only input.
        let s: Vec<_> = (0..SAMPLES).map(|k| clock_derived(0x1234_5678_9abc_def0 + k as u64 * 997)).collect();
        assert!(upper_half_derivable(&s), "detector must fire on the historical clock formula");
    }

    #[test]
    fn upper_half_is_not_derivable_from_lower_half() {
        let s: Vec<_> = (0..SAMPLES).map(|_| at_random_bytes()).collect();
        assert!(!upper_half_derivable(&s), "bytes 8..15 must not be a fixed transform of bytes 0..7");
    }

    #[test]
    fn each_exec_gets_distinct_bytes() {
        let s: Vec<_> = (0..SAMPLES).map(|_| at_random_bytes()).collect();
        for i in 0..s.len() {
            for j in (i + 1)..s.len() { assert_ne!(s[i], s[j], "two execs must not share AT_RANDOM"); }
        }
    }

    #[test]
    fn block_is_never_trivially_constant() {
        for r in (0..SAMPLES).map(|_| at_random_bytes()) {
            assert!(r.iter().any(|&b| b != 0), "AT_RANDOM must not be all zero");
            assert!(r.iter().any(|&b| b != r[0]), "AT_RANDOM must not be a repeated byte");
        }
    }
}
