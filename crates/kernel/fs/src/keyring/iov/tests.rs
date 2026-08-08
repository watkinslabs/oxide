// The EFAULT contract of `KEYCTL_INSTANTIATE_IOV`'s gather, driven through a
// fake user memory that records what was validated and what was copied.
//
// The whole point is the ORDER: the previous keyring suite had no EFAULT
// assertion anywhere, because every test called an op core with kernel-owned
// data, and a gather that copied each segment as it validated it would have
// passed all of them while leaving a half-built payload behind a fault.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::*;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// A fake address space: a set of readable ranges, each filled with one byte
/// value, plus a tally of the copies performed.
struct Fake {
    /// `(base, len, fill)` — every range the fake will admit.
    ok: Vec<(u64, u64, u8)>,
    /// Bytes handed out, so "nothing was copied" is an assertion rather than
    /// an inference from the returned error.
    copied: usize,
    /// The iovec array's raw words, indexed from `array_base`.
    array_base: u64,
    words: Vec<u64>,
}

impl Fake {
    fn new(array_base: u64, segs: &[(u64, u64)], ok: &[(u64, u64, u8)]) -> Self {
        let mut words = Vec::new();
        for &(b, l) in segs { words.push(b); words.push(l); }
        Self { ok: ok.to_vec(), copied: 0, array_base, words }
    }
    fn admits(&self, base: u64, len: u64) -> bool {
        self.ok.iter().any(|&(b, l, _)| base >= b && base.saturating_add(len) <= b + l)
    }
    fn fill_of(&self, base: u64) -> u8 {
        self.ok.iter().find(|&&(b, l, _)| base >= b && base < b + l).map(|&(_, _, f)| f).unwrap_or(0)
    }
}

impl UserMem for Fake {
    fn validate(&mut self, base: u64, len: u64, _align: u64) -> Result<(), i64> {
        if self.admits(base, len) { Ok(()) } else { Err(efault()) }
    }
    fn read_word(&mut self, at: u64) -> Result<u64, i64> {
        let i = ((at - self.array_base) / 8) as usize;
        Ok(self.words.get(i).copied().unwrap_or(0))
    }
    fn copy_in(&mut self, base: u64, len: u64, out: &mut Vec<u8>) -> Result<(), i64> {
        self.copied += len as usize;
        let f = self.fill_of(base);
        for _ in 0..len { out.push(f); }
        Ok(())
    }
}

/// The array holding the segment descriptors is itself user memory, so an
/// unreadable array is EFAULT before a single descriptor is interpreted.
#[test]
fn unreadable_iovec_array_is_efault() {
    let mut m = Fake::new(0x1000, &[(0x9000, 4)], &[]);
    assert_eq!(gather(&mut m, 0x1000, 1), Err(efault()));
    assert_eq!(m.copied, 0);
}

/// THE invariant. Three segments, the LAST unreadable: the whole call is
/// EFAULT and not one byte of the first two has been copied.
#[test]
fn a_bad_last_segment_copies_nothing_at_all() {
    let segs = [(0x9000u64, 4u64), (0xA000, 4), (0xDEAD_0000, 4)];
    let mut m = Fake::new(0x1000, &segs,
        &[(0x1000, 6 * 8, 0), (0x9000, 4, 0xAA), (0xA000, 4, 0xBB)]);
    assert_eq!(gather(&mut m, 0x1000, 3), Err(efault()));
    assert_eq!(m.copied, 0, "no segment may be copied until every segment has been validated");
}

/// The same vector with every segment readable gathers all of them, in order.
#[test]
fn a_whole_valid_vector_gathers_in_order() {
    let segs = [(0x9000u64, 2u64), (0xA000, 3)];
    let mut m = Fake::new(0x1000, &segs,
        &[(0x1000, 4 * 8, 0), (0x9000, 2, 0xAA), (0xA000, 3, 0xBB)]);
    assert_eq!(gather(&mut m, 0x1000, 2), Ok(alloc::vec![0xAA, 0xAA, 0xBB, 0xBB, 0xBB]));
    assert_eq!(m.copied, 5);
}

/// A zero-length segment is legal with any base, NULL included, and is dropped
/// rather than validated — faulting on it would reject a legal vector.
#[test]
fn a_zero_length_segment_is_not_a_fault() {
    let segs = [(0u64, 0u64), (0x9000, 2)];
    let mut m = Fake::new(0x1000, &segs, &[(0x1000, 4 * 8, 0), (0x9000, 2, 0x11)]);
    assert_eq!(gather(&mut m, 0x1000, 2), Ok(alloc::vec![0x11, 0x11]));
}

/// The combined length is bounded by the same ceiling the scalar command
/// applies, and it is EINVAL — a vectored call is not a way past it. Rejected
/// before the oversized segment's pointer is looked at, so an oversized AND
/// unreadable vector reports the length, not the fault.
#[test]
fn the_combined_length_ceiling_is_einval_before_any_pointer_test() {
    let segs = [(0xDEAD_0000u64, KEY_MAX_PAYLOAD + 1)];
    let mut m = Fake::new(0x1000, &segs, &[(0x1000, 2 * 8, 0)]);
    assert_eq!(gather(&mut m, 0x1000, 1), Err(einval()));
    assert_eq!(m.copied, 0);
}

/// A segment count whose descriptor array does not fit in an address is EFAULT,
/// not a wrapped-around range that would validate against nothing.
#[test]
fn an_overflowing_segment_count_is_efault() {
    let mut m = Fake::new(0x1000, &[], &[(0x1000, 8, 0)]);
    assert_eq!(gather(&mut m, 0x1000, u64::MAX / 4), Err(efault()));
}

/// No segments is an empty payload, which is how a type with no payload is
/// instantiated through the vectored command.
#[test]
fn zero_segments_is_an_empty_payload() {
    let mut m = Fake::new(0x1000, &[], &[]);
    assert_eq!(gather(&mut m, 0x1000, 0), Ok(Vec::new()));
}
