// Hosted coverage for the CSPRNG. These cannot prove cryptographic strength —
// the ChaCha20 core carries that, pinned by the RFC 8439 vectors in
// `chacha/tests.rs`. What they DO pin is the property the previous LCG failed:
// output must not be a linear function of a small visible state, and the pool
// must never hand out the same bytes twice.

use super::*;

fn take(n: usize) -> alloc_vec::Vec<u8> {
    let mut v = alloc_vec::Vec::new();
    v.resize(n, 0u8);
    fill(&mut v);
    v
}

// The crate is no_std; hosted tests get a Vec through std.
mod alloc_vec { pub use std::vec::Vec; }

/// `BULK_SOURCE` and `SEEDED` are process-global, so every test that installs
/// a source or inspects readiness must run alone or it will observe another
/// test's source.
static SOURCE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the source lock, ignoring a poisoned mutex — a panicking sibling test
/// should fail on its own assertion, not cascade into every other test.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    SOURCE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn successive_fills_differ() {
    let a = take(64);
    let b = take(64);
    assert_ne!(a, b, "two fills produced identical bytes");
}

#[test]
fn output_is_not_a_repeating_block() {
    let v = take(4 * BLOCK_BYTES);
    for i in 1..4 {
        assert_ne!(&v[0..BLOCK_BYTES], &v[i * BLOCK_BYTES..(i + 1) * BLOCK_BYTES],
                   "block {i} repeats block 0 — the counter is not advancing");
    }
}

#[test]
fn short_and_unaligned_lengths_are_filled_completely() {
    for n in [1usize, 7, 8, 63, 64, 65, 129] {
        let v = take(n);
        assert_eq!(v.len(), n);
        // A run of `n` zeroes is astronomically unlikely; catching it catches
        // a fill that silently wrote nothing.
        assert!(v.iter().any(|&b| b != 0), "fill({n}) produced all zeroes");
    }
}

#[test]
fn zero_length_fill_is_a_no_op() {
    let mut empty: [u8; 0] = [];
    fill(&mut empty);
}

#[test]
fn next_u64_does_not_repeat_over_a_run() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..256 { assert!(seen.insert(next_u64()), "next_u64 repeated a value"); }
}

#[test]
fn output_is_not_linear_the_way_an_lcg_is() {
    // An LCG's successive outputs satisfy x[n+1] = a*x[n] + c for FIXED a, c,
    // so any two consecutive pairs solve for the same (a, c). Pull four words
    // and check no single (a, c) explains all three steps.
    let x: [u64; 4] = [next_u64(), next_u64(), next_u64(), next_u64()];
    let mut consistent = false;
    // Solve a from the first two steps where possible, then test the third.
    let d0 = x[1].wrapping_sub(x[0]);
    let d1 = x[2].wrapping_sub(x[1]);
    let d2 = x[3].wrapping_sub(x[2]);
    // For an LCG, d[n+1] = a * d[n]; an odd d0 is invertible mod 2^64.
    if d0 % 2 == 1 {
        let a = d1.wrapping_mul(inv_odd(d0));
        consistent = a.wrapping_mul(d1) == d2;
    }
    assert!(!consistent, "output satisfies an LCG recurrence: {x:?}");
}

/// Multiplicative inverse of an odd u64 mod 2^64 (Newton iteration).
fn inv_odd(a: u64) -> u64 {
    let mut x = a;
    for _ in 0..6 { x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); }
    x
}

#[test]
fn adding_entropy_changes_subsequent_output() {
    let before = take(32);
    add_entropy(b"F755 rseq/getrandom lane entropy sample");
    let after = take(32);
    assert_ne!(before, after);
}

/// Replaces `is_initialized_after_a_fill`, which asserted the bug: `reseed()`
/// set the ready flag whether or not any source answered, so a `fill()` was
/// enough to make the pool claim readiness. On a host (and on a TCG boot) there
/// is no RDRAND/RNDR and no bulk source, so the honest answer is "not ready" —
/// a `fill()` still returns good ChaCha output, it just cannot claim its key
/// came from entropy.
#[test]
fn a_fill_with_no_entropy_source_does_not_claim_readiness() {
    let _guard = exclusive();
    clear_bulk_source();
    reset_seeded_for_test();
    let v = take(32);
    assert!(v.iter().any(|&b| b != 0), "cold pool must still produce output");
    assert!(!reseed(), "reseed credited a pool with no entropy source");
    assert!(!is_initialized(),
        "pool reports ready with no entropy source — getrandom can never block \
         and GRND_NONBLOCK can never return EAGAIN");
}

/// The counterpart: a source that actually answers DOES make the pool ready.
/// Without this, the honesty fix could be "always report cold", which is just a
/// different lie and would hang `getrandom(2)` forever.
#[test]
fn a_bulk_source_that_answers_makes_the_pool_ready() {
    let _guard = exclusive();
    fn constant_source(dst: &mut [u8]) -> usize { dst.fill(0xA5); dst.len() }
    reset_seeded_for_test();
    assert!(!is_initialized());
    set_bulk_source(constant_source);
    assert!(is_initialized(), "an answering hardware source must credit the pool");
    clear_bulk_source();
}

/// `add_entropy` is Linux `add_device_randomness` — an attacker may have
/// chosen those bytes (userspace can write `/dev/urandom`), so it must mix
/// without crediting. `add_hw_entropy` is `add_hwgenerator_randomness` and does
/// credit.
#[test]
fn only_hardware_entropy_credits_the_pool() {
    let _guard = exclusive();
    clear_bulk_source();
    reset_seeded_for_test();
    add_entropy(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(!is_initialized(), "attacker-suppliable bytes must not mark the pool ready");
    add_hw_entropy(&[0x01, 0x02, 0x03, 0x04]);
    assert!(is_initialized(), "a hardware generator must be able to make a cold pool ready");
    reset_seeded_for_test();
    add_hw_entropy(&[]);
    assert!(!is_initialized(), "an empty contribution is not entropy");
}

#[test]
fn a_bulk_source_that_returns_nothing_still_yields_output() {
    let _guard = exclusive();
    fn empty_source(_: &mut [u8]) -> usize { 0 }
    set_bulk_source(empty_source);
    let v = take(32);
    assert!(v.iter().any(|&b| b != 0));
    clear_bulk_source();
}

#[test]
fn a_constant_bulk_source_cannot_freeze_the_pool() {
    // Even a wholly predictable "entropy" source must not make output repeat:
    // the ChaCha20 key erasure keeps every call distinct.
    let _guard = exclusive();
    fn constant_source(dst: &mut [u8]) -> usize { dst.fill(0xA5); dst.len() }
    set_bulk_source(constant_source);
    let a = take(32);
    let b = take(32);
    clear_bulk_source();
    assert_ne!(a, b);
}
