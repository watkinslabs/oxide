// The randomness has to be REAL, not merely varying. `F768` learned this the
// expensive way: `AT_RANDOM` derived 16 bytes from a single `monotonic_ns()`
// sample and passed a "two execs differ" test for months, because a clock
// advances. Every assertion here is chosen to fail against that shape:
//   * full-budget bit coverage    — a clock pins the high bits
//   * per-bit balance             — a clock's low bits are not uniform
//   * ~50% descending steps       — a clock never descends
//   * no repeated values          — the negative control
// and to fail against an off-by-one in the mask (bits outside the budget must
// be provably constant).

use std::vec::Vec;

use crate::exec::ExecRnd;
use crate::layout;
use crate::limits::{Budget, AARCH64, ELF_ET_DYN_BASE, PAGE_SHIFT, STACK_TOP, X86_64};
use crate::mode::Mode;

/// Sample count. At 4096 samples the chance any single in-budget bit is
/// constant is 2^-4095, so a coverage failure is a real defect, never flake.
const N: usize = 4096;

const ARCHES: [Budget; 2] = [X86_64, AARCH64];

/// Collect `N` values of one randomised quantity, expressed as the OFFSET the
/// randomiser contributed (so the expected varying window is `lo..hi` bits).
fn sample(f: impl Fn(&ExecRnd) -> u64, b: Budget, bits: u32) -> Vec<u64> {
    (0..N).map(|_| f(&ExecRnd::draw_with(Mode::Full, false, b, bits))).collect()
}

/// Every bit in `[lo, hi)` must be observed both set and clear; every bit
/// outside must be constant across all samples. This is the assertion a
/// clock-derived value fails (its high bits never flip) and a wrong mask fails
/// (a bit varies outside the window, or a window bit never moves).
fn assert_bit_window(vals: &[u64], lo: u32, hi: u32, what: &str) {
    let ones: Vec<usize> = (0..64)
        .map(|bit| vals.iter().filter(|v| (*v >> bit) & 1 == 1).count())
        .collect();
    for bit in 0..64u32 {
        let n = ones[bit as usize];
        if bit >= lo && bit < hi {
            assert!(n > 0 && n < vals.len(),
                "{what}: bit {bit} is constant ({n}/{}) — entropy narrower than the {lo}..{hi} budget",
                vals.len());
            // Binomial mean N/2, sd sqrt(N)/2 = 32 at N=4096. A 20% band is
            // ~25 sd wide: impossible to trip by chance, trivially tripped by
            // a biased or counter-derived source.
            let lo_b = vals.len() * 40 / 100;
            let hi_b = vals.len() * 60 / 100;
            assert!(n > lo_b && n < hi_b, "{what}: bit {bit} biased — {n}/{} set", vals.len());
        } else {
            assert_eq!(n, 0, "{what}: bit {bit} varies outside the {lo}..{hi} budget");
        }
    }
}

/// A monotonic source (the clock bug) produces ~100% ascending steps. Real
/// entropy produces ~50%. Also catches a stuck value (0% of either).
fn assert_not_monotonic(vals: &[u64], what: &str) {
    let asc = vals.windows(2).filter(|w| w[1] > w[0]).count();
    let lo = (vals.len() - 1) * 35 / 100;
    let hi = (vals.len() - 1) * 65 / 100;
    assert!(asc > lo && asc < hi,
        "{what}: {asc}/{} steps ascend — a monotonic or stuck source, not entropy",
        vals.len() - 1);
}

/// With a budget of 18 bits or more, 4096 draws from a uniform source collide
/// rarely; a small state space or a repeating stream shows up immediately.
fn assert_mostly_distinct(vals: &[u64], what: &str) {
    let mut sorted: Vec<u64> = vals.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert!(sorted.len() * 100 >= vals.len() * 95,
        "{what}: only {} distinct values in {} draws", sorted.len(), vals.len());
}

fn assert_real_entropy(vals: &[u64], lo: u32, hi: u32, what: &str) {
    assert_bit_window(vals, lo, hi, what);
    assert_not_monotonic(vals, what);
    assert_mostly_distinct(vals, what);
}

/// `arch_mmap_rnd()` must span its FULL `mmap_rnd_bits` budget — 28 bits on
/// x86_64, 18 on aarch64 — page-shifted, with nothing outside that window.
#[test]
fn mmap_rnd_uses_the_whole_budget_on_both_arches() {
    for b in ARCHES {
        for bits in [b.mmap_rnd_bits_min, b.mmap_rnd_bits_max] {
            let v = sample(|r| r.mmap_rnd, b, bits);
            assert_real_entropy(&v, PAGE_SHIFT, PAGE_SHIFT + bits, "mmap_rnd");
        }
    }
}

/// The PIE load bias is a SECOND, independent `arch_mmap_rnd()` draw. If the
/// loader reused the arena's draw, the two would be equal every time and the
/// executable's position would be derivable from any mmap address leak.
#[test]
fn load_bias_draw_is_independent_of_the_arena_draw() {
    for b in ARCHES {
        let bits = b.mmap_rnd_bits;
        let r: Vec<ExecRnd> =
            (0..N).map(|_| ExecRnd::draw_with(Mode::Full, false, b, bits)).collect();
        let same = r.iter().filter(|x| x.mmap_rnd == x.load_bias_rnd).count();
        assert!(same * 100 < N, "load bias tracks the arena draw in {same}/{N} execs");
        let biases: Vec<u64> =
            r.iter().map(|x| x.elf_dyn_load_bias(0x1000) - ELF_ET_DYN_BASE).collect();
        assert_real_entropy(&biases, PAGE_SHIFT, PAGE_SHIFT + bits, "load_bias");
    }
}

/// `mmap_base` carries the arena entropy. Sampling the OFFSET below the
/// unrandomised base isolates the random term from the fixed gap.
#[test]
fn mmap_base_carries_the_full_arena_entropy() {
    for b in ARCHES {
        let bits = b.mmap_rnd_bits;
        let zero = layout::mmap_base(0, 8 << 20, true, &b);
        let v = sample(|r| zero - r.mmap_base(8 << 20), b, bits);
        assert_real_entropy(&v, PAGE_SHIFT, PAGE_SHIFT + bits, "mmap_base");
    }
}

/// `STACK_RND_MASK` is 22 bits on x86_64 and 18 on aarch64. A shared constant
/// would hand aarch64 x86's budget and this test would see bits 30 and 31
/// varying on aarch64.
#[test]
fn stack_top_uses_the_arch_stack_rnd_mask() {
    for b in ARCHES {
        let mask_bits = 64 - b.stack_rnd_mask.leading_zeros();
        let v = sample(|r| STACK_TOP - r.stack_top(), b, b.mmap_rnd_bits);
        assert_real_entropy(&v, PAGE_SHIFT, PAGE_SHIFT + mask_bits, "stack_top");
    }
    assert_eq!(64 - X86_64.stack_rnd_mask.leading_zeros(), 22);
    assert_eq!(64 - AARCH64.stack_rnd_mask.leading_zeros(), 18);
}

/// `arch_randomize_brk` moves the heap up to 1 GiB — 18 page-bits of entropy,
/// identical on both arches (`SZ_1G` for every native 64-bit task).
#[test]
fn brk_offset_spans_one_gigabyte() {
    for b in ARCHES {
        let img_end = 0x5555_5556_0000u64;
        let floor = img_end + hal::PAGE_SIZE_BYTES;
        let v = sample(|r| r.brk(img_end, false) - floor, b, b.mmap_rnd_bits);
        assert_real_entropy(&v, PAGE_SHIFT, PAGE_SHIFT + 18, "brk");
        assert!(v.iter().all(|&x| x < crate::limits::BRK_RND_RANGE));
    }
}

/// `arch_align_stack` shuffles cache-set alignment: up to 8191 bytes on
/// x86_64, up to `PAGE_SIZE - 1` on aarch64, then 16-byte aligned. The 16-byte
/// round-up makes the reachable set the 16-aligned slots in
/// `[0, align_stack_max]`, which is one wider than a power of two — so this
/// measures slot coverage rather than a bit window.
#[test]
fn align_stack_jitter_covers_its_arch_range() {
    for b in ARCHES {
        let sp = 0x7fff_0000_0000u64;
        let max = b.align_stack_max as u64;
        let v = sample(|r| sp - r.align_stack(sp), b, b.mmap_rnd_bits);
        assert!(v.iter().all(|&x| x % 16 == 0 && x <= max),
            "align_stack left an out-of-range or misaligned offset");
        let mut slots: Vec<u64> = v.iter().map(|x| x / 16).collect();
        slots.sort_unstable();
        slots.dedup();
        let want = (max / 16 + 1) * 90 / 100;
        assert!(slots.len() as u64 >= want,
            "align_stack covered {} of {} slots", slots.len(), max / 16 + 1);
        assert_not_monotonic(&v, "align_stack");
    }
}

/// Negative control for the whole file: the same assertions applied to a
/// counter — the shape of the `AT_RANDOM` clock bug — must FAIL. Without this,
/// a green suite proves only that the assertions ran, not that they bite.
#[test]
fn the_assertions_reject_a_clock_like_source() {
    let counter: Vec<u64> = (0..N as u64).map(|i| (0x1_0000_0000u64 + i) << PAGE_SHIFT).collect();
    assert!(std::panic::catch_unwind(|| assert_not_monotonic(&counter, "counter")).is_err(),
        "monotonic check failed to reject a counter");
    assert!(std::panic::catch_unwind(|| {
        assert_bit_window(&counter, PAGE_SHIFT, PAGE_SHIFT + 28, "counter")
    }).is_err(), "bit-window check failed to reject a counter");
    // A stuck source must be rejected too.
    let stuck = std::vec![0x4_1000u64; N];
    assert!(std::panic::catch_unwind(|| assert_mostly_distinct(&stuck, "stuck")).is_err(),
        "distinctness check failed to reject a stuck source");
}
