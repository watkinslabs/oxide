use hal::PAGE_SIZE_BYTES;

use crate::layout::*;
use crate::limits::*;

const ARCHES: [Budget; 2] = [X86_64, AARCH64];

/// `arch_mmap_rnd` masks to the budget and shifts by `PAGE_SHIFT`: the result
/// is page-aligned for every input and never exceeds the budget's span. An
/// off-by-one in the mask is a silent overlap or an out-of-range base.
#[test]
fn mmap_rnd_is_page_aligned_and_within_budget() {
    for b in ARCHES {
        for bits in [b.mmap_rnd_bits_min, b.mmap_rnd_bits_max] {
            let span = 1u64 << (bits + PAGE_SHIFT);
            for raw in [0u64, 1, u64::MAX, 0x5555_5555_5555_5555, 0xaaaa_aaaa_aaaa_aaaa] {
                let r = arch_mmap_rnd(raw, bits);
                assert_eq!(r % PAGE_SIZE_BYTES, 0, "unaligned {r:#x}");
                assert!(r < span, "{r:#x} exceeds {bits}-bit budget");
            }
            // The all-ones input must reach the top of the budget exactly.
            assert_eq!(arch_mmap_rnd(u64::MAX, bits), span - PAGE_SIZE_BYTES);
        }
        // Zero bits = no randomisation, not a panic.
        assert_eq!(arch_mmap_rnd(u64::MAX, 0), 0);
    }
}

/// `mm/util.c:433-448`. `mmap_base` must be page-aligned, must sit below
/// `STACK_TOP` by at least `MIN_GAP`, and must stay above the bottom of user
/// space for every legal `RLIMIT_STACK`.
#[test]
fn mmap_base_respects_gap_clamp() {
    for b in ARCHES {
        for &rlim in &[0u64, 8 << 20, 1 << 30, MAX_GAP, u64::MAX] {
            for &rnd in &[0u64, ((1u64 << b.mmap_rnd_bits_max) - 1) << PAGE_SHIFT] {
                let base = mmap_base(rnd, rlim, true, &b);
                assert_eq!(base % PAGE_SIZE_BYTES, 0, "unaligned base {base:#x}");
                assert!(base <= STACK_TOP - MIN_GAP, "base {base:#x} too close to stack top");
                assert!(base > PAGE_SIZE_BYTES, "base {base:#x} underflowed user space");
            }
        }
    }
}

/// The pad Linux folds in is the MAXIMUM stack randomisation, not the draw
/// actually taken — so the arena top clears the lowest possible stack bottom
/// even when this exec's stack barely moved.
#[test]
fn mmap_base_clears_the_lowest_possible_stack() {
    for b in ARCHES {
        let rlim = 8 << 20;
        let base = mmap_base(0, rlim, true, &b);
        // Lowest stack bottom reachable: max stack-top shift, then rlim below.
        let lowest_stack_bottom =
            randomize_stack_top(STACK_TOP, u64::MAX, true, &b) - rlim;
        assert!(base + STACK_GUARD_GAP <= lowest_stack_bottom,
            "arena top {base:#x} intrudes on stack bottom {lowest_stack_bottom:#x}");
    }
}

/// `mm/util.c:341-355`: the random page count is SUBTRACTED (both arches take
/// the non-`STACK_GROWSUP` branch). A sign error here puts the stack above
/// `USER_VA_END` and every exec faults immediately.
#[test]
fn randomize_stack_top_subtracts_and_stays_aligned() {
    for b in ARCHES {
        let span = (b.stack_rnd_mask + 1) << PAGE_SHIFT;
        for raw in [0u64, 1, u64::MAX, 0x1234_5678_9abc_def0] {
            let top = randomize_stack_top(STACK_TOP, raw, true, &b);
            assert_eq!(top % PAGE_SIZE_BYTES, 0);
            assert!(top <= STACK_TOP, "stack top {top:#x} rose above STACK_TOP");
            assert!(top > STACK_TOP - span, "stack top {top:#x} fell past the budget");
        }
        assert_eq!(randomize_stack_top(STACK_TOP, u64::MAX, true, &b),
            STACK_TOP - (b.stack_rnd_mask << PAGE_SHIFT));
    }
}

/// `mm/util.c:371-387`. Result is page-aligned, at or above the aligned start,
/// and strictly inside `start + range`.
#[test]
fn randomize_page_stays_in_range() {
    let range = BRK_RND_RANGE;
    for &start in &[0x1000u64, 0x1234, ELF_ET_DYN_BASE, ELF_ET_DYN_BASE + 0x777] {
        let aligned = page_align_up(start);
        for raw in [0u64, 1, u64::MAX, 12345678901234567] {
            let p = randomize_page(start, range, raw);
            assert_eq!(p % PAGE_SIZE_BYTES, 0);
            assert!(p >= aligned, "{p:#x} below aligned start {aligned:#x}");
            assert!(p < aligned + range, "{p:#x} past start+range");
        }
    }
    // A range under one page cannot move anything.
    assert_eq!(randomize_page(0x2000, PAGE_SIZE_BYTES - 1, u64::MAX), 0x2000);
}

/// `fs/binfmt_elf.c:1144-1145`: the bias is masked DOWN to the image's
/// coarsest `p_align`, so a 2 MiB-aligned image stays 2 MiB-aligned after
/// randomisation. Losing this makes the segment's `p_vaddr % p_align`
/// wrong and the image mis-maps.
#[test]
fn elf_dyn_load_bias_honours_segment_alignment() {
    for align in [PAGE_SIZE_BYTES, 2 << 20, 1 << 30] {
        for rnd in [0u64, PAGE_SIZE_BYTES, 0x0f_ffff_f000, u64::MAX >> 24] {
            let bias = elf_dyn_load_bias(rnd, align);
            assert_eq!(bias % align, 0, "bias {bias:#x} not {align:#x}-aligned");
            assert!(bias >= ELF_ET_DYN_BASE - align, "bias {bias:#x} fell below the base");
        }
    }
    // Degenerate alignments must not corrupt the bias.
    assert_eq!(elf_dyn_load_bias(0, 0), ELF_ET_DYN_BASE);
    assert_eq!(elf_dyn_load_bias(0, 1), ELF_ET_DYN_BASE);
    assert_eq!(elf_dyn_load_bias(0, 3), ELF_ET_DYN_BASE);
}

/// `arch_align_stack` ends with `sp & ~0xf` on both arches — the SysV ABI
/// requires a 16-byte-aligned SP at `_start`, randomised or not.
#[test]
fn align_stack_is_always_16_byte_aligned() {
    for b in ARCHES {
        for raw in [0u64, 1, 7, u64::MAX, 0xdead_beef] {
            for randomize in [true, false] {
                let sp = arch_align_stack(0x7fff_ffff_0008, raw, randomize, &b);
                assert_eq!(sp % 16, 0, "sp {sp:#x} misaligned");
                assert!(sp <= 0x7fff_ffff_0008);
                assert!(sp + b.align_stack_max as u64 + 16 > 0x7fff_ffff_0008);
            }
        }
        // Not randomising is exactly Linux's `return sp & ~0xf`.
        assert_eq!(arch_align_stack(0x1_0000_000f, u64::MAX, false, &b), 0x1_0000_0000);
    }
}
