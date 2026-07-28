use hal::{PAGE_SIZE_BYTES, USER_VA_END};

use crate::limits::*;

/// `arch/x86/Kconfig:358-364` and `arch/arm64/Kconfig:296-313`. The arm64 max
/// is the `ARM64_VA_BITS=47` row, because `hal::USER_VA_END` makes 47 the user
/// VA width on both arches here — picking the 48-bit row's 33 would let
/// `vm.mmap_rnd_bits` be raised past what the address space can absorb.
#[test]
fn budgets_match_linux_kconfig() {
    assert_eq!(X86_64.mmap_rnd_bits_min, 28);
    assert_eq!(X86_64.mmap_rnd_bits_max, 32);
    assert_eq!(X86_64.mmap_rnd_bits, X86_64.mmap_rnd_bits_min);
    assert_eq!(AARCH64.mmap_rnd_bits_min, 18);
    assert_eq!(AARCH64.mmap_rnd_bits_max, 30);
    assert_eq!(AARCH64.mmap_rnd_bits, AARCH64.mmap_rnd_bits_min);
}

/// `arch/x86/include/asm/elf.h:326` (`0x3fffff`, 22 bits) vs
/// `arch/arm64/include/asm/elf.h:194` (`0x3ffff`, 18 bits). These genuinely
/// differ and a shared constant would silently give arm64 x86's budget.
#[test]
fn stack_rnd_masks_differ_per_arch() {
    assert_eq!(X86_64.stack_rnd_mask, 0x3f_ffff);
    assert_eq!(AARCH64.stack_rnd_mask, 0x3_ffff);
    assert_ne!(X86_64.stack_rnd_mask, AARCH64.stack_rnd_mask);
    // Expressed as VA span: 16 GiB vs 1 GiB.
    assert_eq!((X86_64.stack_rnd_mask + 1) << PAGE_SHIFT, 16 * 1024 * 1024 * 1024);
    assert_eq!((AARCH64.stack_rnd_mask + 1) << PAGE_SHIFT, 1024 * 1024 * 1024);
}

/// `arch/x86/kernel/process.c:1023` subtracts up to 8191; arm64's
/// `arch/arm64/kernel/process.c:816` subtracts up to `PAGE_SIZE - 1`.
#[test]
fn align_stack_jitter_differs_per_arch() {
    assert_eq!(X86_64.align_stack_max, 8192);
    assert_eq!(AARCH64.align_stack_max, PAGE_SIZE_BYTES as u32);
}

/// `DEFAULT_MAP_WINDOW / 3 * 2`, page-aligned — the well-known `0x555555554000`
/// PIE base that `arch/x86/include/asm/elf.h:234` produces on a 47-bit window.
#[test]
fn elf_et_dyn_base_is_two_thirds_of_the_window() {
    assert_eq!(ELF_ET_DYN_BASE, 0x5555_5555_4000);
    assert_eq!(ELF_ET_DYN_BASE % PAGE_SIZE_BYTES, 0);
    assert!(ELF_ET_DYN_BASE < USER_VA_END);
    assert_eq!(DEFAULT_MAP_WINDOW, USER_VA_END - PAGE_SIZE_BYTES);
}

/// The whole point of putting the executable at two thirds and the arena at
/// the top: a maximally randomised PIE must still land below a maximally
/// randomised (i.e. lowest) `mmap_base`, or the loader and the arena fight over
/// the same VAs and a `MAP_FIXED` image silently eats a live mapping.
///
/// Bounded by `RLIM_STACK_MAP_CAP` because that is the largest stack this
/// kernel reserves up front. Linux has the same latent collision at absurd
/// `RLIMIT_STACK` values — `MAP_FIXED_NOREPLACE` turns it into an `EEXIST`
/// exec failure rather than corruption — but that regime is unreachable here.
#[test]
fn max_pie_bias_stays_below_min_mmap_base() {
    for b in [X86_64, AARCH64] {
        let max_rnd = ((1u64 << b.mmap_rnd_bits_max) - 1) << PAGE_SHIFT;
        let highest_pie = ELF_ET_DYN_BASE + max_rnd;
        let lowest_base = crate::layout::mmap_base(max_rnd, RLIM_STACK_MAP_CAP, true, &b);
        assert!(highest_pie < lowest_base,
            "PIE bias {highest_pie:#x} overruns mmap_base {lowest_base:#x}");
    }
}

/// `mm/util.c:428-429`.
#[test]
fn gap_bounds_match_linux() {
    assert_eq!(MIN_GAP, 128 * 1024 * 1024);
    assert_eq!(MAX_GAP, STACK_TOP / 6 * 5);
    assert_eq!(BRK_RND_RANGE, 1024 * 1024 * 1024);
    assert_eq!(STACK_GUARD_GAP, 256 * PAGE_SIZE_BYTES);
    assert_eq!(STACK_TOP, USER_VA_END - 0x1_0000);
}

/// The build arch's budget must be the one the build arch actually gets.
#[test]
fn current_budget_tracks_target_arch() {
    if cfg!(target_arch = "aarch64") {
        assert_eq!(CURRENT, AARCH64);
    } else {
        assert_eq!(CURRENT, X86_64);
    }
}
