// `personality(ADDR_COMPAT_LAYOUT)` and the rest of `mmap_is_legacy`.
//
// The bit is only implemented if the exec ends up with a bottom-up arena
// ANCHORED LOW — asserting that the persona word round-trips proves nothing.
// These cover the decision and the anchor; that the allocator then searches
// upward from it is `vmm`'s `legacy_layout` tests.

use crate::layout::{mmap_is_legacy, mmap_legacy_base, unlimited_stack_flips_layout};
use crate::limits::{AARCH64, DEFAULT_MAP_WINDOW, X86_64};
use crate::mode::Mode;
use crate::tunable::{legacy_va_layout, set_legacy_va_layout};
use crate::{ExecRnd, Layout};

const STACK_8M: u64 = 8 << 20;
const UNLIMITED: bool = true;
const BOUNDED: bool = false;

fn rnd(no_randomize: bool, b: crate::Budget) -> ExecRnd {
    ExecRnd::draw_with(Mode::Full, no_randomize, b, b.mmap_rnd_bits)
}

#[test]
fn task_unmapped_base_is_the_arch_fraction_of_the_window() {
    // x86_64 `PAGE_ALIGN(task_size / 3)`, arm64 `PAGE_ALIGN(window / 4)` —
    // NOT one shared constant. Collapsing them would move every legacy
    // mapping on one arch.
    assert_eq!(X86_64.task_unmapped_base(), page_align(DEFAULT_MAP_WINDOW / 3));
    assert_eq!(AARCH64.task_unmapped_base(), page_align(DEFAULT_MAP_WINDOW / 4));
    assert_ne!(X86_64.task_unmapped_base(), AARCH64.task_unmapped_base());
    for b in [X86_64, AARCH64] {
        assert_eq!(b.task_unmapped_base() % hal::PAGE_SIZE_BYTES, 0);
        assert!(b.task_unmapped_base() > 0);
    }
}

fn page_align(v: u64) -> u64 {
    (v + (hal::PAGE_SIZE_BYTES - 1)) & !(hal::PAGE_SIZE_BYTES - 1)
}

#[test]
fn the_persona_bit_selects_legacy_on_its_own() {
    // Any ONE of the three inputs is sufficient; none is necessary.
    assert!(mmap_is_legacy(true, BOUNDED, false, false));
    assert!(mmap_is_legacy(true, BOUNDED, true, false));
    assert!(!mmap_is_legacy(false, BOUNDED, true, false));
    assert!(mmap_is_legacy(false, BOUNDED, true, true), "the sysctl alone must flip it");
}

#[test]
fn an_unlimited_stack_flips_the_layout_only_where_the_arch_tests_it() {
    // The generic `arch_pick_mmap_layout` (arm64) has the RLIM_INFINITY arm;
    // x86_64's own copy does not, and clamps the gap instead.
    assert!(mmap_is_legacy(false, UNLIMITED, true, false));
    assert!(!mmap_is_legacy(false, UNLIMITED, false, false));
    // `unlimited_stack_flips_layout` is what feeds that argument, and it must
    // be the arm64-only answer.
    assert_eq!(unlimited_stack_flips_layout(), cfg!(target_arch = "aarch64"));
}

#[test]
fn a_legacy_exec_anchors_low_and_a_default_exec_anchors_high() {
    for b in [X86_64, AARCH64] {
        let r = rnd(false, b);
        let legacy = r.mmap_layout(STACK_8M, true, BOUNDED);
        let normal = r.mmap_layout(STACK_8M, false, BOUNDED);
        assert!(!legacy.top_down, "ADDR_COMPAT_LAYOUT must clear MMF_TOPDOWN");
        assert!(normal.top_down, "the default layout is top-down");
        assert!(legacy.base < normal.base,
                "legacy anchor {:#x} is not below the default arena top {:#x}",
                legacy.base, normal.base);
        assert!(legacy.base >= b.task_unmapped_base(),
                "legacy anchor fell below TASK_UNMAPPED_BASE");
        assert_eq!(legacy.base % hal::PAGE_SIZE_BYTES, 0);
    }
}

#[test]
fn the_legacy_anchor_is_task_unmapped_base_plus_the_shared_arena_draw() {
    for b in [X86_64, AARCH64] {
        let r = rnd(false, b);
        // ONE `random_factor` feeds both anchors, exactly as
        // `arch_pick_mmap_base` passes one word to `mmap_base` and
        // `mmap_legacy_base`. Two draws would double this exec's arena entropy
        // consumption and decorrelate anchors that Linux keeps tied.
        assert_eq!(r.mmap_legacy_base(), mmap_legacy_base(r.mmap_rnd, &b));
        assert_eq!(r.mmap_legacy_base(), b.task_unmapped_base() + r.mmap_rnd);
    }
}

#[test]
fn addr_no_randomize_pins_the_legacy_anchor_to_task_unmapped_base() {
    // The two persona bits are orthogonal: direction is not a randomisation
    // decision, but the legacy anchor still inherits the arena draw, so
    // `setarch -R -L` must be exactly reproducible at TASK_UNMAPPED_BASE.
    for b in [X86_64, AARCH64] {
        let fixed = rnd(true, b).mmap_layout(STACK_8M, true, BOUNDED);
        assert_eq!(fixed, Layout { base: b.task_unmapped_base(), top_down: false });
        assert_eq!(rnd(true, b).mmap_layout(STACK_8M, true, BOUNDED), fixed,
                   "ADDR_NO_RANDOMIZE|ADDR_COMPAT_LAYOUT is not reproducible");
        // Randomised, the same bit pair still moves.
        let mut seen = [0u64; 32];
        for slot in seen.iter_mut() { *slot = rnd(false, b).mmap_layout(STACK_8M, true, BOUNDED).base; }
        seen.sort_unstable();
        let distinct = 1 + seen.windows(2).filter(|w| w[0] != w[1]).count();
        assert!(distinct > 16, "the legacy anchor lost its randomisation");
    }
}

#[test]
fn the_sysctl_defaults_off_and_drives_the_layout_when_set() {
    assert!(!legacy_va_layout(), "vm.legacy_va_layout must boot at 0");
    let b = crate::CURRENT;
    let r = rnd(false, b);
    assert!(r.mmap_layout(STACK_8M, false, BOUNDED).top_down);
    set_legacy_va_layout(true);
    let flipped = r.mmap_layout(STACK_8M, false, BOUNDED);
    set_legacy_va_layout(false);
    assert!(!flipped.top_down, "vm.legacy_va_layout=1 did not reach the layout");
    assert_eq!(flipped.base, r.mmap_legacy_base());
    assert!(r.mmap_layout(STACK_8M, false, BOUNDED).top_down, "the sysctl did not reset");
}
