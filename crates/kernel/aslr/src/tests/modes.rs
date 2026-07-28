use crate::exec::ExecRnd;
use crate::limits::{X86_64, AARCH64};
use crate::mode::*;

/// `Documentation/admin-guide/sysctl/kernel.rst:1208-1227` plus the two read
/// sites: `!= 0` arms everything, `> 1` additionally arms `brk`.
#[test]
fn three_modes_fold_exactly_as_linux_folds_them() {
    assert_eq!(Mode::from_raw(0), Mode::Off);
    assert_eq!(Mode::from_raw(1), Mode::Conservative);
    assert_eq!(Mode::from_raw(2), Mode::Full);
    // `proc_dointvec` has no min/max on this leaf, so these are reachable and
    // must fold the way Linux's two comparisons fold them.
    assert_eq!(Mode::from_raw(3), Mode::Full);
    assert_eq!(Mode::from_raw(i32::MAX), Mode::Full);
    assert_eq!(Mode::from_raw(-1), Mode::Conservative);

    assert!(!Mode::Off.randomizes());
    assert!(Mode::Conservative.randomizes() && !Mode::Conservative.randomizes_brk());
    assert!(Mode::Full.randomizes() && Mode::Full.randomizes_brk());
}

/// Mode 1 vs mode 2 differ in exactly one documented way: the heap.
#[test]
fn mode_1_and_2_differ_only_in_brk() {
    let one = ExecRnd::draw_with(Mode::Conservative, false, X86_64, X86_64.mmap_rnd_bits);
    let two = ExecRnd::draw_with(Mode::Full, false, X86_64, X86_64.mmap_rnd_bits);
    assert!(one.randomize && two.randomize);
    assert!(!one.randomize_brk, "mode 1 must leave brk alone");
    assert!(two.randomize_brk, "mode 2 must move brk");

    let img_end = 0x5555_5556_0000u64;
    assert_eq!(one.brk(img_end, false), img_end, "mode 1 moved the heap");
    assert_ne!(two.brk(img_end, false), img_end, "mode 2 left the heap in place");
    // Both still randomise the arena, the stack and the executable.
    for r in [one, two] {
        assert_ne!(r.mmap_rnd, 0);
        assert_ne!(r.stack_top(), crate::limits::STACK_TOP);
    }
}

/// `randomize_va_space=0` must produce a byte-identical layout across execs —
/// the negative case `setarch -R`, `gdb` and reproducible-build tooling need.
#[test]
fn mode_off_is_identical_across_execs() {
    let a = ExecRnd::draw_with(Mode::Off, false, X86_64, X86_64.mmap_rnd_bits);
    let b = ExecRnd::draw_with(Mode::Off, false, X86_64, X86_64.mmap_rnd_bits);
    assert_eq!(a, b);
    assert_eq!(a, crate::exec::NONE);
    assert_layout_is_fixed(&a, &b);
}

/// `personality(ADDR_NO_RANDOMIZE)` must be equally absolute, at every mode —
/// this is what makes `setarch -R` work on a system whose sysctl says 2.
#[test]
fn addr_no_randomize_pins_the_layout_at_every_mode() {
    for m in [Mode::Off, Mode::Conservative, Mode::Full] {
        let a = ExecRnd::draw_with(m, true, X86_64, X86_64.mmap_rnd_bits);
        let b = ExecRnd::draw_with(m, true, AARCH64, AARCH64.mmap_rnd_bits);
        assert!(!a.randomize && !a.randomize_brk, "{m:?} randomised under ADDR_NO_RANDOMIZE");
        assert!(!b.randomize && !b.randomize_brk);
        assert_layout_is_fixed(&a, &a);
        assert_layout_is_fixed(&b, &b);
    }
    // And `Mode::Full` WITHOUT the personality bit does randomise, so the
    // assertion above is testing the bit rather than a dead code path.
    let live = ExecRnd::draw_with(Mode::Full, false, X86_64, X86_64.mmap_rnd_bits);
    assert!(live.randomize && live.randomize_brk);
}

/// The gate combination Linux writes at `fs/binfmt_elf.c:1332`.
#[test]
fn brk_gate_needs_both_the_mode_and_the_personality() {
    assert!(randomize_brk(Mode::Full, false));
    assert!(!randomize_brk(Mode::Full, true));
    assert!(!randomize_brk(Mode::Conservative, false));
    assert!(!randomize_brk(Mode::Off, false));
    assert!(pf_randomize(Mode::Conservative, false));
    assert!(!pf_randomize(Mode::Conservative, true));
    assert!(!pf_randomize(Mode::Off, false));
}

/// The live cell round-trips and starts where Linux starts.
#[test]
fn sysctl_cell_defaults_to_two_and_round_trips() {
    assert_eq!(DEFAULT, 2);
    let saved = randomize_va_space();
    for v in [0, 1, 2] {
        set_randomize_va_space(v);
        assert_eq!(randomize_va_space(), v);
        assert_eq!(mode(), Mode::from_raw(v));
    }
    set_randomize_va_space(saved);
}

/// Every randomised quantity must be pinned, not just the flags.
fn assert_layout_is_fixed(a: &ExecRnd, b: &ExecRnd) {
    let img_end = 0x0060_0000u64;
    assert_eq!(a.mmap_base(8 << 20), b.mmap_base(8 << 20));
    assert_eq!(a.stack_top(), b.stack_top());
    assert_eq!(a.stack_top(), crate::limits::STACK_TOP);
    assert_eq!(a.elf_dyn_load_bias(0x1000), crate::limits::ELF_ET_DYN_BASE);
    assert_eq!(a.brk(img_end, false), img_end);
    assert_eq!(a.align_stack(0x1_0000_0010), 0x1_0000_0010);
}
