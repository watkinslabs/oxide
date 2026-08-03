// The slot arithmetic and the naming, tested against the real window geometry.
//
// The fault this exists for: `rsp=0xfffffb0000006000` on a `#DF`, which is
// exactly a slot's lowest stack byte — the stack exhausted to its last byte,
// the next push in the guard page. The register dump could not say WHICH stack,
// and the two candidates have different budgets and different fixes.

use super::*;

/// The geometry the window is actually built with, restated so a change to
/// either constant fails here rather than silently renaming every slot.
const GUARD: u64 = PAGE;
const STACK: u64 = SLOT_BYTES - PAGE;

fn slot_base(n: u64) -> u64 { KSTACK_VA_BASE + n * SLOT_BYTES }

#[test]
fn an_address_below_the_window_is_not_a_kernel_stack() {
    assert_eq!(span_of(0), None);
    assert_eq!(span_of(KSTACK_VA_BASE - 1), None);
}

#[test]
fn an_address_past_the_last_slot_is_not_a_kernel_stack() {
    assert_eq!(span_of(KSTACK_VA_BASE + MAX_STACKS as u64 * SLOT_BYTES), None);
}

#[test]
fn a_slot_is_a_guard_page_then_the_stack() {
    let s = span_of(slot_base(1) + GUARD).expect("inside the window");
    assert_eq!(s.slot, 1);
    assert_eq!(s.guard_lo, slot_base(1));
    assert_eq!(s.stack_lo, slot_base(1) + GUARD);
    assert_eq!(s.stack_hi, slot_base(1) + SLOT_BYTES);
    assert_eq!(s.stack_hi - s.stack_lo, STACK);
}

/// The observed fault, reproduced as arithmetic: the reported `rsp` is slot 1's
/// floor, so the stack was exhausted to its last byte.
#[test]
fn the_observed_fault_address_is_slot_ones_stack_floor() {
    let rsp = 0xffff_fb00_0000_6000u64;
    let s = span_of(rsp).expect("inside the window");
    assert_eq!(s.slot, 1);
    assert_eq!(s.stack_lo, rsp, "rsp is the lowest stack byte");
    assert_eq!(s.headroom(rsp), 0, "no bytes left");
    assert!(s.is_guard(rsp - 1), "the next push lands in the guard page");
}

#[test]
fn a_top_belongs_to_the_next_slots_guard_page_not_this_one() {
    // The stack's `top` is one past its last byte, so it is NOT in this slot.
    let top = slot_base(3) + SLOT_BYTES;
    assert_eq!(span_of(top).expect("still in the window").slot, 4);
    assert_eq!(span_of(top - 1).expect("last byte").slot, 3);
}

#[test]
fn the_guard_page_is_the_bytes_below_the_stack() {
    let s = span_of(slot_base(2) + GUARD).unwrap();
    assert!(s.is_guard(slot_base(2)));
    assert!(s.is_guard(slot_base(2) + GUARD - 1));
    assert!(!s.is_guard(s.stack_lo), "the floor is stack, not guard");
    assert!(!s.is_guard(s.stack_hi - 1));
}

#[test]
fn headroom_is_the_distance_above_the_floor() {
    let s = span_of(slot_base(5) + GUARD).unwrap();
    assert_eq!(s.headroom(s.stack_lo), 0);
    assert_eq!(s.headroom(s.stack_lo + 256), 256);
    assert_eq!(s.headroom(s.stack_hi), STACK);
}

#[test]
fn a_slot_tagged_at_allocation_is_named_by_that_tag() {
    assert_eq!(kind_from_tag(TAG_IRQ), StackKind::Irq);
    assert_eq!(kind_from_tag(TAG_TASK), StackKind::Task);
}

/// Untagged must be its own answer, never a defaulted TASK: a slot nobody owns
/// is a real failure mode and reporting it as a task stack hides it.
#[test]
fn an_untagged_slot_is_reported_unowned_not_task() {
    assert_eq!(kind_from_tag(TAG_NONE), StackKind::Unowned);
    assert_eq!(kind_from_tag(200), StackKind::Unowned);
}

#[test]
fn the_names_are_the_ones_the_fault_report_prints() {
    assert_eq!(StackKind::Irq.name(), b"IRQ");
    assert_eq!(StackKind::Task.name(), b"TASK");
    assert_eq!(StackKind::Unowned.name(), b"UNOWNED");
}

const TL: u64 = 0xffff_ffff_8000_0000;
const TH: u64 = 0xffff_ffff_8200_0000;

/// The whole point: a stack filled by one site repeating must name that site.
/// A static depth walk measures one pass, so this is what explains the gap
/// between "8.7 KB worst case" and a stack that died at 16 KB.
#[test]
fn one_site_repeated_is_found_and_counted() {
    let isr = TL + 0x6f05f;
    let mut w = alloc::vec::Vec::new();
    for _ in 0..300 { w.push(isr); w.push(0xdead_beef); }
    let (a, n) = top_repeat(&w, TL, TH);
    assert_eq!(a, isr);
    assert_eq!(n, 300);
}

#[test]
fn data_words_outside_kernel_text_are_not_counted() {
    let w = [0u64, 1, 0x7fff_ffff_ffff, TH, TL - 1];
    assert_eq!(top_repeat(&w, TL, TH), (0, 0));
}

/// A deep-but-varied chain has no dominant site — which is the answer that says
/// "this was depth, not repetition", the opposite diagnosis.
#[test]
fn a_chain_of_distinct_sites_reports_no_dominant_repeat() {
    let w: alloc::vec::Vec<u64> = (0..200).map(|i| TL + i * 0x40).collect();
    let (_, n) = top_repeat(&w, TL, TH);
    assert!(n <= 2, "no site should dominate a varied chain, got {n}");
}

/// The dominant site must win even when it is not seen first.
#[test]
fn a_late_dominant_site_still_wins() {
    let early = TL + 0x100;
    let isr = TL + 0x200;
    let mut w = alloc::vec::Vec::new();
    for _ in 0..5 { w.push(early); }
    for _ in 0..500 { w.push(isr); }
    assert_eq!(top_repeat(&w, TL, TH).0, isr);
}
