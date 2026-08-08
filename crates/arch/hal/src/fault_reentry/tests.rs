// Every test uses its own CPU slot so the suite's own concurrency cannot make
// one case observe another's records.

use super::*;

const A: u64 = 0x7ffe_dead_0000;
const B: u64 = 0x7ffe_beef_0000;
/// One kernel stack's span, matching the guard-paged slot size.
const SPAN: u64 = 16 * 1024;
/// A frame near the top of one stack, and the deeper frames a nest produces.
const TOP: u64 = 0xffff_8000_1000_0000;

#[test]
fn a_first_fault_resolves() {
    let c = 1;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(depth(c), 1);
}

/// THE rule. The same address faulting again from a DEEPER frame on the same
/// stack is the runaway that ate the kernel stack; the dispatcher must be told
/// to stop rather than re-enter the resolver.
#[test]
fn the_same_address_recurring_deeper_is_a_runaway() {
    let c = 2;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(enter(c, A, TOP - 208, SPAN), Verdict::Runaway);
}

/// Legitimate nesting must survive: resolving a fault at one address may touch
/// user memory at ANOTHER and fault there. Refusing that would turn every
/// signal-frame push onto an unfaulted user stack into a halt.
#[test]
fn a_different_address_may_nest() {
    let c = 3;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(enter(c, B, TOP - 208, SPAN), Verdict::Resolve);
    assert_eq!(depth(c), 2);
}

/// A resolved fault must not leave a record behind: the next fault at the same
/// address from a DEEPER frame on the same stack is a new fault, not a
/// recursion. Boot-observed — a kernel-mode write permission fault at one user
/// address, resolved, then taken again later in the same call chain, tripped the
/// guard and halted a healthy kernel.
#[test]
fn a_resolved_fault_leaves_no_record_to_match_later() {
    let c = 10;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    leave(c, TOP);
    assert_eq!(depth(c), 0);
    assert_eq!(enter(c, A, TOP - 512, SPAN), Verdict::Resolve, "a deeper later fault is not a recursion");
}

/// Retirement matches the frame, not the newest record: a resolver that blocked
/// and let another fault nest must still retire its own.
#[test]
fn retirement_matches_the_frame_that_made_the_record() {
    let c = 11;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(enter(c, B, TOP - 208, SPAN), Verdict::Resolve);
    leave(c, TOP);
    assert_eq!(depth(c), 1);
    // The inner record survived, so ITS address is still guarded.
    assert_eq!(enter(c, B, TOP - 416, SPAN), Verdict::Runaway);
}

/// Retiring a frame that made no record is a no-op, so a dispatcher path that
/// declined to make one cannot corrupt another CPU-slot's depth.
#[test]
fn retiring_an_unknown_frame_is_harmless() {
    let c = 12;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    leave(c, TOP - 4096);
    assert_eq!(depth(c), 1);
    leave(c, TOP);
    assert_eq!(depth(c), 0);
}

/// A blocking resolver switches away with a record still in flight. When the
/// same CPU next faults on ANOTHER task's stack, the stale record is not an
/// outer frame of it and must be pruned — otherwise a healthy kernel is
/// eventually refused and halted by its own guard.
#[test]
fn a_record_from_another_stack_is_pruned_not_matched() {
    let c = 4;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    // Different task, different stack, same faulting address.
    let other = TOP - 64 * SPAN;
    assert_eq!(enter(c, A, other, SPAN), Verdict::Resolve);
    assert_eq!(depth(c), 1, "the stale record must not survive the prune");
}

/// The prune must also drop records left by a frame the CPU has already
/// returned past on the SAME stack — one at or below the caller cannot be an
/// outer frame of it.
#[test]
fn a_record_from_an_already_unwound_frame_is_pruned() {
    let c = 5;
    assert_eq!(enter(c, A, TOP - 512, SPAN), Verdict::Resolve);
    // Unwound back to a shallower frame, then faulted at the same address.
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(depth(c), 1);
}

/// The overflow arm: distinct addresses nesting past the record bound are a
/// runaway too, because a chain that long is not a chain.
#[test]
fn nesting_past_the_record_bound_is_a_runaway() {
    let c = 6;
    for i in 0..DEPTH {
        assert_eq!(enter(c, A + i as u64 * 0x1000, TOP - i as u64 * 208, SPAN), Verdict::Resolve);
    }
    assert_eq!(enter(c, B, TOP - DEPTH as u64 * 208, SPAN), Verdict::Runaway);
}

/// One CPU's in-flight fault must not make another CPU's identical fault look
/// like a recursion — separate stacks, separate resolutions.
#[test]
fn cpus_do_not_see_each_others_records() {
    let (c, d) = (7, 8);
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(enter(d, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(depth(c), 1);
    assert_eq!(depth(d), 1);
}

/// A CPU index past the tracked ceiling folds into a slot rather than escaping
/// the guard: an unguarded CPU is the one case this must never produce.
#[test]
fn an_out_of_range_cpu_is_still_guarded() {
    let c = CPUS + 9;
    assert_eq!(enter(c, A, TOP, SPAN), Verdict::Resolve);
    assert_eq!(enter(c, A, TOP - 208, SPAN), Verdict::Runaway);
}

#[test]
fn outer_frame_window_is_above_the_caller_and_within_one_stack() {
    assert!(is_outer_frame(TOP, TOP - 208, SPAN));
    assert!(!is_outer_frame(TOP - 208, TOP, SPAN), "a deeper frame is not an outer one");
    assert!(!is_outer_frame(TOP, TOP, SPAN), "the same frame is not its own outer frame");
    assert!(!is_outer_frame(TOP + SPAN, TOP, SPAN), "a full stack away is another stack");
    assert!(!is_outer_frame(0, TOP, SPAN), "an unused record is never an outer frame");
}

#[test]
fn slot_folds_a_raw_cpu_id_into_range() {
    assert_eq!(slot(0), 0);
    assert_eq!(slot(CPUS as u64 - 1), CPUS - 1);
    assert_eq!(slot(CPUS as u64), 0);
}
