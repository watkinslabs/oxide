// The packed I/O-priority ABI, the nice-derived fallback, and the CLONE_IO
// sharing rule. These encode behaviour verified against the reference
// implementation; the tests are the durable record of it.

use super::*;

#[test]
fn class_and_level_round_trip_through_the_packed_value() {
    for class in [CLASS_NONE, CLASS_RT, CLASS_BE, CLASS_IDLE] {
        for level in 0..NR_LEVELS {
            let v = prio_value(class, level);
            assert_eq!(prio_class(v), class);
            assert_eq!(prio_level(v), level);
        }
    }
}

#[test]
fn the_level_is_the_low_three_bits_not_the_low_thirteen() {
    // Bits [12:3] are the hint field. A value carrying hint bits must still
    // report the level from bits [2:0] alone.
    let v = prio_value(CLASS_BE, 4) | (0x3ff << 3);
    assert_eq!(prio_level(v), 4);
    assert_eq!(prio_class(v), CLASS_BE);
}

#[test]
fn the_class_masks_three_bits_of_the_full_int() {
    assert_eq!(prio_class(-1), CLASS_MASK);
    // A value with garbage above the class field still reports the class.
    assert_eq!(prio_class(0x1_2004), CLASS_RT);
}

#[test]
fn only_rt_be_and_idle_are_valid_classes() {
    assert!(!prio_valid(prio_value(CLASS_NONE, 0)));
    assert!(!prio_valid(prio_value(CLASS_NONE, 7)));
    assert!(prio_valid(prio_value(CLASS_RT, 0)));
    assert!(prio_valid(prio_value(CLASS_BE, 7)));
    assert!(prio_valid(prio_value(CLASS_IDLE, 3)));
    for c in 4..=7 { assert!(!prio_valid(prio_value(c, 0))); }
}

#[test]
fn nice_folds_onto_exactly_eight_levels() {
    assert_eq!(nice_to_level(-20), 0);
    assert_eq!(nice_to_level(0), 4);
    assert_eq!(nice_to_level(19), 7);
    for n in -20..=19 {
        let l = nice_to_level(n);
        assert!(l < NR_LEVELS, "nice {n} produced level {l}");
    }
}

#[test]
fn an_unset_priority_is_derived_from_policy_and_nice() {
    assert_eq!(effective(DEFAULT, 0, false, false), prio_value(CLASS_BE, 4));
    assert_eq!(effective(DEFAULT, -20, false, false), prio_value(CLASS_BE, 0));
    assert_eq!(effective(DEFAULT, 19, false, false), prio_value(CLASS_BE, 7));
    // The policy picks the class; the nice value still picks the level.
    assert_eq!(effective(DEFAULT, 0, true, false), prio_value(CLASS_IDLE, 4));
    assert_eq!(effective(DEFAULT, 0, false, true), prio_value(CLASS_RT, 4));
}

#[test]
fn an_explicit_priority_is_reported_verbatim() {
    let v = prio_value(CLASS_IDLE, 2);
    // Neither nice nor policy may override an explicitly set class.
    assert_eq!(effective(v, -20, false, true), v);
}

#[test]
fn best_orders_by_class_first_then_level() {
    assert_eq!(best(prio_value(CLASS_RT, 7), prio_value(CLASS_BE, 0)), prio_value(CLASS_RT, 7));
    assert_eq!(best(prio_value(CLASS_BE, 2), prio_value(CLASS_BE, 5)), prio_value(CLASS_BE, 2));
    assert_eq!(best(prio_value(CLASS_IDLE, 0), prio_value(CLASS_BE, 7)), prio_value(CLASS_BE, 7));
}

#[test]
fn clone_io_shares_one_context_so_a_later_set_is_seen_by_both() {
    let parent = IoContext::new(prio_value(CLASS_BE, 3));
    let child = copy_io(&parent, true);
    child.set_ioprio(prio_value(CLASS_RT, 1));
    assert_eq!(parent.ioprio(), prio_value(CLASS_RT, 1));
    parent.set_ioprio(prio_value(CLASS_IDLE, 0));
    assert_eq!(child.ioprio(), prio_value(CLASS_IDLE, 0));
}

#[test]
fn a_plain_fork_copies_the_value_and_then_diverges() {
    let parent = IoContext::new(prio_value(CLASS_BE, 3));
    let child = copy_io(&parent, false);
    assert_eq!(child.ioprio(), prio_value(CLASS_BE, 3));
    child.set_ioprio(prio_value(CLASS_RT, 1));
    assert_eq!(parent.ioprio(), prio_value(CLASS_BE, 3));
}

#[test]
fn a_fork_from_an_unset_parent_leaves_the_child_unset() {
    // Class NONE is not carried forward: the child must keep deriving from
    // its own nice value, not freeze the parent's derived priority.
    let parent = IoContext::new(DEFAULT);
    assert_eq!(copy_io(&parent, false).ioprio(), DEFAULT);
    // The hint/level bits of an invalid-class value are not carried either.
    let parent = IoContext::new(prio_value(CLASS_NONE, 0) | 0x38);
    assert_eq!(copy_io(&parent, false).ioprio(), DEFAULT);
}
