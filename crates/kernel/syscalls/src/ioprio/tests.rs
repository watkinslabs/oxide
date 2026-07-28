// Hosted unit tests for the ioprio decision core.
// Reference: Linux v7.2.0-rc4 `block/ioprio.c`, `include/linux/ioprio.h`,
// `include/uapi/linux/ioprio.h`.

use super::*;

const EINVAL: i64 = -(Errno::Einval as i32 as i64);

#[test]
fn packing_matches_ioprio_prio_value() {
    assert_eq!(prio_value(CLASS_BE, 4), (2 << 13) | 4);
    assert_eq!(prio_class(prio_value(CLASS_IDLE, 7)), CLASS_IDLE);
    assert_eq!(prio_level(prio_value(CLASS_IDLE, 7)), 7);
}

#[test]
fn class_is_masked_to_three_bits_of_the_full_int() {
    // IOPRIO_PRIO_CLASS shifts the whole `int` and masks 3 bits, so bits above
    // 15 never reach the class.
    assert_eq!(prio_class(0x1_2004), CLASS_RT);
    assert_eq!(prio_class(-1), 7);
}

#[test]
fn level_is_the_low_three_bits_not_the_low_thirteen() {
    // IOPRIO_PRIO_LEVEL uses IOPRIO_LEVEL_MASK (7); bits [12:3] are the hint.
    assert_eq!(prio_level(0b1111_1000), 0);
    assert_eq!(prio_level(0b1111_1101), 5);
}

// --- ioprio_check_cap ------------------------------------------------------

#[test]
fn rt_class_needs_privilege() {
    assert_eq!(check_cap(prio_value(CLASS_RT, 0)), Ok(CapNeed::SysAdminOrSysNice));
}

#[test]
fn be_and_idle_need_nothing() {
    assert_eq!(check_cap(prio_value(CLASS_BE, 7)), Ok(CapNeed::None));
    assert_eq!(check_cap(prio_value(CLASS_IDLE, 0)), Ok(CapNeed::None));
}

#[test]
fn class_none_with_a_level_is_einval() {
    // "case IOPRIO_CLASS_NONE: if (level) return -EINVAL;"
    assert_eq!(check_cap(prio_value(CLASS_NONE, 0)), Ok(CapNeed::None));
    for level in 1..=7 { assert_eq!(check_cap(prio_value(CLASS_NONE, level)), Err(EINVAL), "level {level}"); }
    // The hint bits are not the level, so they stay legal under CLASS_NONE.
    assert_eq!(check_cap(0b1111_1000), Ok(CapNeed::None));
}

#[test]
fn invalid_and_unassigned_classes_are_einval() {
    for class in [4, 5, 6, 7] {
        assert_eq!(check_cap(prio_value(class, 0)), Err(EINVAL), "class {class}");
    }
    assert_eq!(check_cap(-1), Err(EINVAL));
}

// --- which -----------------------------------------------------------------

#[test]
fn who_maps_onto_the_getpriority_base() {
    assert_eq!(who_base(WHO_PROCESS), Ok(0));
    assert_eq!(who_base(WHO_PGRP), Ok(1));
    assert_eq!(who_base(WHO_USER), Ok(2));
    assert_eq!(who_base(0), Err(EINVAL));
    assert_eq!(who_base(4), Err(EINVAL));
    assert_eq!(who_base(-1), Err(EINVAL));
}

// --- __get_task_ioprio -----------------------------------------------------

#[test]
fn unset_priority_is_derived_from_nice() {
    // task_nice_ioclass -> BE, task_nice_ioprio -> (nice + 20) / 5.
    assert_eq!(effective(DEFAULT, 0, false, false), prio_value(CLASS_BE, 4));
    assert_eq!(effective(DEFAULT, -20, false, false), prio_value(CLASS_BE, 0));
    assert_eq!(effective(DEFAULT, 19, false, false), prio_value(CLASS_BE, 7));
}

#[test]
fn unset_priority_follows_the_scheduling_class() {
    assert_eq!(prio_class(effective(DEFAULT, 0, true, false)), CLASS_IDLE);
    assert_eq!(prio_class(effective(DEFAULT, 0, false, true)), CLASS_RT);
}

#[test]
fn an_explicit_priority_is_reported_verbatim() {
    let set = prio_value(CLASS_IDLE, 2);
    assert_eq!(effective(set, -20, false, true), set);
}

// --- ioprio_best -----------------------------------------------------------

#[test]
fn best_prefers_the_lower_class_then_the_lower_level() {
    assert_eq!(best(prio_value(CLASS_BE, 0), prio_value(CLASS_RT, 7)), prio_value(CLASS_RT, 7));
    assert_eq!(best(prio_value(CLASS_BE, 6), prio_value(CLASS_BE, 2)), prio_value(CLASS_BE, 2));
    assert_eq!(best(prio_value(CLASS_IDLE, 0), prio_value(CLASS_BE, 7)), prio_value(CLASS_BE, 7));
}
