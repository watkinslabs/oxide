//! Keyed-event access mapping and key admission.

use super::*;

/// The mapping a keyed event publishes, read straight off the type's access
/// map: the shim has no accessor of its own for it, so a wrapper here would
/// be a second name for one fact.
fn granted_access(desired: u32) -> u32 { crate::nt_access::KEYED_EVENT.map(desired) }

#[test]
fn read_access_grants_the_wait_right_and_not_the_wake_right() {
    let access = granted_access(GENERIC_READ);
    assert_eq!(access & KEYEDEVENT_WAIT, KEYEDEVENT_WAIT);
    assert_eq!(access & KEYEDEVENT_WAKE, 0);
    assert_eq!(access & GENERIC_READ, 0, "the generic bit itself is never retained");
}

#[test]
fn write_access_grants_the_wake_right_and_not_the_wait_right() {
    let access = granted_access(GENERIC_WRITE);
    assert_eq!(access & KEYEDEVENT_WAKE, KEYEDEVENT_WAKE);
    assert_eq!(access & KEYEDEVENT_WAIT, 0);
}

#[test]
fn execute_access_grants_neither_keyed_right() {
    let access = granted_access(GENERIC_EXECUTE);
    assert_eq!(access & (KEYEDEVENT_WAIT | KEYEDEVENT_WAKE), 0);
    assert_eq!(access & STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_EXECUTE);
}

#[test]
fn all_access_grants_both_keyed_rights_but_never_object_synchronisation() {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let access = granted_access(GENERIC_ALL);
    assert_eq!(access & (KEYEDEVENT_WAIT | KEYEDEVENT_WAKE), KEYEDEVENT_WAIT | KEYEDEVENT_WAKE);
    // A handle carrying every keyed-event right is still not a waitable
    // object: waiting on one as an object is refused for lack of this bit.
    assert_eq!(KEYEDEVENT_ALL_ACCESS & SYNCHRONIZE, 0);
}

#[test]
fn an_explicit_right_passes_through_unchanged() {
    assert_eq!(granted_access(KEYEDEVENT_WAIT), KEYEDEVENT_WAIT);
    assert_eq!(granted_access(KEYEDEVENT_ALL_ACCESS), KEYEDEVENT_ALL_ACCESS);
}

#[test]
fn each_operation_demands_its_own_right() {
    // A wait-only handle refuses a release, and a wake-only handle refuses a
    // wait; that asymmetry is the whole access contract of the object.
    assert_eq!(required_access(false), KEYEDEVENT_WAIT);
    assert_eq!(required_access(true), KEYEDEVENT_WAKE);
    assert_eq!(granted_access(KEYEDEVENT_WAIT) & required_access(true), 0);
    assert_eq!(granted_access(KEYEDEVENT_WAKE) & required_access(false), 0);
}

#[test]
fn an_odd_key_is_refused_as_the_first_argument() {
    assert_eq!(key_status(0x2001), Some(STATUS_INVALID_PARAMETER_1));
    assert_ne!(STATUS_INVALID_PARAMETER_1, STATUS_INVALID_PARAMETER);
}

#[test]
fn an_aligned_key_is_admitted_including_the_null_key() {
    assert_eq!(key_status(0x2000), None);
    assert_eq!(key_status(0), None);
}

#[test]
fn the_published_right_values_are_the_documented_ones() {
    assert_eq!(KEYEDEVENT_WAIT, 0x0001);
    assert_eq!(KEYEDEVENT_WAKE, 0x0002);
    assert_eq!(KEYEDEVENT_ALL_ACCESS, 0x000f_0003);
}
