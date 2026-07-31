// The suspend gate: depth transitions, the drain, and in-flight accounting.

use crate::gate;
use crate::uapi::UmhDisableDepth;

use super::serialize;

const EINVAL: i32 = -22;
const EAGAIN: i32 = -11;

#[test]
fn depth_decodes_every_byte() {
    assert_eq!(UmhDisableDepth::from_u8(0), UmhDisableDepth::Enabled);
    assert_eq!(UmhDisableDepth::from_u8(1), UmhDisableDepth::Freezing);
    assert_eq!(UmhDisableDepth::from_u8(2), UmhDisableDepth::Disabled);
    // Anything unrecognised is the SAFE reading — refuse helpers.
    assert_eq!(UmhDisableDepth::from_u8(200), UmhDisableDepth::Disabled);
    assert!(!UmhDisableDepth::Enabled.is_disabled());
    assert!(UmhDisableDepth::Freezing.is_disabled());
    assert!(UmhDisableDepth::Disabled.is_disabled());
}

#[test]
fn freezing_already_refuses_helpers() {
    let _g = serialize();
    gate::reset_for_test();
    gate::usermodehelper_enable();
    assert!(!gate::usermodehelper_disabled());
    // The intermediate depth exists so the freezer can stop new helpers before
    // it has finished freezing; it must already refuse.
    gate::set_disable_depth(UmhDisableDepth::Freezing);
    assert!(gate::usermodehelper_disabled());
}

#[test]
fn disabling_to_the_enabled_depth_is_einval() {
    let _g = serialize();
    gate::reset_for_test();
    gate::usermodehelper_enable();
    assert_eq!(gate::__usermodehelper_disable(UmhDisableDepth::Enabled), EINVAL);
    // The rejected request must not have moved the gate.
    assert!(!gate::usermodehelper_disabled());
}

#[test]
fn disable_succeeds_when_nothing_is_in_flight() {
    let _g = serialize();
    gate::reset_for_test();
    gate::usermodehelper_enable();
    assert_eq!(gate::usermodehelper_disable(), 0);
    assert!(gate::usermodehelper_disabled());
    gate::usermodehelper_enable();
    assert!(!gate::usermodehelper_disabled());
}

#[test]
fn disable_times_out_and_reopens_the_gate_when_a_helper_is_stuck() {
    let _g = serialize();
    gate::reset_for_test();
    gate::usermodehelper_enable();
    gate::helper_lock();
    assert_eq!(gate::running_helpers(), 1);
    // Suspend cannot proceed with a helper mid-exec; the failure must leave the
    // gate OPEN, or the system would resume with helpers permanently refused.
    assert_eq!(gate::usermodehelper_disable(), EAGAIN);
    assert!(!gate::usermodehelper_disabled());
    gate::helper_unlock();
    assert_eq!(gate::running_helpers(), 0);
}

#[test]
fn the_in_flight_count_never_wraps() {
    let _g = serialize();
    gate::reset_for_test();
    // An unbalanced release must not roll the counter to u32::MAX, which would
    // make every later disable time out.
    gate::helper_unlock();
    assert_eq!(gate::running_helpers(), 0);
    gate::helper_lock();
    gate::helper_lock();
    assert_eq!(gate::running_helpers(), 2);
    gate::helper_unlock();
    gate::helper_unlock();
    gate::helper_unlock();
    assert_eq!(gate::running_helpers(), 0);
}
