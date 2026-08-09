// Wire-value round trip for `CallKind`. The queue stores the kind as an
// opaque `u32`, so a kind whose encode and decode disagree would deliver the
// wrong handler on a remote CPU with nothing local to notice.

use super::*;

#[test]
fn every_kind_round_trips_through_its_wire_value() {
    for k in [CallKind::TlbFlush, CallKind::LdtReload] {
        assert_eq!(CallKind::from_u32(k.as_u32()), Some(k), "round trip failed for {:?}", k);
    }
}

#[test]
fn kinds_have_distinct_wire_values() {
    assert_ne!(CallKind::TlbFlush.as_u32(), CallKind::LdtReload.as_u32());
}

#[test]
fn zero_is_never_a_kind_so_an_empty_slot_cannot_decode() {
    assert_eq!(CallKind::from_u32(0), None);
    assert_eq!(CallKind::from_u32(u32::MAX), None);
}

#[test]
fn the_hook_is_absent_in_the_hosted_harness_and_calls_are_no_ops() {
    assert!(!available());
    // Must not panic and must not require an arch.
    call_function_many(0xFF, CallKind::TlbFlush, ALL, true);
}
