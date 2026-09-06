use super::*;

#[test]
fn absent_endpoint_is_only_the_declared_sentinel() {
    assert_eq!(classify(NO_ENDPOINT), Endpoint::Absent);
    assert_eq!(NO_ENDPOINT, -1);
}

#[test]
fn other_negative_descriptors_reject_the_handoff() {
    for raw in [-2, -3, i32::MIN] {
        assert_eq!(classify(raw), Endpoint::Rejected(0xc000_000d), "raw={raw}");
    }
}

#[test]
fn nonnegative_descriptors_are_resolved_in_the_caller_table() {
    for raw in [0, 1, 3, i32::MAX] {
        assert_eq!(classify(raw), Endpoint::Descriptor(raw), "raw={raw}");
    }
}

#[test]
fn a_launch_without_an_endpoint_refuses_rather_than_reporting_an_empty_registry() {
    assert_eq!(no_endpoint_status(), 0xc000_0022);
    assert_ne!(no_endpoint_status(), 0);
    assert_ne!(no_endpoint_status(), 0xc000_0034);
}

#[test]
fn a_descriptor_that_is_not_a_socket_is_a_parameter_error() {
    assert_eq!(not_a_socket_status(), 0xc000_000d);
}
