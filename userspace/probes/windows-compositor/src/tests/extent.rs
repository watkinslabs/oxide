use super::{notified, surface_survives};
use syscall::nt_compositor::MAX_DIMENSION;

#[test]
fn a_server_reported_size_replaces_the_one_the_client_asked_for() {
    assert_eq!(notified((128, 128), (96, 64)), Some((96, 64)));
    assert_eq!(notified((128, 128), (128, 64)), Some((128, 64)));
}

#[test]
fn a_notification_that_reports_the_size_already_held_changes_nothing() {
    assert_eq!(notified((128, 128), (128, 128)), None);
}

#[test]
fn a_size_no_window_can_have_is_not_adopted() {
    assert_eq!(notified((128, 128), (0, 64)), None);
    assert_eq!(notified((128, 128), (96, 0)), None);
    assert_eq!(notified((128, 128), (MAX_DIMENSION + 1, 64)), None);
    assert_eq!(notified((128, 128), (96, MAX_DIMENSION + 1)), None);
    assert_eq!(notified((128, 128), (MAX_DIMENSION, MAX_DIMENSION)), Some((MAX_DIMENSION, MAX_DIMENSION)));
}

#[test]
fn a_surface_only_survives_the_extent_it_was_captured_for() {
    assert!(surface_survives((96, 64), (96, 64)));
    assert!(!surface_survives((128, 128), (96, 64)));
    assert!(!surface_survives((96, 64), (96, 65)));
}

#[test]
fn configure_serial_order_survives_request_counter_wrap() {
    use super::obsolete_configure;
    assert!(obsolete_configure(9, 10));
    assert!(!obsolete_configure(10, 10));
    assert!(!obsolete_configure(11, 10));
    assert!(obsolete_configure(u32::MAX, 0));
    assert!(!obsolete_configure(0, u32::MAX));
}
