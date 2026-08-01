// Layer-mask algebra. These cases pin the semantics every access decision is
// built on: independent layers, union along a walk, and the reparenting
// comparison that decides permission-error versus cross-device-error.

use super::*;

fn masks(pairs: &[(usize, AccessMask)]) -> LayerMasks {
    let mut m = LayerMasks::default();
    for (i, a) in pairs { m.layers[*i] = *a; }
    m
}

#[test]
fn a_request_no_layer_handles_is_not_filtered() {
    let (m, req) = LayerMasks::init(&[ACCESS_FS_READ_FILE], ACCESS_FS_WRITE_FILE);
    assert_eq!(req, 0);
    assert!(m.all_clear());
}

#[test]
fn an_empty_request_is_never_filtered() {
    let (_, req) = LayerMasks::init(&[MASK_ACCESS_FS], 0);
    assert_eq!(req, 0);
}

#[test]
fn each_layer_only_tracks_the_rights_it_handles() {
    let (m, req) = LayerMasks::init(&[ACCESS_FS_READ_FILE, ACCESS_FS_WRITE_FILE],
                                    ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE);
    assert_eq!(req, ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE);
    assert_eq!(m.layers[0], ACCESS_FS_READ_FILE);
    assert_eq!(m.layers[1], ACCESS_FS_WRITE_FILE);
}

#[test]
fn every_layer_must_be_satisfied_independently() {
    let (mut m, _) = LayerMasks::init(&[ACCESS_FS_READ_FILE, ACCESS_FS_READ_FILE],
                                      ACCESS_FS_READ_FILE);
    // Only the first layer grants it: the request is still outstanding.
    assert!(!m.unmask(&[ACCESS_FS_READ_FILE, 0]));
    assert!(m.unmask(&[0, ACCESS_FS_READ_FILE]));
}

#[test]
fn rights_union_along_the_walk_within_a_layer() {
    // A right granted higher in the hierarchy plus one granted lower jointly
    // satisfy a request for both.
    let (mut m, _) = LayerMasks::init(&[ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE],
                                      ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE);
    assert!(!m.unmask(&[ACCESS_FS_EXECUTE]));
    assert!(m.unmask(&[ACCESS_FS_READ_FILE]));
}

#[test]
fn narrowing_to_the_real_request_drops_the_wider_bookkeeping() {
    let mut m = masks(&[(0, ACCESS_FS_EXECUTE), (1, ACCESS_FS_WRITE_FILE)]);
    assert!(!m.scope_to_request(ACCESS_FS_EXECUTE));
    assert_eq!(m.layers[0], ACCESS_FS_EXECUTE);
    assert_eq!(m.layers[1], 0);

    let mut m = masks(&[(0, ACCESS_FS_EXECUTE), (1, ACCESS_FS_WRITE_FILE)]);
    assert!(m.scope_to_request(0));
    assert_eq!(m.layers[0], 0);

    let mut m = LayerMasks::default();
    assert!(m.scope_to_request(ACCESS_FS_EXECUTE));
}

#[test]
fn an_outstanding_reparent_right_alone_is_a_cross_device_answer() {
    // Reporting a permission error there would tell a caller the move can never
    // work, when copying to the destination may still be allowed.
    let m = masks(&[(0, ACCESS_FS_REFER)]);
    assert!(!m.is_eacces(ACCESS_FS_REFER));
    assert!(!m.is_eacces(ACCESS_FS_EXECUTE));
    let m = LayerMasks::default();
    assert!(!m.is_eacces(ACCESS_FS_REFER));
}

#[test]
fn any_other_outstanding_right_is_a_permission_answer() {
    let m = masks(&[(0, ACCESS_FS_WRITE_FILE)]);
    assert!(m.is_eacces(ACCESS_FS_WRITE_FILE));
    assert!(!m.is_eacces(ACCESS_FS_EXECUTE));
    let m = masks(&[(0, ACCESS_FS_REFER | ACCESS_FS_WRITE_FILE)]);
    assert!(m.is_eacces(ACCESS_FS_WRITE_FILE | ACCESS_FS_REFER));
}

#[test]
fn a_move_into_an_equally_restricted_hierarchy_is_allowed() {
    let none = LayerMasks::default();
    let x0 = masks(&[(0, ACCESS_FS_EXECUTE)]);
    // Destination restricts execute, source did not restrict the child: fine.
    assert!(may_refer(&x0, &none, &x0, true));
    assert!(may_refer(&none, &none, &x0, true));
}

#[test]
fn a_move_that_would_gain_a_right_is_refused() {
    let none = LayerMasks::default();
    let x0 = masks(&[(0, ACCESS_FS_EXECUTE)]);
    // Source withheld execute from the child; destination does not: gaining it.
    assert!(!may_refer(&x0, &x0, &none, true));
}

#[test]
fn a_non_directory_child_ignores_directory_shaped_restrictions() {
    let mk = masks(&[(0, ACCESS_FS_MAKE_REG)]);
    let none = LayerMasks::default();
    // Creation rights are meaningless for a file, so they cannot make a move an
    // escalation.
    assert!(may_refer(&mk, &mk, &none, false));
    assert!(!may_refer(&mk, &mk, &none, true));
}

#[test]
fn restrictions_on_different_layers_do_not_cancel_out() {
    let x0 = masks(&[(0, ACCESS_FS_EXECUTE)]);
    let x1 = masks(&[(1, ACCESS_FS_EXECUTE)]);
    assert!(!may_refer(&x0, &x0, &x1, true));
}

#[test]
fn an_exchange_is_checked_in_both_directions() {
    let none = LayerMasks::default();
    let x0 = masks(&[(0, ACCESS_FS_EXECUTE)]);
    // One direction fine, the other an escalation: the exchange is refused.
    assert!(no_more_access(&x0, &none, true, &x0, Some(&none), true));
    assert!(!no_more_access(&none, &none, true, &x0, Some(&x0), true));
    // Without a second child only one direction is examined.
    assert!(no_more_access(&none, &none, true, &x0, None, true));
}
