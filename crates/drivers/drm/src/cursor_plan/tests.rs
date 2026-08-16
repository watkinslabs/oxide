// The contract these pin was read off the legacy cursor ioctl's admission
// ladder before any of it was written. Each refusal below is a DIFFERENT errno
// upstream, and every one of them was EINVAL here.

use syscall::errno::Errno;

use super::{CursorPlan, CursorSupport, plan};
use crate::{DRM_MODE_CURSOR_BO, DRM_MODE_CURSOR_MOVE};

const BOTH: CursorSupport = CursorSupport { set: true,  mov: true  };
const NONE: CursorSupport = CursorSupport { set: false, mov: false };

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[test]
fn no_flags_at_all_is_a_malformed_request() {
    assert_eq!(plan(0, true, BOTH), Err(errno(Errno::Einval)));
}

#[test]
fn a_flag_outside_the_two_defined_ones_is_a_malformed_request() {
    assert_eq!(plan(DRM_MODE_CURSOR_BO | 0x4, true, BOTH), Err(errno(Errno::Einval)));
}

#[test]
fn flag_validity_is_decided_before_the_crtc_is_looked_up() {
    // An unknown CRTC would be ENOENT, but a malformed flag word outranks it.
    assert_eq!(plan(0, false, BOTH), Err(errno(Errno::Einval)));
}

#[test]
fn an_unknown_crtc_is_not_found_rather_than_invalid() {
    assert_eq!(plan(DRM_MODE_CURSOR_BO, false, BOTH), Err(errno(Errno::Enoent)));
}

#[test]
fn the_crtc_is_resolved_before_cursor_support_is_consulted() {
    // Both would refuse; the identity failure is the one reported.
    assert_eq!(plan(DRM_MODE_CURSOR_BO, false, NONE), Err(errno(Errno::Enoent)));
}

#[test]
fn an_image_request_on_a_card_with_no_cursor_image_support_is_enxio() {
    let no_set = CursorSupport { set: false, mov: true };
    assert_eq!(plan(DRM_MODE_CURSOR_BO, true, no_set), Err(errno(Errno::Enxio)));
}

#[test]
fn a_move_on_a_card_with_no_move_support_is_efault() {
    let no_move = CursorSupport { set: true, mov: false };
    assert_eq!(plan(DRM_MODE_CURSOR_MOVE, true, no_move), Err(errno(Errno::Efault)));
}

#[test]
fn the_image_refusal_outranks_the_move_refusal_when_both_are_asked_for() {
    assert_eq!(plan(DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE, true, NONE), Err(errno(Errno::Enxio)));
}

#[test]
fn the_three_refusals_are_three_different_values() {
    let no_set  = CursorSupport { set: false, mov: true };
    let no_move = CursorSupport { set: true,  mov: false };
    let unknown_crtc = plan(DRM_MODE_CURSOR_BO, false, BOTH).unwrap_err();
    let no_image     = plan(DRM_MODE_CURSOR_BO, true, no_set).unwrap_err();
    let no_movement  = plan(DRM_MODE_CURSOR_MOVE, true, no_move).unwrap_err();
    assert_ne!(unknown_crtc, no_image);
    assert_ne!(no_image, no_movement);
    assert_ne!(unknown_crtc, no_movement);
}

#[test]
fn an_image_request_is_admitted_as_an_image_request_alone() {
    assert_eq!(plan(DRM_MODE_CURSOR_BO, true, BOTH), Ok(CursorPlan { set_bo: true, mov: false }));
}

#[test]
fn a_move_request_is_admitted_as_a_move_alone() {
    assert_eq!(plan(DRM_MODE_CURSOR_MOVE, true, BOTH), Ok(CursorPlan { set_bo: false, mov: true }));
}

#[test]
fn one_request_carrying_both_flags_asks_for_both_operations() {
    // The move is not dropped because an image came with it.
    assert_eq!(plan(DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE, true, BOTH),
               Ok(CursorPlan { set_bo: true, mov: true }));
}

#[test]
fn a_move_is_admitted_without_any_image_having_been_published_first() {
    // Support, not published state, decides admission; a card that can move
    // its cursor accepts the move whether or not an image is up.
    assert_eq!(plan(DRM_MODE_CURSOR_MOVE, true, BOTH), Ok(CursorPlan { set_bo: false, mov: true }));
}
