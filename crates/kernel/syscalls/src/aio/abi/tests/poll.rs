// The wake arithmetic an IOCB_CMD_POLL request is completed by.

use crate::aio_abi::poll::*;

#[test]
fn interest_always_carries_error_and_hangup() {
    assert_eq!(request_events(0), POLL_ALWAYS);
    assert_eq!(request_events(vfs::POLL_IN as u16) & vfs::POLL_IN, vfs::POLL_IN);
    assert_eq!(request_events(vfs::POLL_IN as u16) & vfs::POLL_ERR, vfs::POLL_ERR);
    assert_eq!(request_events(vfs::POLL_IN as u16) & vfs::POLL_HUP, vfs::POLL_HUP);
    // Nothing outside the request plus the always-reported pair.
    assert_eq!(request_events(vfs::POLL_IN as u16), vfs::POLL_IN | POLL_ALWAYS);
}

#[test]
fn a_keyed_wake_completes_from_the_published_mask() {
    let want = request_events(vfs::POLL_IN as u16);
    // `live` must be ignored entirely when a key is present — reading the file
    // again inside the source's wake path is what this avoids.
    assert_eq!(wake_mask(vfs::POLL_IN, 0, want), vfs::POLL_IN);
    assert_eq!(wake_mask(vfs::POLL_IN, vfs::POLL_OUT, want), vfs::POLL_IN);
}

#[test]
fn a_keyed_wake_for_an_uninteresting_event_leaves_the_request_pending() {
    let want = request_events(vfs::POLL_IN as u16);
    assert_eq!(wake_mask(vfs::POLL_OUT, 0, want), 0);
    // Even when the file happens to be readable: the wake did not say so, and
    // a later keyed or keyless wake will.
    assert_eq!(wake_mask(vfs::POLL_OUT, vfs::POLL_IN, want), 0);
}

#[test]
fn hangup_and_error_complete_a_request_that_never_asked_for_them() {
    let want = request_events(vfs::POLL_IN as u16);
    assert_eq!(wake_mask(vfs::POLL_HUP, 0, want), vfs::POLL_HUP);
    assert_eq!(wake_mask(vfs::POLL_ERR, 0, want), vfs::POLL_ERR);
}

#[test]
fn a_keyless_wake_falls_back_to_the_files_current_mask() {
    let want = request_events(vfs::POLL_IN as u16);
    assert_eq!(wake_mask(0, vfs::POLL_IN, want), vfs::POLL_IN);
    assert_eq!(wake_mask(0, vfs::POLL_OUT, want), 0);
    assert_eq!(wake_mask(0, 0, want), 0);
    // A file reporting several conditions reports only the requested subset.
    assert_eq!(wake_mask(0, vfs::POLL_IN | vfs::POLL_OUT, want), vfs::POLL_IN);
}

#[test]
fn the_result_never_carries_bits_outside_the_request() {
    let want = request_events(vfs::POLL_IN as u16);
    for key in [0u32, vfs::POLL_IN, vfs::POLL_OUT, vfs::POLL_PRI, !0] {
        for live in [0u32, vfs::POLL_OUT, !0] {
            assert_eq!(wake_mask(key, live, want) & !want, 0);
        }
    }
}
