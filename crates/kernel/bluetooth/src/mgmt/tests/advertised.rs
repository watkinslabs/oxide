//! What `READ_COMMANDS` reports.

use super::*;
use crate::mgmt::table;

#[test]
fn the_two_discovery_commands_are_assumed_not_announced() {
    assert!(!ADVERTISED_COMMANDS.contains(&MGMT_OP_READ_VERSION));
    assert!(!ADVERTISED_COMMANDS.contains(&MGMT_OP_READ_COMMANDS));
    // Everything else with a handler is announced.
    for op in 3..=MGMT_OP_MAX {
        assert!(ADVERTISED_COMMANDS.contains(&op), "opcode {op:#06x} is not announced");
    }
}

#[test]
fn every_announced_command_has_a_handler() {
    for op in ADVERTISED_COMMANDS { assert!(table::is_implemented(op), "opcode {op:#06x}"); }
    for op in UNTRUSTED_COMMANDS { assert!(table::is_implemented(op), "opcode {op:#06x}"); }
}

/// The untrusted list must not name a command an untrusted socket would then be
/// refused — the announcement and the admission decision are the same fact.
#[test]
fn the_untrusted_list_matches_the_untrusted_flag() {
    for op in 1..=MGMT_OP_MAX {
        let flagged = table::lookup(op).is_some_and(|s| s.untrusted());
        let announced = UNTRUSTED_COMMANDS.contains(&op);
        // The two discovery commands are untrusted-safe but never announced.
        let assumed = op == MGMT_OP_READ_VERSION || op == MGMT_OP_READ_COMMANDS;
        assert_eq!(announced, flagged && !assumed, "opcode {op:#06x}");
    }
}

#[test]
fn the_replies_are_not_announced_as_events() {
    assert!(!ADVERTISED_EVENTS.contains(&MGMT_EV_CMD_COMPLETE));
    assert!(!ADVERTISED_EVENTS.contains(&MGMT_EV_CMD_STATUS));
    assert!(!UNTRUSTED_EVENTS.contains(&MGMT_EV_CMD_COMPLETE));
}

/// The mesh reports exist but are not announced.
#[test]
fn the_mesh_events_are_not_announced() {
    assert!(!ADVERTISED_EVENTS.contains(&MGMT_EV_MESH_DEVICE_FOUND));
    assert!(!ADVERTISED_EVENTS.contains(&MGMT_EV_MESH_PACKET_CMPLT));
}

/// An untrusted socket learns about presence and identity, never about keys,
/// pairing, or what the radio has seen.
#[test]
fn the_untrusted_event_list_leaks_nothing_sensitive() {
    for ev in [
        MGMT_EV_NEW_LINK_KEY, MGMT_EV_NEW_LONG_TERM_KEY, MGMT_EV_NEW_IRK, MGMT_EV_NEW_CSRK,
        MGMT_EV_DEVICE_FOUND, MGMT_EV_DEVICE_CONNECTED, MGMT_EV_USER_CONFIRM_REQUEST,
        MGMT_EV_PASSKEY_NOTIFY, MGMT_EV_PIN_CODE_REQUEST,
    ] {
        assert!(!UNTRUSTED_EVENTS.contains(&ev), "event {ev:#06x} must not be announced");
    }
    // And every untrusted event is one a trusted socket also gets.
    for ev in UNTRUSTED_EVENTS { assert!(ADVERTISED_EVENTS.contains(&ev), "{ev:#06x}"); }
}

#[test]
fn no_list_repeats_an_entry() {
    for list in [&ADVERTISED_COMMANDS[..], &UNTRUSTED_COMMANDS[..],
                 &ADVERTISED_EVENTS[..], &UNTRUSTED_EVENTS[..]] {
        for (i, a) in list.iter().enumerate() {
            for b in &list[i + 1..] { assert_ne!(a, b, "{a:#06x} appears twice"); }
        }
    }
}

#[test]
fn the_response_is_two_counts_then_both_lists() {
    let buf = encode_read_commands(true);
    let n_cmd = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let n_ev = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    assert_eq!(n_cmd, ADVERTISED_COMMANDS.len());
    assert_eq!(n_ev, ADVERTISED_EVENTS.len());
    assert_eq!(buf.len(), 4 + 2 * (n_cmd + n_ev));
    assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), ADVERTISED_COMMANDS[0]);
    let ev0 = 4 + 2 * n_cmd;
    assert_eq!(u16::from_le_bytes([buf[ev0], buf[ev0 + 1]]), ADVERTISED_EVENTS[0]);
}

#[test]
fn an_untrusted_socket_is_told_about_a_smaller_surface() {
    let buf = encode_read_commands(false);
    assert_eq!(u16::from_le_bytes([buf[0], buf[1]]) as usize, UNTRUSTED_COMMANDS.len());
    assert_eq!(u16::from_le_bytes([buf[2], buf[3]]) as usize, UNTRUSTED_EVENTS.len());
    assert!(buf.len() < encode_read_commands(true).len());
}
