//! Terminal-input accumulation: what is audited, when it is flushed, and what
//! the flush carries. These encode the verified ABI so the contract is
//! re-checkable without reading another kernel.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

const TTY: Devno = Devno { major: 136, minor: 1 };
const OTHER: Devno = Devno { major: 4, minor: 2 };
const TG: u32 = 42;

/// A group marked for auditing, echoing a canonical line.
fn audited() -> TtyAudit {
    let mut t = TtyAudit::new();
    t.set_mask(TG, AUDIT_TTY_ENABLE);
    t
}

fn add(t: &mut TtyAudit, data: &[u8]) -> Vec<Push> {
    t.add_data(TG, TTY, true, true, false, data)
}

// ---- what is audited -----------------------------------------------------

#[test]
fn a_group_with_no_mask_accumulates_nothing_and_holds_no_state() {
    let mut t = TtyAudit::new();
    assert!(t.add_data(TG, TTY, true, true, false, b"secret").is_empty());
    assert_eq!(t.tracked(), 0, "an unaudited group must not cost a map entry");
    assert_eq!(t.exit(TG), None);
}

#[test]
fn the_enable_bit_alone_decides_whether_input_is_accumulated() {
    assert!(!TtyAudit::audits(0, 1, false, true, true));
    assert!(TtyAudit::audits(AUDIT_TTY_ENABLE, 1, false, true, true));
    // The password bit without the enable bit audits nothing.
    assert!(!TtyAudit::audits(AUDIT_TTY_LOG_PASSWD, 1, false, true, true));
}

/// Canonical input with echo off is a password prompt; it is audited only when
/// the separate bit says so.
#[test]
fn echo_off_canonical_input_needs_the_password_bit() {
    assert!(!TtyAudit::audits(AUDIT_TTY_ENABLE, 1, false, true, false));
    assert!(TtyAudit::audits(AUDIT_TTY_ENABLE | AUDIT_TTY_LOG_PASSWD, 1, false, true, false));
    // Raw mode with echo off is not a password prompt and stays audited.
    assert!(TtyAudit::audits(AUDIT_TTY_ENABLE, 1, false, false, false));
}

#[test]
fn a_pty_master_is_never_audited_and_an_empty_read_is_not_an_event() {
    assert!(!TtyAudit::audits(AUDIT_TTY_ENABLE, 1, true, true, true));
    assert!(!TtyAudit::audits(AUDIT_TTY_ENABLE, 0, false, true, true));
    let mut t = audited();
    assert!(t.add_data(TG, TTY, true, true, true, b"ls\n").is_empty());
    assert_eq!(t.exit(TG), None, "a refused read leaves nothing buffered");
}

// ---- when it is flushed --------------------------------------------------

#[test]
fn ordinary_input_accumulates_without_producing_a_record() {
    let mut t = audited();
    assert!(add(&mut t, b"who").is_empty());
    assert!(add(&mut t, b"ami\n").is_empty());
}

#[test]
fn a_full_buffer_flushes_and_an_oversized_read_flushes_more_than_once() {
    let mut t = audited();
    let big = vec![b'x'; TTY_AUDIT_BUF_SIZE * 2 + 3];
    let out = add(&mut t, &big);
    assert_eq!(out.len(), 2, "one record per filled buffer");
    assert_eq!(out[0].data.len(), TTY_AUDIT_BUF_SIZE);
    assert_eq!(out[1].data.len(), TTY_AUDIT_BUF_SIZE);
    // The remainder stays buffered until something else flushes it.
    assert_eq!(t.exit(TG).expect("tail").data, vec![b'x'; 3]);
}

#[test]
fn a_different_terminal_flushes_what_the_previous_one_left() {
    let mut t = audited();
    add(&mut t, b"abc");
    let out = t.add_data(TG, OTHER, true, true, false, b"def");
    assert_eq!(out, vec![Push { dev: TTY, data: b"abc".to_vec() }]);
    assert_eq!(t.exit(TG).expect("second terminal"),
               Push { dev: OTHER, data: b"def".to_vec() });
}

#[test]
fn a_canonical_mode_change_flushes_because_a_record_carries_one_mode() {
    let mut t = audited();
    add(&mut t, b"abc");
    let out = t.add_data(TG, TTY, false, true, false, b"d");
    assert_eq!(out, vec![Push { dev: TTY, data: b"abc".to_vec() }]);
}

#[test]
fn an_explicit_push_flushes_a_partial_line_and_reports_nothing_twice() {
    let mut t = audited();
    add(&mut t, b"id\n");
    assert_eq!(t.push(TG).expect("audited"), Some(Push { dev: TTY, data: b"id\n".to_vec() }));
    assert_eq!(t.push(TG).expect("audited"), None);
}

#[test]
fn pushing_an_unaudited_group_is_eperm_not_an_empty_flush() {
    let mut t = TtyAudit::new();
    assert_eq!(t.push(TG), Err(Errno::Eperm));
}

// ---- exit ----------------------------------------------------------------

/// The row this whole subsystem exists to close: a dying thread group's
/// unflushed tail is written, not dropped.
#[test]
fn exit_flushes_the_tail_of_the_session() {
    let mut t = audited();
    add(&mut t, b"rm -rf /");
    assert_eq!(t.exit(TG), Some(Push { dev: TTY, data: b"rm -rf /".to_vec() }));
}

#[test]
fn exit_forgets_the_group_so_a_reused_id_starts_clean() {
    let mut t = audited();
    add(&mut t, b"abc");
    t.exit(TG);
    assert_eq!(t.tracked(), 0);
    assert_eq!(t.mask(TG), 0);
    assert!(t.add_data(TG, TTY, true, true, false, b"xyz").is_empty(),
            "a recycled group id is not audited until a daemon says so");
    assert_eq!(t.exit(TG), None, "and carries none of the dead group's bytes");
}

#[test]
fn exit_of_a_group_that_read_nothing_produces_no_record() {
    let mut t = audited();
    assert_eq!(t.exit(TG), None);
}

// ---- fork ----------------------------------------------------------------

#[test]
fn a_new_thread_group_inherits_the_mask_but_not_the_buffer() {
    const CHILD: u32 = 43;
    let mut t = audited();
    add(&mut t, b"parent");
    t.fork(TG, CHILD);
    assert_eq!(t.mask(CHILD), AUDIT_TTY_ENABLE);
    assert_eq!(t.exit(CHILD), None, "the child starts with an empty transcript");
    assert_eq!(t.exit(TG).expect("parent tail").data, b"parent".to_vec());
}

#[test]
fn forking_from_an_unaudited_parent_creates_no_state() {
    let mut t = TtyAudit::new();
    t.fork(TG, 43);
    assert_eq!(t.tracked(), 0);
    assert_eq!(t.mask(43), 0);
}

// ---- the enable state ----------------------------------------------------

/// A flush empties the buffer whether or not audit is switched on; what the
/// enable state decides is only whether a record is written.
#[test]
fn a_flush_writes_a_record_only_while_audit_is_on() {
    assert!(!push_logs(crate::uapi::AUDIT_OFF));
    assert!(push_logs(crate::uapi::AUDIT_ON));
    assert!(push_logs(crate::uapi::AUDIT_LOCKED));
}

// ---- the status struct ---------------------------------------------------

#[test]
fn the_status_struct_is_two_u32_enabled_then_log_passwd() {
    assert_eq!(encode_status(0), [0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(encode_status(AUDIT_TTY_ENABLE), [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(encode_status(AUDIT_TTY_LOG_PASSWD), [0, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(encode_status(AUDIT_TTY_MASK_ALL), [1, 0, 0, 0, 1, 0, 0, 0]);
}

#[test]
fn a_status_field_holding_anything_but_zero_or_one_is_refused() {
    assert_eq!(decode_status(&[2, 0, 0, 0, 0, 0, 0, 0]), Err(Errno::Einval));
    assert_eq!(decode_status(&[0, 0, 0, 0, 2, 0, 0, 0]), Err(Errno::Einval));
}

#[test]
fn a_short_status_payload_is_zero_filled_rather_than_refused() {
    assert_eq!(decode_status(&[1, 0, 0, 0]), Ok(AUDIT_TTY_ENABLE));
    assert_eq!(decode_status(&[]), Ok(0));
}

#[test]
fn a_status_round_trips_through_both_directions() {
    for m in [0, AUDIT_TTY_ENABLE, AUDIT_TTY_LOG_PASSWD, AUDIT_TTY_MASK_ALL] {
        assert_eq!(decode_status(&encode_status(m)), Ok(m));
    }
}

// ---- the live instance ---------------------------------------------------

/// The read path's gate is a plain flag, so a system with no audited group
/// pays one load. It must be off until a mask is set.
#[test]
fn the_live_read_path_gate_is_off_until_a_group_is_marked() {
    assert!(!armed(), "no group is marked at rest");
    let old = set_status(7777, AUDIT_TTY_ENABLE);
    assert_eq!(old, 0);
    assert!(armed());
    assert_eq!(status(7777), AUDIT_TTY_ENABLE);
    assert_eq!(set_status(7777, 0), AUDIT_TTY_ENABLE);
    assert!(!armed(), "clearing the last mask disarms the read path");
}
