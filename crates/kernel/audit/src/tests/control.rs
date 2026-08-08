use alloc::vec::Vec;

use super::*;
use crate::config::Field;
use crate::config::Config;
use crate::wire::Status;

const ROOT: Caller = Caller {
    init_user_ns: true, init_pid_ns: true, cap_audit_control: true, cap_audit_write: true,
};

fn req<'a>(msg_type: u16, data: &'a [u8], caller_pid: u32) -> Request<'a> {
    Request { msg_type, data, caller: ROOT, caller_pid, port_id: 77, route: 5,
              realtime_ns: 1_000_000_000, now_ms: 1_000 }
}

fn status_bytes(mask: u32, f: impl FnOnce(&mut Status)) -> Vec<u8> {
    let mut s = Status { mask, ..Status::default() };
    f(&mut s);
    s.encode()
}

fn on() -> AuditState {
    let mut s = AuditState::new();
    crate::config::set(&mut s.cfg, Field::Enabled, crate::uapi::AUDIT_ON).unwrap();
    s
}

#[test]
fn a_status_query_reports_the_live_system() {
    let mut s = on();
    crate::config::set(&mut s.cfg, Field::RateLimit, 9).unwrap();
    let Reply::Status(bytes) = handle(&mut s, &req(AUDIT_GET, &[], 1)) else {
        panic!("AUDIT_GET answers with a status body")
    };
    let got = Status::decode(&bytes);
    assert_eq!(got.enabled, crate::uapi::AUDIT_ON);
    assert_eq!(got.rate_limit, 9);
    assert_eq!(got.pid, 0);
    assert_eq!(got.feature_bitmap, AUDIT_FEATURE_BITMAP_ALL);
}

#[test]
fn an_unprivileged_caller_is_refused_before_anything_changes() {
    let mut s = AuditState::new();
    let data = status_bytes(AUDIT_STATUS_ENABLED, |st| st.enabled = 1);
    let mut r = req(AUDIT_SET, &data, 1);
    r.caller = Caller { cap_audit_control: false, ..ROOT };
    assert_eq!(handle(&mut s, &r), Reply::Ack(-(Errno::Eperm.as_i32())));
    assert_eq!(s.cfg, Config::default(), "a refused request changes nothing");
}

#[test]
fn an_unknown_status_bit_is_refused() {
    let mut s = AuditState::new();
    let data = status_bytes(!AUDIT_STATUS_ALL, |_| {});
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 1)), Reply::Ack(-(Errno::Einval.as_i32())));
    assert_eq!(s.cfg, Config::default());
}

#[test]
fn enabling_audit_takes_effect_and_records_the_change() {
    let mut s = AuditState::new();
    let data = status_bytes(AUDIT_STATUS_ENABLED, |st| st.enabled = crate::uapi::AUDIT_ON);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 1)), Reply::Ack(0));
    assert_eq!(s.cfg.enabled, crate::uapi::AUDIT_ON);
    // The system was OFF when the change was applied, so nothing was recorded:
    // an audit log that starts before audit does would have no consumer.
    assert_eq!(s.backlog.hold_len(), 0);
}

/// A configuration change made while audit is running IS itself an audited
/// event — including a refused one, which is exactly what a log exists for.
#[test]
fn a_refused_configuration_change_is_recorded_with_its_outcome() {
    let mut s = on();
    crate::config::set(&mut s.cfg, Field::Enabled, crate::uapi::AUDIT_LOCKED).unwrap();
    let data = status_bytes(AUDIT_STATUS_RATE_LIMIT, |st| st.rate_limit = 5);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 42)), Reply::Ack(-(Errno::Eperm.as_i32())));
    assert_eq!(s.cfg.rate_limit, 0);
    assert_eq!(s.backlog.hold_len(), 1);
    let r = s.backlog.pop_hold_for_test().expect("the refusal was recorded");
    assert_eq!(r.ty, AUDIT_CONFIG_CHANGE);
    let t = core::str::from_utf8(&r.text).unwrap();
    assert!(t.contains("op=set audit_rate_limit=5 old=0 pid=42 res=0"), "{t}");
}

#[test]
fn a_successful_configuration_change_is_recorded_as_allowed() {
    let mut s = on();
    let data = status_bytes(AUDIT_STATUS_BACKLOG_LIMIT, |st| st.backlog_limit = 256);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 42)), Reply::Ack(0));
    assert_eq!(s.cfg.backlog_limit, 256);
    let r = s.backlog.pop_hold_for_test().expect("the change was recorded");
    let t = core::str::from_utf8(&r.text).unwrap();
    assert!(t.contains("op=set audit_backlog_limit=256 old=64 pid=42 res=1"), "{t}");
}

/// The wait-time field only exists in the full-length struct; asking to set a
/// field that was not supplied is a malformed request.
#[test]
fn setting_the_backlog_wait_time_needs_the_full_struct() {
    let mut s = on();
    let mut short = status_bytes(AUDIT_STATUS_BACKLOG_WAIT_TIME, |st| st.backlog_wait_time = 5);
    short.truncate(AUDIT_STATUS_LEN - 4);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &short, 1)), Reply::Ack(-(Errno::Einval.as_i32())));
    let full = status_bytes(AUDIT_STATUS_BACKLOG_WAIT_TIME, |st| st.backlog_wait_time = 5);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &full, 1)), Reply::Ack(0));
    assert_eq!(s.cfg.backlog_wait_time, 5);
}

#[test]
fn a_consumer_registers_itself_and_takes_delivery_of_the_held_records() {
    let mut s = on();
    for _ in 0..3 {
        crate::emit::admit(&mut s, crate::record::build(1331, 0, 1, b"x"), 0).unwrap();
    }
    assert_eq!(s.backlog.hold_len(), 3);
    let data = status_bytes(AUDIT_STATUS_PID, |st| st.pid = 500);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 500)), Reply::Ack(0));
    assert_eq!(s.consumer.pid, 500);
    assert_eq!(s.consumer.port_id, 77);
    assert_eq!(s.consumer.route, 5);
    assert_eq!(s.backlog.hold_len(), 0);
    assert!(s.backlog.len() >= 3, "the held history became deliverable");
}

#[test]
fn a_second_daemon_cannot_displace_a_live_one() {
    let mut s = on();
    let first = status_bytes(AUDIT_STATUS_PID, |st| st.pid = 500);
    handle(&mut s, &req(AUDIT_SET, &first, 500));
    let second = status_bytes(AUDIT_STATUS_PID, |st| st.pid = 600);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &second, 600)), Reply::Ack(-(Errno::Eexist.as_i32())));
    assert_eq!(s.consumer.pid, 500);
    let steal = status_bytes(AUDIT_STATUS_PID, |st| st.pid = 0);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &steal, 600)), Reply::Ack(-(Errno::Eacces.as_i32())));
    assert_eq!(s.consumer.pid, 500);
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &steal, 500)), Reply::Ack(0));
    assert!(!s.consumer.registered());
}

/// Reading the lost counter is a whole-mask request and answers with the
/// count, which the netlink layer returns in the acknowledgement's value.
#[test]
fn reading_the_lost_counter_returns_it_and_clears_it() {
    let mut s = on();
    s.cfg.count_lost();
    s.cfg.count_lost();
    let data = status_bytes(AUDIT_STATUS_LOST, |_| {});
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 1)), Reply::Ack(2));
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 1)), Reply::Ack(0));
}

#[test]
fn reading_the_backlog_wait_time_actual_returns_it_and_clears_it() {
    let mut s = on();
    s.cfg.backlog_wait_time_actual = 17;
    let data = status_bytes(AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL, |_| {});
    assert_eq!(handle(&mut s, &req(AUDIT_SET, &data, 1)), Reply::Ack(17));
    assert_eq!(s.cfg.backlog_wait_time_actual, 0);
}

#[test]
fn a_features_query_answers_with_the_features_struct() {
    let mut s = on();
    let Reply::Features(bytes) = handle(&mut s, &req(AUDIT_GET_FEATURE, &[], 1)) else {
        panic!("AUDIT_GET_FEATURE answers with a features body")
    };
    assert_eq!(bytes.len(), AUDIT_FEATURES_LEN);
}

#[test]
fn a_short_features_request_is_refused_rather_than_zero_extended() {
    let mut s = on();
    assert_eq!(handle(&mut s, &req(AUDIT_SET_FEATURE, &[0u8; 8], 1)),
        Reply::Ack(-(Errno::Einval.as_i32())));
}

/// The rule list is empty, but the dump must still terminate or a rule
/// loader's pre-load listing blocks forever.
#[test]
fn an_empty_rule_list_still_terminates_its_dump() {
    let mut s = on();
    assert_eq!(handle(&mut s, &req(AUDIT_LIST_RULES, &[], 1)), Reply::Done);
}

#[test]
fn the_deprecated_rule_operations_report_the_interface() {
    let mut s = on();
    for t in [AUDIT_LIST, AUDIT_ADD, AUDIT_DEL] {
        assert_eq!(handle(&mut s, &req(t, &[], 1)), Reply::Ack(-(Errno::Eopnotsupp.as_i32())));
    }
}

#[test]
fn a_user_record_is_stored_with_its_text_quoted() {
    let mut s = on();
    assert_eq!(handle(&mut s, &req(AUDIT_USER, b"hello\0", 33)), Reply::Ack(0));
    let r = s.backlog.pop_hold_for_test().expect("the user record was stored");
    assert_eq!(r.ty, AUDIT_USER);
    let t = core::str::from_utf8(&r.text).unwrap();
    assert!(t.ends_with("pid=33 msg=\"hello\""), "{t}");
}

/// The text came from userspace, so anything that could split a field forces
/// the hex encoding.
#[test]
fn a_user_record_with_a_space_is_hex_encoded() {
    let mut s = on();
    handle(&mut s, &req(AUDIT_USER, b"a b\0", 33));
    let r = s.backlog.pop_hold_for_test().unwrap();
    let t = core::str::from_utf8(&r.text).unwrap();
    assert!(t.ends_with("msg=612062"), "{t}");
}

#[test]
fn a_user_record_shorter_than_two_bytes_is_malformed() {
    let mut s = on();
    assert_eq!(handle(&mut s, &req(AUDIT_USER, b"x", 1)), Reply::Ack(-(Errno::Einval.as_i32())));
}

/// With audit off, a user record is accepted and discarded — except the one
/// type that reports an access-vector denial, which is logged regardless.
#[test]
fn user_records_are_discarded_while_audit_is_off() {
    let mut s = AuditState::new();
    assert_eq!(handle(&mut s, &req(AUDIT_USER, b"hello\0", 1)), Reply::Ack(0));
    assert_eq!(s.backlog.hold_len(), 0);
    assert_eq!(handle(&mut s, &req(AUDIT_USER_AVC, b"denied\0", 1)), Reply::Ack(0));
    assert_eq!(s.backlog.hold_len(), 1);
}

#[test]
fn an_oversized_user_record_is_truncated_not_refused() {
    let mut s = on();
    let big = Vec::from([b'a'; AUDIT_MESSAGE_TEXT_MAX * 2]);
    assert_eq!(handle(&mut s, &req(AUDIT_USER, &big, 1)), Reply::Ack(0));
    let r = s.backlog.pop_hold_for_test().unwrap();
    assert!(r.text.len() < AUDIT_MESSAGE_TEXT_MAX + 64);
}
