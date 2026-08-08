use super::*;

const ROOT: Caller = Caller {
    init_user_ns: true, init_pid_ns: true, cap_audit_control: true, cap_audit_write: true,
};

const CONTROL_TYPES: [u16; 12] = [
    AUDIT_GET, AUDIT_SET, AUDIT_GET_FEATURE, AUDIT_SET_FEATURE, AUDIT_LIST_RULES,
    AUDIT_ADD_RULE, AUDIT_DEL_RULE, AUDIT_SIGNAL_INFO, AUDIT_TTY_GET, AUDIT_TTY_SET,
    AUDIT_TRIM, AUDIT_MAKE_EQUIV,
];

#[test]
fn a_fully_privileged_caller_reaches_every_live_message_type() {
    for t in CONTROL_TYPES { assert_eq!(netlink_ok(ROOT, t), Ok(()), "type {t}"); }
    for t in [AUDIT_USER, AUDIT_FIRST_USER_MSG, AUDIT_USER_AVC, AUDIT_USER_TTY,
              AUDIT_LAST_USER_MSG, AUDIT_FIRST_USER_MSG2, AUDIT_LAST_USER_MSG2] {
        assert_eq!(netlink_ok(ROOT, t), Ok(()), "type {t}");
    }
}

/// A login stack that cannot reach audit must be able to tell "no audit here"
/// from "audit is refusing you" — the first lets the login proceed, the second
/// rejects it. Confining audit to the initial user namespace must therefore
/// report the first.
#[test]
fn a_foreign_user_namespace_is_refused_as_if_audit_were_absent() {
    let c = Caller { init_user_ns: false, ..ROOT };
    for t in CONTROL_TYPES { assert_eq!(netlink_ok(c, t), Err(Errno::Econnrefused)); }
    assert_eq!(netlink_ok(c, AUDIT_USER), Err(Errno::Econnrefused));
    assert_eq!(netlink_ok(c, AUDIT_LIST), Err(Errno::Econnrefused),
        "the namespace check runs before the deprecation check");
    assert_eq!(netlink_ok(c, 4242), Err(Errno::Econnrefused));
}

/// The three deprecated rule operations are answered as a supported interface
/// this kernel does not speak, not as a malformed request: a rule loader tells
/// the two apart to choose its format.
#[test]
fn the_deprecated_rule_operations_report_the_interface_not_the_request() {
    for t in [AUDIT_LIST, AUDIT_ADD, AUDIT_DEL] {
        assert_eq!(netlink_ok(ROOT, t), Err(Errno::Eopnotsupp));
        assert!(is_deprecated_rule_op(t));
    }
}

#[test]
fn control_needs_the_control_capability_not_the_write_one() {
    let c = Caller { cap_audit_control: false, ..ROOT };
    for t in CONTROL_TYPES { assert_eq!(netlink_ok(c, t), Err(Errno::Eperm), "type {t}"); }
    assert_eq!(netlink_ok(c, AUDIT_USER), Ok(()), "writing a record is a separate right");
}

#[test]
fn a_user_record_needs_the_write_capability_not_the_control_one() {
    let c = Caller { cap_audit_write: false, ..ROOT };
    assert_eq!(netlink_ok(c, AUDIT_USER), Err(Errno::Eperm));
    assert_eq!(netlink_ok(c, AUDIT_USER_AVC), Err(Errno::Eperm));
    assert_eq!(netlink_ok(c, AUDIT_LAST_USER_MSG2), Err(Errno::Eperm));
    assert_eq!(netlink_ok(c, AUDIT_GET), Ok(()));
}

/// Control is additionally confined to the initial pid namespace: the consumer
/// registration names a pid, and a pid from another namespace names a
/// different process.
#[test]
fn control_is_confined_to_the_initial_pid_namespace() {
    let c = Caller { init_pid_ns: false, ..ROOT };
    for t in CONTROL_TYPES { assert_eq!(netlink_ok(c, t), Err(Errno::Eperm), "type {t}"); }
    assert_eq!(netlink_ok(c, AUDIT_USER), Ok(()), "a user record names no pid");
}

#[test]
fn an_unknown_message_type_is_a_malformed_request() {
    assert_eq!(netlink_ok(ROOT, 0), Err(Errno::Einval));
    assert_eq!(netlink_ok(ROOT, AUDIT_LOGIN), Err(Errno::Einval));
    assert_eq!(netlink_ok(ROOT, AUDIT_FIRST_USER_MSG - 1), Err(Errno::Einval));
    assert_eq!(netlink_ok(ROOT, AUDIT_LAST_USER_MSG + 1), Err(Errno::Einval));
    assert_eq!(netlink_ok(ROOT, AUDIT_FIRST_USER_MSG2 - 1), Err(Errno::Einval));
    assert_eq!(netlink_ok(ROOT, AUDIT_LAST_USER_MSG2 + 1), Err(Errno::Einval));
}

#[test]
fn the_user_message_ranges_are_closed_at_both_ends() {
    assert!(!is_user_message(AUDIT_FIRST_USER_MSG - 1));
    assert!(is_user_message(AUDIT_FIRST_USER_MSG));
    assert!(is_user_message(AUDIT_LAST_USER_MSG));
    assert!(!is_user_message(AUDIT_LAST_USER_MSG + 1));
    assert!(is_user_message(AUDIT_FIRST_USER_MSG2));
    assert!(is_user_message(AUDIT_LAST_USER_MSG2));
    assert!(!is_user_message(AUDIT_LAST_USER_MSG2 + 1));
    assert!(is_user_message(AUDIT_USER));
    assert!(!is_control(AUDIT_USER));
}
