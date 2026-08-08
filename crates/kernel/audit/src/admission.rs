// Who may send which NETLINK_AUDIT message.
//
// Two distinct capabilities: controlling the audit system (registering as the
// consumer, changing limits, loading rules) and merely writing a user record
// into the log. A process that may write records must not thereby be able to
// turn the log off, so the two are checked separately and the control set is
// additionally confined to the initial namespaces.
//
// Pure: the caller gathers the facts, this decides. Hosted-testable.

use syscall::errno::Errno;

use crate::uapi::*;

/// What the sender of a NETLINK_AUDIT message is, as far as admission cares.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Caller {
    /// The sender's user namespace is the initial one.
    pub init_user_ns: bool,
    /// The sender's pid namespace is the initial one.
    pub init_pid_ns: bool,
    pub cap_audit_control: bool,
    pub cap_audit_write: bool,
}

/// Whether `msg_type` is one of the deprecated syscall-rule operations.
/// # C: O(1)
pub fn is_deprecated_rule_op(msg_type: u16) -> bool {
    matches!(msg_type, AUDIT_LIST | AUDIT_ADD | AUDIT_DEL)
}

/// Whether `msg_type` controls the audit system.
/// # C: O(1)
pub fn is_control(msg_type: u16) -> bool {
    matches!(msg_type,
        AUDIT_GET | AUDIT_SET | AUDIT_GET_FEATURE | AUDIT_SET_FEATURE
        | AUDIT_LIST_RULES | AUDIT_ADD_RULE | AUDIT_DEL_RULE | AUDIT_SIGNAL_INFO
        | AUDIT_TTY_GET | AUDIT_TTY_SET | AUDIT_TRIM | AUDIT_MAKE_EQUIV)
}

/// Whether `msg_type` is a user-supplied record.
/// # C: O(1)
pub fn is_user_message(msg_type: u16) -> bool {
    msg_type == AUDIT_USER
        || (AUDIT_FIRST_USER_MSG..=AUDIT_LAST_USER_MSG).contains(&msg_type)
        || (AUDIT_FIRST_USER_MSG2..=AUDIT_LAST_USER_MSG2).contains(&msg_type)
}

/// Admit one NETLINK_AUDIT message.
///
/// A sender outside the initial user namespace is refused with ECONNREFUSED,
/// not EPERM, and the difference matters: a login stack that cannot reach the
/// audit system reads "not configured in" from ECONNREFUSED and proceeds,
/// where EPERM tells it the system is present and refusing, which makes it
/// reject the login outright. Confining audit to the initial user namespace
/// must not lock every containerised login out.
/// # C: O(1)
pub fn netlink_ok(c: Caller, msg_type: u16) -> Result<(), Errno> {
    if !c.init_user_ns { return Err(Errno::Econnrefused); }
    if is_deprecated_rule_op(msg_type) { return Err(Errno::Eopnotsupp); }
    if is_control(msg_type) {
        if !c.init_pid_ns { return Err(Errno::Eperm); }
        if !c.cap_audit_control { return Err(Errno::Eperm); }
        return Ok(());
    }
    if is_user_message(msg_type) {
        if !c.cap_audit_write { return Err(Errno::Eperm); }
        return Ok(());
    }
    Err(Errno::Einval)
}

#[cfg(test)]
#[path = "tests/admission.rs"]
mod tests;
