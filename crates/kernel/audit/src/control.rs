// NETLINK_AUDIT request handling: admission, then the per-message-type effect
// on the audit system, then what to reply.
//
// Runs against a borrowed [`AuditState`] and returns a [`Reply`] rather than
// wire bytes, so the netlink layer owns framing and the hosted suite owns the
// decision. Nothing here allocates a socket, reads a task, or touches a clock.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::admission::{self, Caller};
use crate::config::{self, apply_features, FeatureRequest, Field};
use crate::consumer::{pid_action, Consumer, PidAction};
use crate::record::Record;
use crate::state::AuditState;
use crate::uapi::*;
use crate::wire::Status;
use crate::{fmt, record};

/// One decoded NETLINK_AUDIT request.
pub struct Request<'a> {
    pub msg_type: u16,
    /// Payload after the netlink header.
    pub data: &'a [u8],
    pub caller: Caller,
    /// The sender's process id, as seen in the initial pid namespace.
    pub caller_pid: u32,
    /// The transport port the sender bound, where records would be delivered.
    pub port_id: u32,
    /// Opaque routing token the transport hands back at delivery.
    pub route: u64,
    /// Wall-clock nanoseconds, for stamping any record this request generates.
    pub realtime_ns: u64,
    /// Milliseconds, for the rate-limit window.
    pub now_ms: u64,
}

/// What the netlink layer must send back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// A `AUDIT_GET` reply body.
    Status(Vec<u8>),
    /// A `AUDIT_GET_FEATURE` reply body.
    Features(Vec<u8>),
    /// End an empty dump.
    Done,
    /// Acknowledge with this value in the error field. Zero is success; a
    /// negative value is an errno; a positive value is the counter the request
    /// asked to read and reset.
    Ack(i32),
}

/// Handle one request.
/// # C: O(payload len)
pub fn handle(s: &mut AuditState, req: &Request<'_>) -> Reply {
    if let Err(e) = admission::netlink_ok(req.caller, req.msg_type) {
        return Reply::Ack(-(e.as_i32()));
    }
    match req.msg_type {
        AUDIT_GET => {
            let st = Status::from_config(&s.cfg, s.consumer.pid, s.backlog.len());
            Reply::Status(st.encode())
        }
        AUDIT_SET => match set_status(s, req) {
            Ok(v) => Reply::Ack(v),
            Err(e) => Reply::Ack(-(e.as_i32())),
        },
        AUDIT_GET_FEATURE => Reply::Features(FeatureRequest::reply(&s.cfg)),
        AUDIT_SET_FEATURE => {
            if req.data.len() < AUDIT_FEATURES_LEN { return Reply::Ack(-(Errno::Einval.as_i32())); }
            let want = FeatureRequest::decode(req.data);
            match apply_features(&mut s.cfg, want) {
                Ok(()) => Reply::Ack(0),
                Err(e) => Reply::Ack(-(e.as_i32())),
            }
        }
        // No rules are installed, so the list is empty. The dump must still be
        // terminated or a rule loader's pre-load listing blocks forever.
        AUDIT_LIST_RULES => Reply::Done,
        t if admission::is_user_message(t) => user_message(s, req),
        _ => Reply::Ack(0),
    }
}

/// `AUDIT_SET`: apply each field the mask selects, in a fixed order, stopping
/// at the first failure. A partial application is deliberate — the client
/// learns which field failed from the errno and re-reads the rest with
/// `AUDIT_GET`.
/// # C: O(1)
fn set_status(s: &mut AuditState, req: &Request<'_>) -> Result<i32, Errno> {
    let want = Status::decode(req.data);
    if want.mask & !AUDIT_STATUS_ALL != 0 { return Err(Errno::Einval); }
    if want.mask & AUDIT_STATUS_ENABLED != 0 { change(s, req, Field::Enabled, want.enabled)?; }
    if want.mask & AUDIT_STATUS_FAILURE != 0 { change(s, req, Field::Failure, want.failure)?; }
    if want.mask & AUDIT_STATUS_PID != 0 { set_consumer(s, req, want.pid)?; }
    if want.mask & AUDIT_STATUS_RATE_LIMIT != 0 {
        change(s, req, Field::RateLimit, want.rate_limit)?;
    }
    if want.mask & AUDIT_STATUS_BACKLOG_LIMIT != 0 {
        change(s, req, Field::BacklogLimit, want.backlog_limit)?;
    }
    if want.mask & AUDIT_STATUS_BACKLOG_WAIT_TIME != 0 {
        // The field only exists in the full-length struct; a client that sent
        // a shorter one is asking to set a field it did not supply.
        if req.data.len() < AUDIT_STATUS_LEN { return Err(Errno::Einval); }
        change(s, req, Field::BacklogWaitTime, want.backlog_wait_time)?;
    }
    // The two counter reads are whole-mask requests, not fields: reading and
    // resetting a counter alongside a configuration change would leave the
    // client unable to say which of the two the reply answered.
    if want.mask == AUDIT_STATUS_LOST {
        let lost = s.cfg.take_lost();
        log_config_change(s, req, b"lost", 0, lost, true);
        return Ok(lost as i32);
    }
    if want.mask == AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL {
        let actual = s.cfg.take_backlog_wait_time_actual();
        log_config_change(s, req, b"backlog_wait_time_actual", 0, actual, true);
        return Ok(actual as i32);
    }
    Ok(0)
}

/// Apply one configuration field and record the attempt.
///
/// The record is written BEFORE the change lands and carries whether it was
/// allowed. Both halves matter: recording afterwards would mean a change that
/// switches audit off is never recorded at all, and recording only successes
/// would hide exactly the attempts an auditor cares about.
/// # C: O(1)
fn change(s: &mut AuditState, req: &Request<'_>, f: Field, new: u32) -> Result<(), Errno> {
    f.validate(new)?;
    let old = f.get(&s.cfg);
    let allowed = !s.cfg.locked();
    log_config_change(s, req, f.name(), new, old, allowed);
    config::set(&mut s.cfg, f, new)
}

/// `op=set <name>=<new> old=<old> auid=<pid> res=<0|1>`.
/// # C: O(1)
fn log_config_change(s: &mut AuditState, req: &Request<'_>, name: &[u8], new: u32, old: u32,
                     allowed: bool)
{
    if s.cfg.enabled == AUDIT_OFF { return; }
    let mut b = Vec::new();
    b.extend_from_slice(b"op=set ");
    b.extend_from_slice(name);
    b.push(b'=');
    fmt::dec(&mut b, new as u64);
    b.extend_from_slice(b" old=");
    fmt::dec(&mut b, old as u64);
    b.extend_from_slice(b" pid=");
    fmt::dec(&mut b, req.caller_pid as u64);
    b.extend_from_slice(b" res=");
    fmt::dec(&mut b, u64::from(allowed));
    queue(s, req, AUDIT_CONFIG_CHANGE, &b);
}

/// The consumer-registration arm of `AUDIT_SET`.
/// # C: O(N_held)
fn set_consumer(s: &mut AuditState, req: &Request<'_>, new_pid: u32) -> Result<(), Errno> {
    let action = pid_action(s.consumer, req.caller_pid, new_pid);
    let old = s.consumer.pid;
    match action {
        Err(e) => { log_config_change(s, req, b"audit_pid", new_pid, old, false); Err(e) }
        Ok(PidAction::Register) => {
            s.consumer = Consumer { pid: new_pid, port_id: req.port_id, route: req.route };
            // Everything produced before a consumer existed becomes
            // deliverable the moment one does, oldest first.
            s.backlog.release_hold();
            log_config_change(s, req, b"audit_pid", new_pid, old, true);
            Ok(())
        }
        Ok(PidAction::Unregister) => {
            s.consumer = Consumer::default();
            log_config_change(s, req, b"audit_pid", new_pid, old, true);
            Ok(())
        }
    }
}

/// A record the sender supplied. Its text is not the kernel's, so it is
/// encoded as untrusted: quoted when plainly printable, hex otherwise, and
/// never long enough to be a memory-exhaustion channel.
/// # C: O(payload len)
fn user_message(s: &mut AuditState, req: &Request<'_>) -> Reply {
    const MIN_USER_MESSAGE: usize = 2;
    if s.cfg.enabled == AUDIT_OFF && req.msg_type != AUDIT_USER_AVC { return Reply::Ack(0); }
    if req.data.len() < MIN_USER_MESSAGE { return Reply::Ack(-(Errno::Einval.as_i32())); }
    let mut text = &req.data[..req.data.len().min(AUDIT_MESSAGE_TEXT_MAX)];
    // A sender's C string carries its terminator; the record does not.
    if let Some((last, head)) = text.split_last() { if *last == 0 { text = head; } }
    let mut b = Vec::new();
    b.extend_from_slice(b"pid=");
    fmt::dec(&mut b, req.caller_pid as u64);
    b.extend_from_slice(b" msg=");
    fmt::untrusted(&mut b, text);
    queue(s, req, req.msg_type, &b);
    Reply::Ack(0)
}

/// Stamp and admit a record produced while handling a request.
/// # C: O(body len)
fn queue(s: &mut AuditState, req: &Request<'_>, ty: u16, body: &[u8]) {
    let r: Record = record::build(ty, req.realtime_ns, record::next_serial(), body);
    let _ = crate::emit::admit(s, r, req.now_ms);
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
