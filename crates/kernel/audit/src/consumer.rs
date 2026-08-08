// Which process receives records.
//
// Exactly one consumer at a time, identified by its process id and by the
// netlink port it registered from. The registration ladder is deliberately
// unforgiving: a healthy consumer cannot be displaced, and only the registered
// consumer can stand down — otherwise any holder of the control capability
// could silently redirect the log to itself.

use syscall::errno::Errno;

/// The registered consumer, if any.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Consumer {
    /// Process id, or zero when nobody is registered.
    pub pid: u32,
    /// Transport port records are unicast to.
    pub port_id: u32,
    /// Opaque routing token the transport supplied at registration and is
    /// handed back at delivery. The audit system never interprets it — which
    /// is what keeps this crate free of any transport's namespace model.
    pub route: u64,
}

impl Consumer {
    /// # C: O(1)
    pub fn registered(&self) -> bool { self.pid != 0 }
}

/// What an `AUDIT_STATUS_PID` request resolves to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PidAction {
    /// Install the sender as the consumer.
    Register,
    /// Tear down the registration.
    Unregister,
}

/// Decide an `AUDIT_STATUS_PID` request.
///
/// A caller may only register ITSELF: the pid it names must be its own, so a
/// control client cannot point the record stream at an unrelated process.
/// Replacing a live consumer is EEXIST rather than a silent takeover, and
/// unregistering someone else is EACCES — the two failures are distinct
/// because the daemon's restart logic branches on them.
/// # C: O(1)
pub fn pid_action(current: Consumer, caller_pid: u32, new_pid: u32)
    -> Result<PidAction, Errno>
{
    if new_pid != 0 && new_pid != caller_pid { return Err(Errno::Einval); }
    if current.registered() {
        if new_pid != 0 { return Err(Errno::Eexist); }
        if caller_pid != current.pid { return Err(Errno::Eacces); }
    }
    Ok(if new_pid != 0 { PidAction::Register } else { PidAction::Unregister })
}

#[cfg(test)]
#[path = "tests/consumer.rs"]
mod tests;
