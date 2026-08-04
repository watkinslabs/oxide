// Per-message sender credentials for SO_PASSCRED / SCM_CREDENTIALS.
//
// The pid a receiver is shown is NOT the number the sender knows itself by: it
// is the number the RECEIVER's pid namespace gives that process. So a message
// carries the sender's pid IDENTITY, and the number is rendered at receive
// time — the same reason `SO_PEERCRED` pins an identity rather than a number.

use alloc::{sync::Arc, vec::Vec};

use sched::pid::PidIdentity;

/// Sender credentials stamped into one message.
#[derive(Clone, Default)]
pub struct MsgCred {
    /// The number the SENDER knew the process by; the value a receiver in the
    /// sender's own namespace sees, and the fallback for a message whose
    /// sender identity is unavailable (hosted fixtures, kernel senders).
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Linux `UNIXCB(skb).pid`: the pinned sender identity, so the number can
    /// be re-rendered for whichever namespace ends up reading the message.
    pub identity: Option<Arc<PidIdentity>>,
    /// Security context captured while the sender owns the message.  It must
    /// not be derived from a receiver-side peer lookup after queueing.
    pub security: Option<Vec<u8>>,
}

impl MsgCred {
    /// Numbers only, for a sender with no identity to pin. # C: O(1)
    pub fn from_ids(ids: (u32, u32, u32)) -> Self {
        Self { pid: ids.0, uid: ids.1, gid: ids.2, identity: None, security: None }
    }

    /// A credential set userspace supplied through `SCM_CREDENTIALS`. The pid
    /// was named in the SENDER's namespace, so it is resolved there and the
    /// resulting identity re-rendered for the receiver. # C: O(N_tasks)
    #[cfg(target_os = "oxide-kernel")]
    pub fn from_supplied(ids: (u32, u32, u32)) -> Self {
        let identity = sched::registry::resolve_user_pid(ids.0).map(|t| Arc::clone(&t.pid));
        // SCM_CREDENTIALS may name an authorised supplied pid, but the LSM
        // label is always that of the task doing the send.
        let sender = sched::live::current().map(|task| leader_identity(&task));
        let security = security::network::message_security(sender.as_deref());
        Self { pid: ids.0, uid: ids.1, gid: ids.2, identity, security }
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn from_supplied(ids: (u32, u32, u32)) -> Self { Self::from_ids(ids) }

    /// The running task's credentials, pinning its identity. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn of_current(fallback: (u32, u32, u32)) -> Self {
        use core::sync::atomic::Ordering::Relaxed;
        match sched::live::current() {
            Some(c) => {
                let identity = leader_identity(&c);
                let security = security::network::message_security(Some(&identity));
                Self {
                pid: c.visible_pid(),
                uid: c.creds.ruid.load(Relaxed),
                gid: c.creds.rgid.load(Relaxed),
                // The credential names the PROCESS, so it pins the thread
                // group's identity — a worker thread's message must be
                // attributed to its process, not to the thread.
                identity: Some(identity), security,
            }},
            None => Self::from_ids(fallback),
        }
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn of_current(fallback: (u32, u32, u32)) -> Self { Self::from_ids(fallback) }

    /// Whether two stamps name the same writer, which is what decides if a
    /// stream receive may glue their bytes into one read. Two pinned
    /// identities are the same writer only when they are the same process —
    /// equal pid NUMBERS are not enough, since two pid namespaces number
    /// different processes alike. # C: O(1)
    pub fn same_sender(&self, other: &Self) -> bool {
        if self.uid != other.uid || self.gid != other.gid { return false; }
        match (&self.identity, &other.identity) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => self.pid == other.pid,
            _ => false,
        }
    }

    /// The `{pid,uid,gid}` triple to hand the reader running now, with the pid
    /// expressed in that reader's pid namespace. A sender the reader's
    /// namespace does not number at all reports pid 0, which is what a
    /// namespace-local receiver must see. # C: O(depth)
    pub fn ids_for_reader(&self) -> (u32, u32, u32) {
        match &self.identity {
            Some(identity) => {
                let ns = sched::registry::reader_pid_ns();
                // The initial namespace numbers every process, so a stamp whose
                // identity published no mapping (a kernel sender) keeps the
                // number it was captured with rather than reporting none.
                let nr = match identity.nr_in(&ns) {
                    0 if ns.is_initial() => self.pid,
                    nr => nr,
                };
                (nr, self.uid, self.gid)
            }
            None => (self.pid, self.uid, self.gid),
        }
    }
}

/// The thread group's PID identity for a task, which is the identity every
/// process-scoped credential names. # C: O(log N_tasks)
#[cfg(target_os = "oxide-kernel")]
fn leader_identity(task: &sched::Task) -> Arc<PidIdentity> {
    use core::sync::atomic::Ordering::Acquire;
    let tgid = task.tgid.load(Acquire);
    if tgid == task.tid { return Arc::clone(&task.pid); }
    match sched::registry::lookup(tgid) {
        Some(leader) => Arc::clone(&leader.pid),
        None => Arc::clone(&task.pid),
    }
}

/// Two stamps are the same credential when they name the same process with the
/// same ids; the pinned identity is the same object whenever the numbers are.
impl PartialEq for MsgCred {
    fn eq(&self, other: &Self) -> bool {
        self.pid == other.pid && self.uid == other.uid && self.gid == other.gid
    }
}

impl Eq for MsgCred {}

impl PartialEq<(u32, u32, u32)> for MsgCred {
    fn eq(&self, other: &(u32, u32, u32)) -> bool {
        (self.pid, self.uid, self.gid) == *other
    }
}

impl core::fmt::Debug for MsgCred {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MsgCred{:?}", (self.pid, self.uid, self.gid))
    }
}
