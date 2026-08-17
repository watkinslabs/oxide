// What a write to this filesystem tells userspace, and when.
//
// Two events reach the userspace AVC over `NETLINK_SELINUX`: the enforcement
// mode changed, and the policy in force changed. `libselinux` drops every
// cached access decision when it reads the second one, so a change this
// filesystem applies without announcing leaves every process linked against it
// answering from a cache the new policy may contradict.
//
// The DECISION — whether a write is a change at all, which message it produces
// and which sequence number that message carries — is a function over values
// here, so it runs under hosted `cargo test`. Only the send is plumbing.

use crate::ops::PolicyOps;

/// One event the userspace AVC is told about.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Notice {
    /// The enforcement mode is now this.
    Setenforce(bool),
    /// The policy in force changed; the value is the sequence number the
    /// change produced, which is what a reader compares against the last one
    /// it saw.
    Policyload(u32),
}

/// The notice an enforcement write produces, or `None` when the write asked
/// for the mode already in force. # C: O(1)
///
/// A write that changes nothing is not an event: announcing it would make
/// every process linked against `libselinux` flush its decision cache because
/// somebody re-asserted the current setting.
pub fn enforce_notice(before: bool, after: bool) -> Option<Notice> {
    if before == after { None } else { Some(Notice::Setenforce(after)) }
}

/// The notice a policy load or a boolean commit produces. Both replace the
/// answers the policy gives, and the reference announces both the same way.
/// # C: O(1)
pub fn policy_notice(seqno: u32) -> Notice { Notice::Policyload(seqno) }

/// Send one notice to every subscribed userspace AVC. Returns the number of
/// subscribers reached — zero before any process has opened such a socket.
/// # C: O(N subscribers)
pub fn emit(notice: Notice) -> usize {
    // What a write announced is otherwise unobservable from a hosted test: the
    // send reaches a socket registry no test in this crate owns, and a
    // notification nobody sends looks exactly like one nobody subscribed to.
    #[cfg(test)]
    tests::record(notice);
    match notice {
        Notice::Setenforce(on) => netlink::notify_setenforce(on),
        Notice::Policyload(seqno) => netlink::notify_policyload(seqno),
    }
}

/// Announce that the policy in force changed, reading the sequence number the
/// change produced from the server itself. # C: O(N subscribers)
pub fn policy_changed(ops: &dyn PolicyOps) -> usize {
    emit(policy_notice(ops.facts().seqno))
}

#[cfg(test)]
#[path = "tests/notify.rs"]
pub(crate) mod tests;
