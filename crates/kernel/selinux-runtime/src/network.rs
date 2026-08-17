// How this module labels sockets, and how a recorded label becomes the context
// userspace reads back from `SO_PEERSEC`.
//
// The label ids live on the sockets and connections that recorded them; this
// file only answers questions about them. Nothing here keeps a table keyed by
// socket identity — that would be a second source of truth outliving the
// sockets it described.

use alloc::vec::Vec;

use selinux::sidtab::Sid;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::label::unlabeled_sid;

/// Reader for the label the current thread staged for its next new socket.
static SOCKCREATE_SID: Spinlock<Option<fn() -> Option<Sid>>, TaskListClass> = Spinlock::new(None);

/// Install the staged-socket-label reader. Idempotent. # C: O(1)
///
/// The task owner holds the staged label, as it holds every other per-task
/// label; a copy kept here could answer with one the task no longer carries.
pub fn set_sockcreate_sid_source(f: fn() -> Option<Sid>) { *SOCKCREATE_SID.lock() = Some(f); }

/// Label the running thread staged for its next socket, if any. # C: O(1)
pub fn sockcreate_sid() -> Option<Sid> {
    // Copied out before it runs: it reads task state under the task owner's own
    // lock, and holding this one across that would order two locks that have no
    // order between them.
    let reader = *SOCKCREATE_SID.lock();
    match reader { Some(f) => f(), None => None }
}

/// Label a socket created now takes. # C: O(1)
///
/// A thread that staged a socket label gets that label; otherwise the socket
/// takes the creating thread's own. Nothing else is consulted, so a socket is
/// never labelled from the task that later happens to use it.
pub fn create_sid() -> Sid {
    sockcreate_sid().unwrap_or_else(crate::task::current_sid)
}

/// Label the server end of a new connection takes. # C: O(categories)
///
/// The listening socket's identity carrying the connecting socket's
/// sensitivity, so a service accepting clients at several sensitivities has one
/// server end per client sensitivity. With no policy loaded there is no range
/// to move and the listener's label stands, which is also what a policy without
/// MLS produces.
pub fn server_end_sid(listener: Sid, client: Sid) -> Sid {
    crate::with(|s| s.sid_mls_copy(listener, client).unwrap_or(listener)).unwrap_or(listener)
}

/// Rendered context of one label id. # C: O(categories)
///
/// The terminator is the security boundary's business, not this module's: it is
/// appended once, there, so the length published beside the value always counts
/// it.
pub fn context(label: Sid) -> Option<Vec<u8>> {
    crate::with(|s| s.sid_to_context(label).ok())?.map(alloc::string::String::into_bytes)
}

/// Label reported for a peer no label was ever recorded for. # C: O(1)
///
/// A socket of a reporting class has a label from the moment it exists; before
/// it connects, that label is "unlabelled". Reporting nothing there would make
/// an unconnected socket indistinguishable from one on a kernel with no module.
pub fn unlabeled() -> Sid { unlabeled_sid() }

#[cfg(test)]
#[path = "tests/network.rs"]
mod tests;
