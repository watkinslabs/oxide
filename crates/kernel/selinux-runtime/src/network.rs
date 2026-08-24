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
/// A thread that staged a socket label gets that label; otherwise policy
/// computes a transition from the creating thread's own label for this class.
/// With no policy/server or no matching rule, the creating label stands.
pub fn create_sid(class: &'static str) -> Sid {
    if let Some(sid) = sockcreate_sid() { return sid; }
    let sid = crate::task::current_sid();
    let Some(class) = selinux::uapi::classmap::class_by_name(class) else { return sid; };
    crate::with(|s| s.transition_sid(sid, sid, class, None).unwrap_or(sid)).unwrap_or(sid)
}

/// Whether ICMP sockets have their distinct extended security class. # C: O(1)
pub fn extended_socket_class() -> bool {
    crate::with(|s| s.policycap(selinux::uapi::policycap::POLICYDB_CAP_EXTSOCKCLASS))
        .unwrap_or(false)
}

/// Whether the loaded policy asks SELinux to refine netlink message access
/// with `nlmsg` xperms rather than only the class's read/write bit.
pub fn netlink_xperm() -> bool {
    crate::with(|s| s.policycap(selinux::uapi::policycap::POLICYDB_CAP_NETLINK_XPERM))
        .unwrap_or(false)
}

/// Resolve one transport port through the loaded policy's `portcon` table.
/// Unmatched ports retain SELinux's initial `port` SID, exactly as the kernel
/// object-context lookup does. # C: O(portcon entries)
pub fn port_sid(protocol: u8, port: u16) -> Sid {
    crate::with(|s| s.network_port_sid(protocol, port))
        .unwrap_or(selinux::uapi::initsid::InitSid::Port.sid())
}

pub fn node_sid_v4(addr: u32) -> Sid {
    crate::with(|s| s.network_node_sid_v4(addr))
        .unwrap_or(selinux::uapi::initsid::InitSid::Node.sid())
}

pub fn node_sid_v6(addr: [u32; 4]) -> Sid {
    crate::with(|s| s.network_node_sid_v6(addr))
        .unwrap_or(selinux::uapi::initsid::InitSid::Node.sid())
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

/// Why a socket label could not be rendered for userspace.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContextError {
    /// The server is absent or the label has no SID-table entry.
    InvalidLabel,
    /// Rendering could not allocate the context string.
    NoMemory,
}

/// Rendered context of one label id. # C: O(categories)
///
/// The terminator is the security boundary's business, not this module's: it is
/// appended once, there, so the length published beside the value always counts
/// it.
pub fn context(label: Sid) -> Result<Vec<u8>, ContextError> {
    let rendered = crate::with(|s| s.sid_to_context(label))
        .ok_or(ContextError::InvalidLabel)?;
    rendered.map(alloc::string::String::into_bytes).map_err(|error| match error {
        selinux::Error::NoMemory => ContextError::NoMemory,
        _ => ContextError::InvalidLabel,
    })
}

/// Resolve a written security context for a kernel object. Unlike the inode
/// label path, a failed secmark context is an object-creation error: Linux
/// does not silently turn an nft security context into the unlabeled SID.
pub fn sid_from_context(written: &str) -> Option<Sid> {
    let sid = crate::with(|s| s.context_to_sid(written).ok()).flatten()
        .filter(|sid| *sid != 0)?;
    let class = selinux::uapi::classmap::class_by_name("packet")?;
    let permission = selinux::uapi::classmap::perm_bit(class, "relabelto")?;
    crate::check::has_perm(crate::task::current_sid(), sid, class, permission).ok()?;
    Some(sid)
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
