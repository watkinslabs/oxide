// Socket-level `reuseport_attach_prog` / `reuseport_detach_prog` ladders.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::group::ReuseportGroup;
use super::slot;
use crate::bpf_filter::FilterProgram;
use crate::sock::{InetSocket, SockKind};

/// Whether the socket already occupies a transport hash, which is what decides
/// between allocating a fresh group and requiring an existing one.
/// A datagram socket is hashed by `bind`; a stream socket by `listen` or
/// `connect`. # C: O(1)
pub fn is_hashed(sock: &InetSocket) -> bool {
    if sock.udp4.lock().is_some() || sock.udp6.lock().is_some() { return true; }
    matches!(*sock.kind.lock(), SockKind::TcpListener(_) | SockKind::TcpConn(_))
}

/// The group this socket belongs to. # C: O(1)
pub fn group_of(sock: &InetSocket) -> Option<Arc<ReuseportGroup>> {
    slot::group(&sock.reuseport_group)
}

/// Create the one-member group an unhashed socket needs before a program can be
/// installed. SO_REUSEPORT must already be set; a socket that already names a
/// group keeps it. # C: O(1)
pub fn alloc_for_unhashed(sock: &Arc<InetSocket>) -> Result<Arc<ReuseportGroup>, Errno> {
    if sock.opts.base.reuseport.load(Ordering::Acquire) == 0 { return Err(Errno::Einval); }
    if let Some(group) = group_of(sock) { return Ok(group); }
    let group = ReuseportGroup::new();
    slot::join(&sock.reuseport_group, &group);
    Ok(group)
}

/// Install a selection program over this socket's group. # C: O(program bytes)
pub fn attach_prog(sock: &Arc<InetSocket>, prog: FilterProgram) -> Result<(), Errno> {
    let group = if is_hashed(sock) {
        // Already hashed without a group means the socket was bound without
        // SO_REUSEPORT, so no group can be created for it now.
        group_of(sock).ok_or(Errno::Einval)?
    } else {
        alloc_for_unhashed(sock)?
    };
    group.attach_prog(prog);
    Ok(())
}

/// Remove the selection program from this socket's group. # C: O(1)
pub fn detach_prog(sock: &InetSocket) -> Result<(), Errno> {
    let Some(group) = group_of(sock) else {
        return Err(if sock.opts.base.reuseport.load(Ordering::Acquire) != 0 {
            Errno::Enoent
        } else {
            Errno::Einval
        });
    };
    // An unhashed socket looking at a group that still retains shutdown members
    // is no longer the group's owner, so it cannot drop the shared program.
    if !is_hashed(sock) && group.num_closed_socks() != 0 { return Err(Errno::Enoent); }
    group.detach_prog()
}
