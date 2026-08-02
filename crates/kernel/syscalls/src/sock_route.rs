// Which socket implementation owns an fd, for the control syscalls that
// classify one: `shutdown(2)` 48, `accept(2)` 43 / `accept4(2)` 288,
// `listen(2)` 50, `getpeername(2)` 52.
//
// The ladder is a decision — an fd that names no open file is EBADF, a file
// that is no socket at all is ENOTSOCK, and a protocol whose `proto_ops` slot
// for this operation is the "no such operation" stub is EOPNOTSUPP, which is a
// DIFFERENT refusal from "not a socket". Getting the order or the errno wrong
// is invisible to a boot and visible to every portable caller.
//
// Ungated on purpose (docs/53, CLAUDE.md phantom-test rule): the slot files
// are `#![cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]` block written
// beside them compiles away in silence. This module owns the decision and the
// slot files call it, so the hosted suite drives exactly the code the kernel
// runs. It used to be asserted by `include_str!`-grepping the slot files for
// the order of two literals, which could not fail on a behaviour change and
// broke whenever the text moved.

use alloc::sync::Arc;
use syscall::errno::Errno;

/// Which socket implementation backs an open file. # C: n/a
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// AF_NETLINK.
    Netlink,
    /// AF_VSOCK.
    Vsock,
    /// Everything `net::sock::InetSocket` backs: AF_INET, AF_INET6, AF_UNIX,
    /// AF_PACKET.
    Inet,
    /// An open file that is not a socket at all.
    NotSocket,
}

/// The control syscalls that classify their fd this way. # C: n/a
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOp { Shutdown, Listen, Accept, GetPeerName }

impl ControlOp {
    /// Name used by the ENOTSOCK trace point. # C: O(1)
    pub fn trace_name(self) -> &'static [u8] {
        match self {
            ControlOp::Shutdown    => b"shutdown",
            ControlOp::Listen      => b"listen",
            ControlOp::Accept      => b"accept",
            ControlOp::GetPeerName => b"getpeername",
        }
    }
}

/// The endpoint that carries out `op`, or the errno the call refuses with.
///
/// `endpoint` is `None` when the fd names no open file. `arg_error` is the
/// refusal the call's OWN argument screen produced, if any — `accept4`'s flag
/// word is the only one, and it is rejected AFTER the fd lookup and BEFORE the
/// file's protocol is consulted. So `accept4(not_a_socket, .., garbage_flags)`
/// is EINVAL, not ENOTSOCK, and `accept4(-1, .., garbage_flags)` is EBADF.
/// # C: O(1)
pub fn route(op: ControlOp, endpoint: Option<Endpoint>, arg_error: Option<Errno>)
    -> Result<Endpoint, Errno>
{
    let endpoint = match endpoint { Some(e) => e, None => return Err(Errno::Ebadf) };
    if let Some(error) = arg_error { return Err(error); }
    match endpoint {
        // The fd is an open file, so this is not EBADF; it is simply not a
        // socket, and no protocol gets a say.
        Endpoint::NotSocket => Err(Errno::Enotsock),
        // AF_NETLINK's protocol operations carry the "no such operation" stub
        // for listen and accept, and real implementations for shutdown (which
        // performs its own admission and then refuses) and the name query.
        Endpoint::Netlink => match op {
            ControlOp::Listen | ControlOp::Accept => Err(Errno::Eopnotsupp),
            ControlOp::Shutdown | ControlOp::GetPeerName => Ok(Endpoint::Netlink),
        },
        Endpoint::Vsock => Ok(Endpoint::Vsock),
        Endpoint::Inet  => Ok(Endpoint::Inet),
    }
}

/// Classify an already-pinned open file. Ungated so the classification a
/// control syscall acts on is provable against real socket inodes.
/// # C: O(1)
pub fn endpoint_of(file: &Arc<vfs::File>) -> Endpoint {
    let inode = file.inode();
    if ::netlink::netlink_arc_from_inode(inode).is_some() { return Endpoint::Netlink; }
    if crate::net_common::inode_as_vsock(inode).is_some() { return Endpoint::Vsock; }
    if crate::net_common::inode_as_inet_socket(inode).is_some() { return Endpoint::Inet; }
    Endpoint::NotSocket
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests {
    use super::*;

    const OPS: [ControlOp; 4] = [ControlOp::Shutdown, ControlOp::Listen,
        ControlOp::Accept, ControlOp::GetPeerName];

    /// The three ops with no argument screen of their own.
    fn route_op(op: ControlOp, endpoint: Option<Endpoint>) -> Result<Endpoint, Errno> {
        route(op, endpoint, None)
    }

    #[test]
    fn an_fd_that_names_no_open_file_is_bad_before_any_protocol_question() {
        for op in OPS { assert_eq!(route_op(op, None), Err(Errno::Ebadf), "{op:?}"); }
    }

    #[test]
    fn an_fd_that_names_no_open_file_is_bad_before_the_calls_own_arguments() {
        // accept4 reads its flag word only once the fd resolved: a bad flag on
        // a bad fd reports the bad fd.
        assert_eq!(route(ControlOp::Accept, None, Some(Errno::Einval)), Err(Errno::Ebadf));
    }

    #[test]
    fn a_calls_own_argument_screen_precedes_the_files_protocol() {
        // accept4 rejects an unknown flag bit before asking whether the file is
        // a socket at all, so a garbage flag word on a regular file is EINVAL.
        for endpoint in [Endpoint::NotSocket, Endpoint::Netlink, Endpoint::Inet, Endpoint::Vsock] {
            assert_eq!(route(ControlOp::Accept, Some(endpoint), Some(Errno::Einval)),
                Err(Errno::Einval), "{endpoint:?}");
        }
    }

    #[test]
    fn an_open_file_that_is_no_socket_is_notsock_on_every_control_call() {
        for op in OPS {
            assert_eq!(route_op(op, Some(Endpoint::NotSocket)), Err(Errno::Enotsock), "{op:?}");
        }
    }

    #[test]
    fn netlink_refuses_listen_and_accept_as_unsupported_not_as_a_non_socket() {
        // The distinction is the whole point: EOPNOTSUPP says "this socket has
        // no such operation", ENOTSOCK says "this is not a socket". A caller
        // that probes for a listening-capable fd tells them apart.
        assert_eq!(route_op(ControlOp::Listen, Some(Endpoint::Netlink)), Err(Errno::Eopnotsupp));
        assert_eq!(route_op(ControlOp::Accept, Some(Endpoint::Netlink)), Err(Errno::Eopnotsupp));
        assert_ne!(route_op(ControlOp::Listen, Some(Endpoint::Netlink)), Err(Errno::Enotsock));
    }

    #[test]
    fn netlink_owns_its_shutdown_and_its_name_query() {
        // Both reach the netlink owner, which performs its own admission —
        // shutdown then reports the refusal itself, so the ladder must not
        // short-circuit it here.
        assert_eq!(route_op(ControlOp::Shutdown, Some(Endpoint::Netlink)), Ok(Endpoint::Netlink));
        assert_eq!(route_op(ControlOp::GetPeerName, Some(Endpoint::Netlink)), Ok(Endpoint::Netlink));
    }

    #[test]
    fn vsock_and_inet_files_reach_their_own_owner_on_every_control_call() {
        for op in OPS {
            assert_eq!(route_op(op, Some(Endpoint::Vsock)), Ok(Endpoint::Vsock), "{op:?}");
            assert_eq!(route_op(op, Some(Endpoint::Inet)), Ok(Endpoint::Inet), "{op:?}");
        }
    }

    fn file_for(inode: vfs::InodeRef) -> Arc<vfs::File> {
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
    }

    #[test]
    fn a_real_vsock_file_classifies_as_vsock_and_a_real_inet_file_as_inet() {
        let vsock = Arc::new(net::vsock_socket::VsockSocket::new());
        let file = file_for(net::vsock_socket::make_vsock_socket_inode(vsock));
        assert_eq!(endpoint_of(&file), Endpoint::Vsock);
        assert_eq!(route_op(ControlOp::Accept, Some(endpoint_of(&file))), Ok(Endpoint::Vsock));

        let inet = Arc::new(net::sock::InetSocket::new_udp());
        let file = file_for(net::sock::make_inet_socket_inode(inet));
        assert_eq!(endpoint_of(&file), Endpoint::Inet);
    }

    #[test]
    fn a_file_backed_by_no_socket_classifies_as_not_a_socket() {
        let inode: vfs::InodeRef = vfs::InodeBuilder::new(7,
            vfs::mk_mode(vfs::FileType::Regular, 0o644),
            vfs::default_inode_ops(), vfs::default_file_ops()).build();
        let file = file_for(inode);
        assert_eq!(endpoint_of(&file), Endpoint::NotSocket);
        assert_eq!(route_op(ControlOp::Shutdown, Some(endpoint_of(&file))), Err(Errno::Enotsock));
    }

    #[test]
    fn each_control_op_names_itself_to_the_notsock_trace() {
        assert_eq!(ControlOp::Shutdown.trace_name(), b"shutdown");
        assert_eq!(ControlOp::Listen.trace_name(), b"listen");
        assert_eq!(ControlOp::Accept.trace_name(), b"accept");
        assert_eq!(ControlOp::GetPeerName.trace_name(), b"getpeername");
    }
}
