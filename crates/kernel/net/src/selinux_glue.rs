// Wiring between the mandatory-access-control module and sockets.
//
// The module below `sched` answers the label questions and the boundary above
// stores nothing; this file is the only place the two meet, because it is the
// lowest crate that can see both. Nothing here decides policy — every answer
// comes from the module, and every stored id lives on the socket or connection
// that recorded it.

use syscall::errno::Errno;

fn context(label: u32) -> Result<alloc::vec::Vec<u8>, Errno> {
    selinux_runtime::network::context(label).map_err(|error| match error {
        selinux_runtime::network::ContextError::NoMemory => Errno::Enomem,
        selinux_runtime::network::ContextError::InvalidLabel => Errno::Einval,
    })
}

/// Publish the security module as the one that labels sockets. # C: O(1)
///
/// Called once at boot, after the security server is installed and before the
/// first socket is created. A socket created before this runs carries no label
/// and reports none for its peers, so this must not be deferred past the first
/// socket the kernel opens.
///
/// Returns whether this call installed it; a second call is refused rather than
/// replacing the first, so two callers cannot leave sockets labelled from one
/// module and rendered by another.
pub fn init() -> bool {
    security::network::install_socket_label(security::network::SocketLabelOps {
        create: selinux_runtime::network::create_sid,
        unlabeled: selinux_runtime::network::unlabeled(),
        context,
        server_end: selinux_runtime::network::server_end_sid,
    })
}
