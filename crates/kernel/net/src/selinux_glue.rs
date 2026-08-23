// Wiring between the mandatory-access-control module and sockets.
//
// The module below `sched` answers the label questions and the boundary above
// stores nothing; this file is the only place the two meet, because it is the
// lowest crate that can see both. Nothing here decides policy — every answer
// comes from the module, and every stored id lives on the socket or connection
// that recorded it.

use syscall::errno::Errno;

fn create(class: security::network::SocketClass) -> u32 {
    let name = socket_class_name(class, selinux_runtime::network::extended_socket_class());
    selinux_runtime::network::create_sid(name)
}

fn socket_class_name(class: security::network::SocketClass, extended: bool) -> &'static str {
    use security::network::SocketClass;
    match class {
        SocketClass::Tcp => "tcp_socket",
        SocketClass::Udp => "udp_socket",
        SocketClass::RawIp => "rawip_socket",
        SocketClass::Icmp if extended => "icmp_socket",
        SocketClass::Icmp => "rawip_socket",
        SocketClass::Packet => "packet_socket",
        SocketClass::UnixStream => "unix_stream_socket",
        SocketClass::UnixDgram => "unix_dgram_socket",
    }
}

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
        create,
        unlabeled: selinux_runtime::network::unlabeled(),
        context,
        server_end: selinux_runtime::network::server_end_sid,
    })
}

/// Resolve the security context used by an nft SECMARK object through the
/// one installed SELinux server. # C: O(categories)
pub fn secmark_sid(context: &str) -> Option<u32> {
    selinux_runtime::network::sid_from_context(context)
}

#[cfg(test)]
mod tests {
    use super::socket_class_name;
    use security::network::SocketClass;

    #[test]
    fn every_constructor_class_maps_to_its_policy_class() {
        assert_eq!(socket_class_name(SocketClass::Tcp, false), "tcp_socket");
        assert_eq!(socket_class_name(SocketClass::Udp, false), "udp_socket");
        assert_eq!(socket_class_name(SocketClass::RawIp, false), "rawip_socket");
        assert_eq!(socket_class_name(SocketClass::Packet, false), "packet_socket");
        assert_eq!(socket_class_name(SocketClass::UnixStream, false), "unix_stream_socket");
        assert_eq!(socket_class_name(SocketClass::UnixDgram, false), "unix_dgram_socket");
        assert_eq!(socket_class_name(SocketClass::Icmp, false), "rawip_socket");
        assert_eq!(socket_class_name(SocketClass::Icmp, true), "icmp_socket");
    }
}
