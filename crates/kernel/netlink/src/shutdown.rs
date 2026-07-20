//! AF_NETLINK shutdown ownership.

use crate::NetlinkSocket;

impl NetlinkSocket {
    /// Apply Linux `netlink_ops.shutdown = sock_no_shutdown`. Generic socket
    /// security admission precedes the protocol's unsupported-operation errno.
    /// # C: O(1)
    pub fn shutdown(&self) -> Result<(), net::NetError> {
        net::security_admission::check(
            net::net_ns::namespace_id(&self.net_ns),
            net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Shutdown,
        ).map_err(|_| net::NetError::Eacces)?;
        Err(net::NetError::Eopnotsupp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_is_the_linux_unsupported_socket_operation() {
        let socket = NetlinkSocket::new(crate::proto::NETLINK_ROUTE,
            &network_namespace::initial());
        assert_eq!(socket.shutdown(), Err(net::NetError::Eopnotsupp));
    }
}
