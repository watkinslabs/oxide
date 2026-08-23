//! AF_NETLINK shutdown ownership.

use crate::NetlinkSocket;

impl NetlinkSocket {
    /// Apply Linux `netlink_ops.shutdown = sock_no_shutdown`. Generic socket
    /// security admission precedes the protocol's unsupported-operation errno.
    /// # C: O(1)
    pub fn shutdown(&self) -> Result<(), net::NetError> {
        net::security_admission::check_socket(
            net::net_ns::namespace_id(&self.net_ns),
            net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Shutdown,
            self.security_sid.load(core::sync::atomic::Ordering::Acquire),
            self.security_class(),
        ).map_err(|_| net::NetError::Eacces)?;
        Err(net::NetError::Eopnotsupp)
    }

    /// Apply Linux `netlink_ops.listen = sock_no_listen`. # C: O(1)
    pub fn listen(&self, backlog: i32) -> Result<(), net::NetError> {
        let namespace = net::net_ns::namespace_id(&self.net_ns);
        let somaxconn = net::sysctl::somaxconn_in(namespace).ok_or(net::NetError::Enodev)?;
        let backlog = net::sysctl::normalize_listen_backlog(backlog, somaxconn);
        net::security_admission::check_socket_listen(namespace,
            net::socket_args::AF_NETLINK_WIRE, backlog as u32,
            self.security_sid.load(core::sync::atomic::Ordering::Acquire),
            self.security_class())
            .map_err(|_| net::NetError::Eacces)?;
        Err(net::NetError::Eopnotsupp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKLOG_LIMIT: usize = 3;
    const REQUESTED_BACKLOG: i32 = 7;

    #[test]
    fn shutdown_is_the_linux_unsupported_socket_operation() {
        let socket = NetlinkSocket::new(crate::proto::NETLINK_ROUTE,
            &network_namespace::initial());
        assert_eq!(socket.shutdown(), Err(net::NetError::Eopnotsupp));
    }

    #[test]
    fn listen_admits_before_its_unsupported_operation_errno() {
        let namespace = crate::netlink_tests::test_namespace();
        let id = net::net_ns::namespace_id(&namespace);
        assert_eq!(net::sysctl::set_somaxconn_in(id, BACKLOG_LIMIT), Ok(()));
        let socket = NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace);
        assert_eq!(socket.listen(REQUESTED_BACKLOG), Err(net::NetError::Eopnotsupp));
        assert!(security::network::install(id, security::network::Operation::Listen,
            |context| {
                assert_eq!(context.backlog, Some(BACKLOG_LIMIT as u32));
                security::network::Verdict::Deny
            }).is_none());
        assert_eq!(socket.listen(REQUESTED_BACKLOG), Err(net::NetError::Eacces));
        assert!(security::network::remove(id, security::network::Operation::Listen).is_some());
    }
}
