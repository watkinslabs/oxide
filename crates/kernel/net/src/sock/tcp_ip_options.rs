use alloc::sync::Arc;

use super::InetSocket;
use crate::sock_opts::sol_ip::IpOpts;

/// Transfer the socket-owned sticky IPv4 options into a TCP entry. # C: O(1)
pub(crate) fn tcp_entry_ip_options(sock: &InetSocket) -> Arc<IpOpts> { sock.opts.ip.clone() }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sock_opts::sol_ip::flag;

    #[test]
    fn tcp_entry_retains_the_socket_ip_option_owner() {
        let sock = InetSocket::new_tcp();
        let entry_opts = tcp_entry_ip_options(&sock);

        assert!(Arc::ptr_eq(&entry_opts, &sock.opts.ip));
        sock.opts.ip.set_flag(flag::RECVOPTS, true);
        assert!(entry_opts.flag(flag::RECVOPTS));
    }
}
