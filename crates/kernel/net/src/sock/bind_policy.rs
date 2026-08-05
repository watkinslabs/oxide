use super::InetSocket;

/// One bind's immutable IP local-port policy snapshot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BindPortPolicy { pub defer: bool, pub range: u32 }

/// Read the two port-allocation inputs once from the socket that owns them.
/// # C: O(1)
pub fn bind_port_policy(sock: &InetSocket, requested_port: u16) -> BindPortPolicy {
    BindPortPolicy {
        defer: crate::local_port::defers_port(requested_port,
            sock.opts.ip.flag(crate::sock_opts::sol_ip::flag::BIND_ADDRESS_NO_PORT)),
        range: sock.opts.ip.local_port_range(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_carries_both_bind_port_inputs_to_every_family() {
        let sock = InetSocket::new_udp();
        sock.opts.ip.set_local_port_range((40_000u32) | (41_000u32 << 16));
        assert_eq!(bind_port_policy(&sock, 0), BindPortPolicy { defer: false,
            range: (40_000u32) | (41_000u32 << 16) });
        sock.opts.ip.set_flag(crate::sock_opts::sol_ip::flag::BIND_ADDRESS_NO_PORT, true);
        assert_eq!(bind_port_policy(&sock, 0), BindPortPolicy { defer: true,
            range: (40_000u32) | (41_000u32 << 16) });
        assert_eq!(bind_port_policy(&sock, 443).defer, false);
    }
}
