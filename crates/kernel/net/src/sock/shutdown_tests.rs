use super::*;

const PACKET_RAW: u8 = crate::socket_args::SOCK_RAW as u8;

fn packet_socket() -> InetSocket {
    InetSocket::new_packet_in(crate::eth_p::ALL, PACKET_RAW,
        crate::net_ns::test_support::allocate_namespace())
}

#[test]
fn packet_shutdown_is_linux_sock_no_shutdown_for_each_direction() {
    let sock = packet_socket();
    for how in [ShutdownHow::Read, ShutdownHow::Write, ShutdownHow::ReadWrite] {
        assert_eq!(shutdown(&sock, how), Err(NetError::Eopnotsupp));
        assert!(!sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
        assert!(!sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
    }
}
