#[test]
fn socket_control_routes_retain_one_file() {
    for source in [
        include_str!("048_shutdown.rs"),
        include_str!("050_listen.rs"),
        include_str!("052_getpeername.rs"),
    ] {
        assert_eq!(source.matches("fd_file(fd)").count(), 1);
        assert!(!source.contains("socket_from_fd"));
        assert!(!source.contains("vsock_from_fd"));
    }
}

#[test]
fn vsock_control_routes_use_the_pinned_endpoint() {
    let shutdown = include_str!("048_shutdown.rs");
    assert!(shutdown.contains("vsock_from_file(file.clone())"));
    assert!(shutdown.contains("vsock.shutdown(how)"));
    assert!(!shutdown.contains("make_hdr"));
    assert!(!shutdown.contains("VIRTIO_VSOCK_OP_SHUTDOWN"));

    let listen = include_str!("050_listen.rs");
    assert!(listen.contains("vsock_from_file(file.clone())"));

    let peer = include_str!("052_getpeername.rs");
    assert!(peer.contains("vsock_from_file(file.clone())"));
    assert!(peer.contains("vsock.peer_addr()"));
    assert!(peer.contains("encoded_sockaddr_vm(port, cid)"));
}

#[test]
fn control_routes_distinguish_bad_fd_from_non_socket() {
    for source in [
        include_str!("048_shutdown.rs"),
        include_str!("050_listen.rs"),
        include_str!("052_getpeername.rs"),
    ] {
        assert!(source.contains("None => return -(Errno::Ebadf.as_i32() as i64)"));
        assert!(source.contains("Errno::Enotsock"));
    }
}

#[test]
fn setsockopt_classifies_file_before_rejecting_negative_optlen() {
    let source = include_str!("054_setsockopt/main.rs");
    let classify = source.find("let sock = match socket_from_file(file)").unwrap();
    let negative = source[classify..].find("if signed_optlen < 0").unwrap() + classify;
    assert!(classify < negative);
    assert!(source[classify..negative].contains("Errno::Enotsock"));
}

#[test]
fn obsolete_packet_options_remain_explicitly_unsupported() {
    let set = include_str!("054_setsockopt/packet.rs");
    let get = include_str!("055_getsockopt/packet.rs");
    for source in [set, get] {
        assert!(!source.contains("PACKET_RECV_OUTPUT =>"));
        assert!(!source.contains("PACKET_TX_TIMESTAMP =>"));
        assert!(source.contains("_ =>"));
        assert!(source.contains("Errno::Enoprotoopt"));
    }
}

#[test]
fn packet_loss_uses_linux_number_and_dedicated_set_get_routes() {
    assert_eq!(net::uapi::PACKET_LOSS, 14);
    let set = include_str!("054_setsockopt/packet.rs");
    let get = include_str!("055_getsockopt/packet.rs");
    assert!(set.contains("PACKET_LOSS => packet_loss(sock, optval, optlen)"));
    let loss = set.split("fn packet_loss(").nth(1).unwrap();
    assert!(loss.contains("if optlen != core::mem::size_of::<i32>() as u32"));
    assert!(loss.contains("parse_packet_flag(&bytes, optlen as usize)"));
    assert!(set.contains("sock.set_packet_loss(value)"));
    assert!(get.contains("sock.packet_loss().map(i32::from)"));
}
