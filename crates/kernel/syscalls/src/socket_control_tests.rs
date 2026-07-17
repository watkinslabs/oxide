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

#[test]
fn packet_offload_options_use_linux_numbers_and_net_methods() {
    assert_eq!(net::uapi::PACKET_COPY_THRESH, 7);
    assert_eq!(net::uapi::PACKET_VNET_HDR, 15);
    assert_eq!(net::uapi::PACKET_TIMESTAMP, 17);
    assert_eq!(net::uapi::PACKET_TX_HAS_OFF, 19);
    assert_eq!(net::uapi::PACKET_QDISC_BYPASS, 20);
    assert_eq!(net::uapi::PACKET_VNET_HDR_SZ, 24);
    let set = include_str!("054_setsockopt/packet.rs");
    let get = include_str!("055_getsockopt/packet.rs");
    for method in [
        "set_packet_copy_thresh", "set_packet_vnet_hdr_size", "set_packet_timestamp",
        "set_packet_tx_has_off", "set_packet_qdisc_bypass",
    ] { assert!(set.contains(method)); }
    for method in [
        "packet_copy_thresh()", "packet_vnet_hdr_size()", "packet_timestamp()",
        "packet_tx_has_off()", "packet_qdisc_bypass()",
    ] { assert!(get.contains(method)); }
}

#[test]
fn packet_offload_set_abi_preserves_lengths_and_coercions() {
    let source = include_str!("054_setsockopt/packet.rs");
    let signed = source.split("fn packet_signed(").nth(1).unwrap();
    assert!(signed.contains("optlen != core::mem::size_of::<i32>() as u32"));
    assert!(signed.contains("i32::from_ne_bytes(bytes)"));
    let signed_flag = source.split("fn packet_signed_flag(").nth(1).unwrap();
    assert!(signed_flag.contains("optlen != core::mem::size_of::<i32>() as u32"));
    assert!(signed_flag.contains("i32::from_ne_bytes(bytes) != 0"));
    let unsigned_flag = source.split("fn packet_unsigned_flag(").nth(1).unwrap();
    assert!(unsigned_flag.contains("optlen != core::mem::size_of::<u32>() as u32"));
    assert!(unsigned_flag.contains("u32::from_ne_bytes(bytes) != 0"));
    assert!(source.contains("PACKET_COPY_THRESH => packet_signed"));
    assert!(source.contains("PACKET_TIMESTAMP => packet_signed"));
    assert!(source.contains("PACKET_TX_HAS_OFF => packet_unsigned_flag"));
    assert!(source.contains("PACKET_QDISC_BYPASS => packet_signed_flag"));
}

#[test]
fn packet_vnet_raw_rejection_precedes_length_and_usercopy() {
    let set = include_str!("054_setsockopt/packet.rs");
    let vnet = set.split("fn packet_vnet_hdr(").nth(1).unwrap();
    let raw = vnet.find("if !raw").unwrap();
    let length = vnet.find("if optlen <").unwrap();
    let copy = vnet.find("copy_from_user").unwrap();
    assert!(raw < length && length < copy);
    assert!(vnet.contains("else if value == 0 { 0 } else { net::uapi::VIRTIO_NET_HDR_LEN }"));

}

#[test]
fn packet_offload_get_abi_uses_native_i32_truncation() {
    let source = include_str!("055_getsockopt/packet.rs");
    for option in [
        "PACKET_COPY_THRESH", "PACKET_VNET_HDR", "PACKET_TIMESTAMP",
        "PACKET_TX_HAS_OFF", "PACKET_QDISC_BYPASS", "PACKET_VNET_HDR_SZ",
    ] { assert!(source.contains(option)); }
    assert!(source.contains("PacketOptionValue"));
    assert!(source.contains("value.output(requested as usize)"));
    assert!(source.contains("sock.packet_vnet_hdr_size().map(|size| i32::from(size != 0))"));
    assert!(source.contains("sock.packet_vnet_hdr_size().map(|size| size as i32)"));
}

#[test]
fn packet_getsockopt_uses_one_linux_ordered_copyout_transaction() {
    let source = include_str!("055_getsockopt/packet.rs");
    let dispatch = source.find("let value = match optname").unwrap();
    let unsupported = source.find("_ => return -(Errno::Enoprotoopt").unwrap();
    let output = source.find("let output = value.output").unwrap();
    let length = source.find("copy_to_user(optlen_p").unwrap();
    let value = source.find("copy_to_user(optval").unwrap();
    assert!(dispatch < unsupported && unsupported < output);
    assert!(output < length && length < value);
    assert_eq!(source.matches("copy_to_user(optval").count(), 1);
    assert_eq!(source.matches("copy_to_user(optlen_p").count(), 1);
    assert!(source.find("packet_statistics(sock)").unwrap() < length);
}

#[test]
fn generic_getsockopt_matches_canonical_socket_option_constants() {
    let source = include_str!("055_getsockopt.rs");
    for (qualified, unqualified) in [
        ("(SOL_SOCKET, net::uapi::SO_TYPE)", "(SOL_SOCKET, SO_TYPE)"),
        ("(SOL_SOCKET, net::uapi::SO_ACCEPTCONN)", "(SOL_SOCKET, SO_ACCEPTCONN)"),
        ("(SOL_SOCKET, net::uapi::SO_DOMAIN)", "(SOL_SOCKET, SO_DOMAIN)"),
        ("(SOL_SOCKET, net::uapi::SO_PROTOCOL)", "(SOL_SOCKET, SO_PROTOCOL)"),
    ] {
        assert!(source.contains(qualified));
        assert!(!source.contains(unqualified));
    }
}

#[test]
fn oobinline_setsockopt_normalizes_linux_boolean_values() {
    let source = include_str!("054_setsockopt/main.rs");
    assert!(source.contains(
        "sock.opts.oobinline.store((v != 0) as i32, Ordering::Release)"
    ));
}
