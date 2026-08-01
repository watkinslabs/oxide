// The dispatch-instrumentation half, split out at the per-file size cutoff.
mod dispatch;

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
    assert!(shutdown.contains("vsock.shutdown_raw(how)"));
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
fn ipv6_tcp_bind_preserves_the_resolved_scope_owner() {
    let bind = include_str!("../../net/src/sock/ops.rs");
    assert!(bind.contains("crate::sock_v6::scoped_iface(sock, ip, scope_id)?"));
    assert!(bind.contains("bind_tcp(sock, crate::IpAddr::V6(ip), port, iface)"));
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

// The socket-level identity options are answered from one canonical table,
// and their option numbers have exactly one definition in the tree.
#[test]
fn generic_getsockopt_matches_canonical_socket_option_constants() {
    use net::sock_opts::sol_socket as sol;
    assert_eq!((net::uapi::SO_TYPE, net::uapi::SO_ACCEPTCONN, net::uapi::SO_DOMAIN,
        net::uapi::SO_PROTOCOL, net::uapi::SO_OOBINLINE, net::uapi::SOL_SOCKET),
        (sol::SO_TYPE, sol::SO_ACCEPTCONN, sol::SO_DOMAIN, sol::SO_PROTOCOL,
         sol::SO_OOBINLINE, sol::SOL_SOCKET));
    let source = include_str!("055_getsockopt.rs");
    assert!(source.contains("sol_socket::read(&sock, optname, optval, optlen_p)"));
    for owned in ["SO_TYPE", "SO_ACCEPTCONN", "SO_DOMAIN", "SO_PROTOCOL"] {
        assert!(!source.contains(&alloc::format!("(SOL_SOCKET, {owned})")));
        assert!(!source.contains(&alloc::format!("(SOL_SOCKET, net::uapi::{owned})")));
    }
    let table = include_str!("../../net/src/sock_opts/sol_socket/get.rs");
    for owned in ["SO_TYPE", "SO_ACCEPTCONN", "SO_DOMAIN", "SO_PROTOCOL"] {
        assert!(table.contains(&alloc::format!("{owned} =>")), "{owned}");
    }
}

#[test]
fn netlink_getsockopt_imports_optlen_before_dispatch_or_value_copyout() {
    let source = include_str!("netlink_fd.rs");
    let import = source.find("copy_from_user(&mut raw_len, optlen_p)").unwrap();
    let negative = source.find("if requested < 0").unwrap();
    let dispatch = source.find("let required = match (level, optname)").unwrap();
    let value = source.find("netlink_getsockopt_copyout(optval, optlen_p").unwrap();
    assert!(import < negative && negative < dispatch && dispatch < value);
    assert!(source[import..negative].contains("Errno::Efault"));
    assert!(source[negative..dispatch].contains("Errno::Einval"));
}

#[test]
fn netlink_getsockopt_keeps_linux_owned_options_and_rejects_unknowns() {
    let source = include_str!("netlink_fd.rs");
    let dispatch = source.split("let required = match (level, optname)").nth(1).unwrap();
    assert!(dispatch.contains("(net::uapi::SOL_SOCKET, net::uapi::SO_PROTOCOL)"));
    assert!(dispatch.contains("socket.protocol as u32"));
    assert!(dispatch.contains("(net::uapi::SOL_SOCKET, net::uapi::SO_TYPE)"));
    assert!(dispatch.contains("net::socket_args::SOCK_RAW"));
    assert!(dispatch.contains("(::netlink::sockopt::SOL_NETLINK, ::netlink::sockopt::NETLINK_LIST_MEMBERSHIPS)"));
    assert!(dispatch.contains("netlink_membership_words(socket.membership_words())"));
    let unknown = dispatch.find("_ => return -(Errno::Enoprotoopt").unwrap();
    let copyout = dispatch.find("netlink_getsockopt_copyout(optval").unwrap();
    assert!(unknown < copyout);
    assert!(!source.contains("write_volatile"));
    assert!(source.contains("out.extend_from_slice(&word.to_ne_bytes())"));
    assert!(source.contains("if copied != 0 && uaccess::copy_to_user(optval"));
    assert!(source.contains("uaccess::copy_to_user(optlen_p, &required.to_ne_bytes())"));
}

#[test]
fn netlink_connect_runs_one_admission_before_destination_state() {
    let route = include_str!("netlink_fd.rs");
    let owner = include_str!("../../netlink/src/destination.rs");
    let connect = route.split("pub fn connect(").nth(1).unwrap()
        .split("/// `setsockopt").next().unwrap();
    let admission = connect.find("security::network::Operation::Connect").unwrap();
    let disconnect = connect.find("socket.disconnect_destination()").unwrap();
    let destination = connect.find("socket.connect_destination(port_id, groups)").unwrap();
    assert_eq!(connect.matches("security::network::Operation::Connect").count(), 1);
    assert!(admission < disconnect && admission < destination);
    assert!(!owner.contains("security::network::Operation::Connect"));
}

// SO_OOBINLINE stores Linux's normalized boolean, and the normalization lives
// in the canonical table rather than the ABI shim.
#[test]
fn oobinline_setsockopt_normalizes_linux_boolean_values() {
    use net::sock_opts::sol_socket::set::{Action, Arg, SetEnv, admit};
    let sock = net::sock_opts::sol_socket::OptSock::default();
    let env = SetEnv::default();
    assert_eq!(admit(net::uapi::SO_OOBINLINE, Arg::Int(42), sock, env),
        Ok(Action::Oobinline(1)));
    assert_eq!(admit(net::uapi::SO_OOBINLINE, Arg::Int(0), sock, env),
        Ok(Action::Oobinline(0)));
    // Every non-zero value normalizes to the same stored 1, so a readback can
    // never report the caller's raw argument.
    for value in [1, 2, -1, i32::MIN, i32::MAX] {
        assert_eq!(admit(net::uapi::SO_OOBINLINE, Arg::Int(value), sock, env),
            Ok(Action::Oobinline(1)), "{value}");
    }
}

// B1376: IPV6_TCLASS / IPV6_RECVTCLASS carry the Linux optname values, and
// each is the exact twin of its HOPLIMIT counterpart — TCLASS a
// range-validated sticky store whose route sentinel resolves at write time,
// RECVTCLASS a boolean receive bit. The behaviour is asserted against the one
// ungated owner rather than against shim source text, so moving the shim
// cannot make the guarantee silently stop being checked.
#[test]
fn ipv6_tclass_recvtclass_use_linux_optnames_and_twin_shapes() {
    use net::sock_opts::sol_ipv6::set::{self, Action, Ipv6Sock, RECVHOPLIMIT, RECVTCLASS};
    use net::sock_opts::sol_ipv6::uapi::{IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS, IPV6_TCLASS};
    use net::sock_opts::sol_socket::OptCaps;
    assert_eq!((IPV6_TCLASS, IPV6_RECVTCLASS), (67, 66));
    let sock = Ipv6Sock { dgram: true, ..Default::default() };
    let admit = |name, val| set::admit(name, val, 4, sock, OptCaps::default());
    // The sticky class takes the route sentinel and the full byte window.
    assert_eq!(admit(IPV6_TCLASS, -1), Ok(Action::Tclass(0)));
    assert_eq!(admit(IPV6_TCLASS, 255), Ok(Action::Tclass(255)));
    assert_eq!(admit(IPV6_TCLASS, 256), Err(syscall::errno::Errno::Einval));
    assert_eq!(admit(IPV6_TCLASS, -2), Err(syscall::errno::Errno::Einval));
    // Both receive bits are booleans, and they are distinct bits.
    assert_eq!(admit(IPV6_RECVTCLASS, 42), Ok(Action::Flag { bit: RECVTCLASS, on: true }));
    assert_eq!(admit(IPV6_RECVTCLASS, 0), Ok(Action::Flag { bit: RECVTCLASS, on: false }));
    assert_ne!(RECVTCLASS, RECVHOPLIMIT);
    assert_eq!(admit(IPV6_RECVHOPLIMIT, 1), Ok(Action::Flag { bit: RECVHOPLIMIT, on: true }));
}

// B1376: recvmsg emits the IPV6_TCLASS ancillary from the captured traffic
// class only when IPV6_RECVTCLASS is enabled — mirroring the
// IPV6_HOPLIMIT/IPV6_RECVHOPLIMIT gate exactly. The receive plan owns the
// decision, so this asserts the behaviour rather than the shim's text.
#[test]
fn recvmsg_emits_ipv6_tclass_cmsg_gated_on_recvtclass() {
    use net::cmsg::{self, Msg, RxMeta, Want};
    let meta = RxMeta { hoplimit: Some(64), tclass: Some(0x28), ..Default::default() };
    assert!(cmsg::plan(&Want::default(), &meta).is_empty());
    let want = Want { tclass6: true, ..Default::default() };
    assert_eq!(cmsg::plan(&want, &meta), alloc::vec![Msg {
        level: cmsg::SOL_IPV6, kind: cmsg::IPV6_TCLASS,
        bytes: alloc::vec::Vec::from(0x28i32.to_ne_bytes()),
    }]);
    // The twin gate is separate: asking for the hop limit does not produce a
    // traffic class, and the hop limit precedes it when both are on.
    let hop = Want { hoplimit6: true, ..Default::default() };
    assert_eq!(cmsg::plan(&hop, &meta).len(), 1);
    let both = Want { hoplimit6: true, tclass6: true, ..Default::default() };
    let kinds: alloc::vec::Vec<i32> = cmsg::plan(&both, &meta).iter().map(|m| m.kind).collect();
    assert_eq!(kinds, alloc::vec![cmsg::IPV6_HOPLIMIT, cmsg::IPV6_TCLASS]);
    // A datagram that carried no traffic class produces no message.
    let absent = RxMeta { tclass: None, ..Default::default() };
    assert!(cmsg::plan(&want, &absent).is_empty());}

// A dual-stack AF_INET6 socket that connected to an IPv4 peer took the IPv4
// path, so its peer tuple is in `sock.peer`, not `sock.peer6`. Linux
// `inet6_getname` still answers with `sk->sk_v6_daddr` == `::ffff:a.b.c.d`
// (`net/ipv6/af_inet6.c`), so an empty `peer6` must FALL THROUGH to the
// generic tuple rather than short-circuit to ENOTCONN — that early return
// declared every `getaddrinfo(AI_V4MAPPED)` connection unconnected.

// `getsockname` on the same socket has the mirror bug: reading `local_ip6`
// unconditionally reported `[::]`. Linux reports `sk_v6_rcv_saddr` or, when
// that is unspecified, whatever local address the socket actually holds.

// The SOL_SOCKET options with their own argument or value shape are routed to
// their owner instead of the scalar table, and the option numbers come from the
// one canonical table.

// The peer identity one AF_UNIX end reports is a single snapshot, so
// SO_PEERCRED and SO_PEERGROUPS can never name two different instants.

// C245: the name-query and socketpair guarantees that used to be asserted by
// grepping the kernel-gated slot files are now asserted on BEHAVIOUR against
// their ungated owners — `sock_name` (which socket field answers a
// `getsockname`/`getpeername`, and the errno a socket with no such name
// reports), `net::sock_v6_name` (the `sin6_scope_id` rule) and
// `socketpair_spec` (the family/type admission and the AF_UNIX SOCK_RAW
// personality). The socketpair reserve-then-construct ordering is covered by
// `fd_pair::tests::rejected_socket_arguments_still_perturb_the_callers_array`.

// C246: the AF_PACKET option-ABI guarantees are asserted on BEHAVIOUR against
// `packet_optshape` — the ungated owner of the per-option `optlen` contract,
// the cooked-socket refusal that precedes any import, and the vnet-header
// value coercion the shim now calls instead of open-coding. Value truncation
// and the statistics layout are covered by `055_getsockopt/packet_abi.rs`.
