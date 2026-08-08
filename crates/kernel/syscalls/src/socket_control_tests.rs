// The dispatch-instrumentation half, split out at the per-file size cutoff.
mod dispatch;

// B1715: `shutdown`/`listen`/`accept`/`getpeername` used to be "covered" by
// grepping their kernel-gated slot files for `fd_file(fd)` and `Errno::Ebadf`
// — assertions that could not fail on a behaviour change and broke whenever
// the text moved. The ladder now lives in the ungated `sock_route`, which the
// slots call, so these drive the same code the kernel runs.

#[test]
fn control_routes_distinguish_bad_fd_from_non_socket() {
    use crate::sock_route::{ControlOp, Endpoint, route};
    for op in [ControlOp::Shutdown, ControlOp::Listen, ControlOp::Accept,
               ControlOp::GetPeerName] {
        // An fd naming no open file, and an open file that is no socket, are
        // different refusals — collapsing them tells a caller its fd is closed
        // when it is merely a pipe.
        assert_eq!(route(op, None, None), Err(syscall::errno::Errno::Ebadf), "{op:?}");
        assert_eq!(route(op, Some(Endpoint::NotSocket), None),
            Err(syscall::errno::Errno::Enotsock), "{op:?}");
    }
}

#[test]
fn vsock_control_routes_reach_the_vsock_endpoint() {
    use crate::sock_route::{ControlOp, Endpoint, endpoint_of, route};
    let socket = alloc::sync::Arc::new(net::vsock_socket::VsockSocket::new());
    let inode = net::vsock_socket::make_vsock_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    // Every control call on an AF_VSOCK file reaches the vsock endpoint rather
    // than falling through to the INET tail or to ENOTSOCK.
    for op in [ControlOp::Shutdown, ControlOp::Listen, ControlOp::Accept,
               ControlOp::GetPeerName] {
        assert_eq!(route(op, Some(endpoint_of(&file)), None), Ok(Endpoint::Vsock), "{op:?}");
    }
}

// The AF_VSOCK peer name a `getpeername` copies out carries the port and CID
// in the `struct sockaddr_vm` slots, so the encoding is checked on the bytes
// rather than on the shim's call text.
#[test]
fn vsock_peer_name_encodes_its_cid_and_port_in_place() {
    let sa = crate::sockaddr_encode::encoded_sockaddr_vm(0x1234, 0x2a);
    let bytes = sa.as_bytes();
    assert_eq!(u16::from_ne_bytes([bytes[0], bytes[1]]), net::sock::AF_VSOCK as u16);
    assert_eq!(u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 0x1234);
    assert_eq!(u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]), 0x2a);
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
fn netlink_getsockopt_negative_optlen_is_rejected_by_the_live_policy_owner() {
    use crate::netlink_getsockopt_policy::requested_len;
    assert_eq!(requested_len((-1i32).to_ne_bytes()), Err(syscall::errno::Errno::Einval));
    assert_eq!(requested_len(0i32.to_ne_bytes()), Ok(0));
    assert_eq!(requested_len(4i32.to_ne_bytes()), Ok(4));
}

#[test]
fn netlink_getsockopt_keeps_linux_owned_options_and_rejects_unknowns() {
    let source = include_str!("netlink_fd.rs");
    // SOL_SOCKET is answered by the ONE generic table every family reads, so
    // this shim carries no identity arm of its own to disagree with it.
    assert!(source.contains("sol_socket::get(target, optname, requested)"));
    assert!(!source.contains("(net::uapi::SOL_SOCKET, net::uapi::SO_PROTOCOL)"));
    assert!(!source.contains("(net::uapi::SOL_SOCKET, net::uapi::SO_TYPE)"));
    let dispatch = source.split("let copied = match (level, optname)").nth(1).unwrap();
    // SOL_NETLINK answers are owned by the netlink crate's decision table, not
    // by a second switch in the shim.
    assert!(dispatch.contains("(::netlink::sockopt::SOL_NETLINK, name) => match ::netlink::get_answer(name)"));
    assert!(dispatch.contains("netlink_membership_words(socket.membership_words())"));
    assert!(dispatch.contains("socket.flags.get(bit)"));
    assert_eq!(::netlink::get_answer(::netlink::sockopt::NETLINK_LIST_MEMBERSHIPS),
        ::netlink::GetAnswer::Memberships);
    assert_eq!(::netlink::get_answer(::netlink::sockopt::NETLINK_GET_STRICT_CHK),
        ::netlink::GetAnswer::Flag(::netlink::F_STRICT_CHK));
    assert_eq!(::netlink::get_answer(::netlink::sockopt::NETLINK_ADD_MEMBERSHIP),
        ::netlink::GetAnswer::Unknown);
    let unknown = dispatch.find("_ => return -(Errno::Enoprotoopt").unwrap();
    let copyout = dispatch.find("netlink_getsockopt_copyout(optval").unwrap();
    assert!(unknown < copyout);
    assert!(!source.contains("write_volatile"));
    assert!(source.contains("out.extend_from_slice(&word.to_ne_bytes())"));
    assert!(source.contains("if !value.is_empty() && uaccess::copy_to_user(optval"));
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
    let destination = connect.find("socket.connect_destination(dest.port_id, dest.group)").unwrap();
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
// `inet6_getname` still answers with `sk->sk_v6_daddr` == `::ffff:a.b.c.d`,
// so an empty `peer6` must FALL THROUGH to the
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

#[test]
fn netlink_setsockopt_reports_enoprotoopt_for_an_option_it_does_not_implement() {
    // Accepting an unknown SOL_NETLINK option and returning success tells the
    // client a setting took effect that never did. The shim reaches the
    // decision table for every optname and has no silent fall-through.
    let source = include_str!("netlink_fd.rs");
    let body = source.split("pub fn setsockopt(").nth(1).unwrap()
        .split("/// `CAP_NET_BROADCAST`").next().unwrap();
    assert!(body.contains("match ::netlink::set_action(optname)"));
    assert!(body.contains("SetAction::Unknown => -(Errno::Enoprotoopt"));
    assert!(!body.contains("matches!(optname"), "no second optname table in the shim");
    for name in [::netlink::sockopt::NETLINK_RX_RING, ::netlink::sockopt::NETLINK_TX_RING,
                 ::netlink::sockopt::NETLINK_LIST_MEMBERSHIPS, u64::MAX] {
        assert_eq!(::netlink::set_action(name), ::netlink::SetAction::Unknown);
    }
    // A short option is not an error in netlink: the value simply stays zero.
    assert!(body.contains("if optlen >= NETLINK_OPTION_BYTES"));
    assert!(body.contains("Errno::Efault"), "a bad pointer is EFAULT, not EINVAL");
}

// SOL_SOCKET on a netlink fd is the SAME generic decision every other family
// makes. A second table here diverged in three ways at once: it validated only
// three option numbers and silently reported success for the rest, it kept its
// own timeval arithmetic with no EDOM screen and no negative-seconds rule, and
// it answered the buffer sizes as unreadable while accepting writes to them.
#[test]
fn netlink_sol_socket_defers_to_the_one_generic_table() {
    let source = include_str!("netlink_fd/sol_socket.rs");
    assert!(source.contains("crate::s054_setsockopt::sol_socket::import(optname, optval, optlen)"),
        "the argument import is the canonical one");
    assert!(source.contains("sol::set::admit(optname, arg, personality(), env)"),
        "the admission ladder is the canonical one");
    assert!(source.contains("sol::get::value(optname, requested, &socket.generic, &view)"),
        "the read table is the canonical one");
    // No arithmetic, no length rule and no capability gate of its own.
    for reimplementation in ["NSEC_PER_USEC", "TIMEVAL_BYTES", "may_scm_recv", "Errno::Edom"] {
        assert!(!source.contains(reimplementation),
            "{reimplementation} belongs to the generic table, not to this shim");
    }
    // The rules that shim now inherits, asserted on the owner itself.
    use net::sock_opts::sol_socket::timeout_ns_from_timeval as timeout;
    assert_eq!(timeout(1, 1_000_000), Err(syscall::errno::Errno::Edom));
    assert_eq!(timeout(1, -1), Err(syscall::errno::Errno::Edom));
    assert_eq!(timeout(-1, 500), Ok(net::sock_opts::sol_socket::IMMEDIATE_TIMEOUT_NS));
    assert_eq!(timeout(0, 0), Ok(0));
}

#[test]
fn netlink_membership_and_listen_all_nsid_carry_their_capability_gates() {
    let source = include_str!("netlink_fd.rs");
    assert!(source.contains("!::netlink::nonroot_recv(socket.protocol) && !has_net_admin(socket)"));
    assert!(source.contains("sched::cap::NET_BROADCAST"));
    assert!(::netlink::nonroot_recv(::netlink::proto::NETLINK_ROUTE));
    assert!(!::netlink::nonroot_recv(::netlink::proto::NETLINK_NETFILTER));
    assert_eq!(::netlink::set_action(::netlink::sockopt::NETLINK_LISTEN_ALL_NSID),
        ::netlink::SetAction::PrivilegedFlag(::netlink::F_LISTEN_ALL_NSID));
}
