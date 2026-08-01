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
fn packet_getpeername_preserves_the_packet_owner_error() {
    let peer = include_str!("052_getpeername.rs");
    let packet = peer.find("net::sock::AF_PACKET").unwrap();
    let unix = peer.find("net::sock::AF_UNIX").unwrap();
    assert!(packet < unix);
    assert!(peer[packet..unix].contains("Errno::Eopnotsupp"));
}

#[test]
fn packet_name_queries_route_to_packet_owned_abi() {
    let local = include_str!("051_getsockname.rs");
    assert!(local.contains("net::sock::packet_local_addr(&sock)"));
    assert!(local.contains("encoded_sockaddr_ll(packet)"));
}

#[test]
fn ipv6_name_queries_use_ipv6_socket_state() {
    let local = include_str!("051_getsockname.rs");
    let peer = include_str!("052_getpeername.rs");
    assert!(local.contains("sock.local_ip6.lock()"));
    assert!(peer.contains("sock.peer6.lock()"));
    for source in [local, peer] {
        assert!(source.contains("net::sock_v6::name_scope_id"));
        assert!(source.contains("net::sock_v6::name_bound_ifindex"));
    }
}

#[test]
fn tcp_peername_checks_transport_state_before_tuple_copyout() {
    let peer = include_str!("052_getpeername.rs");
    let state = peer.find("let tcp_peer_unavailable").unwrap();
    let ipv6 = peer.find("sock.peer6.lock()").unwrap();
    let ipv4 = peer.find("sock.peer.lock()").unwrap();
    assert!(state < ipv6);
    assert!(state < ipv4);
    assert!(peer[state..ipv6].contains("entry.peer_name_connected()"));
    assert!(peer[state..ipv6].contains("Errno::Enotconn"));
}

#[test]
fn ipv6_tcp_bind_preserves_the_resolved_scope_owner() {
    let bind = include_str!("../../net/src/sock/ops.rs");
    assert!(bind.contains("crate::sock_v6::scoped_iface(sock, ip, scope_id)?"));
    assert!(bind.contains("bind_tcp(sock, crate::IpAddr::V6(ip), port, iface)"));
}

#[test]
fn socketpair_reserves_and_copyouts_before_family_creation() {
    let source = include_str!("053_socketpair.rs");
    let install = source.find("crate::fd_pair::install_fd_pair").unwrap();
    let parse = source.find("let spec = parse_socket_args").unwrap();
    assert!(install < parse);
}

#[test]
fn socketpair_keeps_valid_non_unix_families_on_linux_unsupported_owner_path() {
    let source = include_str!("053_socketpair.rs");
    let parse = source.find("let spec = parse_socket_args").unwrap();
    let unsupported = source.find("if spec.family != AF_UNIX").unwrap();
    assert!(parse < unsupported);
    assert!(source[unsupported..].contains("Errno::Eopnotsupp"));
    assert!(!source[unsupported..].contains("Errno::Eafnosupport"));
}

#[test]
fn unix_raw_socketpair_uses_linux_datagram_personality() {
    let source = include_str!("053_socketpair.rs");
    assert!(source.contains("if spec.typ == SOCK_RAW { SOCK_DGRAM }"));
    assert!(source.contains("s.opts.so_type.store(socket_type"));
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
    assert!(source.contains("sol_socket::read(&s, optname, optval, optlen_p)"));
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
    assert!(include_str!("054_setsockopt/sol_socket.rs")
        .contains("Action::Oobinline(v) => sock.opts.oobinline.store(v, Ordering::Release)"));
}

// B1376: IPV6_TCLASS / IPV6_RECVTCLASS carry the Linux optname values and
// route through named UAPI constants (never inline literals). TCLASS is a
// range-validated (-1..=255) sticky store; RECVTCLASS is a boolean store —
// each the exact twin of its HOPLIMIT counterpart.
#[test]
fn ipv6_tclass_recvtclass_use_linux_optnames_and_twin_shapes() {
    for uapi in [include_str!("054_setsockopt/uapi.rs"), include_str!("055_getsockopt/uapi.rs")] {
        assert!(uapi.contains("IPV6_TCLASS: u64 = 67"));
        assert!(uapi.contains("IPV6_RECVTCLASS: u64 = 66"));
    }
    let set = include_str!("054_setsockopt/main.rs");
    let tclass = set.find("(IPPROTO_IPV6, IPV6_TCLASS) =>").unwrap();
    assert!(set[tclass..].contains("require_v6(&sock)"));
    assert!(set[tclass..].contains("if !(-1..=255).contains(&v)"));
    assert!(set[tclass..].contains("sock.opts.ipv6_tclass.store(v, Ordering::Release)"));
    let recvtclass = set.find("(IPPROTO_IPV6, IPV6_RECVTCLASS) =>").unwrap();
    assert!(set[recvtclass..]
        .contains("sock.opts.ipv6_recvtclass.store(if v != 0 { 1 } else { 0 }, Ordering::Release)"));

    let get = include_str!("055_getsockopt.rs");
    let get_tclass = get.find("(IPPROTO_IPV6, IPV6_TCLASS) =>").unwrap();
    // Unset (-1) sticky resolves to 0 on read, matching the TX path.
    assert!(get[get_tclass..].contains("if t < 0 { 0 } else { t }"));
    assert!(get.contains(
        "(IPPROTO_IPV6, IPV6_RECVTCLASS) => return i32_back(s.opts.ipv6_recvtclass.load(Ordering::Acquire))"
    ));
}

// B1376: recvmsg emits the IPV6_TCLASS ancillary from the captured
// Received.tclass only when IPV6_RECVTCLASS is enabled — mirroring the
// IPV6_HOPLIMIT/IPV6_RECVHOPLIMIT gate exactly.
#[test]
fn recvmsg_emits_ipv6_tclass_cmsg_gated_on_recvtclass() {
    let source = include_str!("recvmsg/inet.rs");
    assert!(source.contains("const IPV6_TCLASS: i32 = 67;"));
    let gate = source.find("if sock.opts.ipv6_recvtclass.load(Ordering::Acquire) != 0 {").unwrap();
    let emit = source[gate..].find(
        "if let Some(tclass) = rcv.tclass { out.push(IPPROTO_IPV6, IPV6_TCLASS,").unwrap();
    assert!(emit < source[gate..].find("if sock.packet_auxdata()").unwrap_or(usize::MAX));
}

#[test]
fn sshd_base_lifecycle_omits_per_syscall_trace_and_detail_retains_it() {
    let source = include_str!("dispatch/core.rs");
    let enter = source.find("trace_sshd_listener_enter(nr, &args);").unwrap();
    let dispatch = source.find("let entry = crate::dispatch_entry_order::entry_work(").unwrap();
    let exit = source.find("trace_sshd_listener_exit(nr, rv);").unwrap();
    let detail = source.find("#[cfg(feature = \"debug-sshd-detail\")]\n    trace_sshd_syscall(nr, rv);").unwrap();
    assert!(enter < dispatch);
    assert!(detail < exit);
    assert!(source.contains("#[cfg(feature = \"debug-sshd\")]\nfn trace_sshd_listener_enter"));
    assert!(source.contains("#[cfg(feature = \"debug-sshd\")]\nfn trace_sshd_listener_exit"));
    for nr in ["NR_SOCKET", "NR_BIND", "NR_LISTEN", "NR_ACCEPT4"] {
        assert!(source.contains(nr));
    }
    assert!(source.contains("[SSHD-LISTEN] enter"));
    assert!(source.contains("[SSHD-LISTEN] exit"));
    assert!(source.contains("#[cfg(feature = \"debug-sshd-detail\")]\nfn trace_sshd_syscall"));
    assert!(!source.contains("#[cfg(feature = \"debug-sshd\")]\nfn trace_sshd_syscall"));
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("debug-sshd = []"));
    assert!(manifest.contains("debug-sshd-detail = [\"debug-sshd\"]"));
}

#[test]
fn aarch64_sshd_exec_marker_follows_executable_path_publication() {
    let source = include_str!("059_execve/aarch64.rs");
    let path = source.find("cur.set_exe_path(Some(path_str.clone()));").unwrap();
    let marker = source.find("trace_sshd_exec_success(cur.tid, &path_owned);").unwrap();
    assert!(path < marker);
    assert!(source.contains("#[cfg(feature = \"debug-sshd\")]\nfn trace_sshd_exec_success"));
    assert!(source.contains("[SSHD-EXEC] tid="));
    assert!(source.contains("path=/usr/sbin/sshd"));
}

#[test]
fn syscall_return_stages_are_feature_gated_ordered_and_cleared() {
    let source = include_str!("dispatch/core.rs");
    let feature = "#[cfg(feature = \"debug-syscall-return\")]";
    let dispatch = source.find("SYSCALL_RETURN_STAGE_AFTER_DISPATCH").unwrap();
    let diag = source.find("SYSCALL_RETURN_STAGE_AFTER_DIAG").unwrap();
    let timers = source.find("SYSCALL_RETURN_STAGE_AFTER_TIMERS").unwrap();
    let rseq = source.find("SYSCALL_RETURN_STAGE_AFTER_RSEQ").unwrap();
    let ptrace = source.find("SYSCALL_RETURN_STAGE_AFTER_PTRACE").unwrap();
    let loop_stage = source.find("SYSCALL_RETURN_STAGE_IN_EXIT_TO_USER").unwrap();
    let clear = source.rfind("syscall_return_clear(task)").unwrap();
    // The `return_task` binding plus the six ordered stage markers
    // (DISPATCH/DIAG/TIMERS/RSEQ/PTRACE/IN_EXIT_TO_USER) are each
    // feature-gated; the DISPATCH marker's binding and emit are two
    // attributes, giving eight.
    //
    // B1471 dropped the ninth and tenth: the signal + restart arms used to
    // sit inline here and return EARLY, so each early exit needed its own
    // gated `syscall_return_clear`. They now live in the shared
    // `exit_to_user` loop (Linux `exit_to_user_mode_loop`, run by the IRQ and
    // exception return paths too), so this function has exactly ONE exit and
    // one clear.
    assert_eq!(source.matches(feature).count(), 8);
    assert!(dispatch < diag && diag < timers && timers < rseq && rseq < ptrace);
    assert!(ptrace < loop_stage && loop_stage < clear);
    assert_eq!(source.matches("syscall_return_clear(task)").count(), 1,
        "one exit from the tail means one clear");
    assert!(source.contains("crate::exit_to_user::exit_to_user_mode_loop(regs, Some(rv))"),
        "the tail delegates to the ONE return-to-user work loop");
}

// A dual-stack AF_INET6 socket that connected to an IPv4 peer took the IPv4
// path, so its peer tuple is in `sock.peer`, not `sock.peer6`. Linux
// `inet6_getname` still answers with `sk->sk_v6_daddr` == `::ffff:a.b.c.d`
// (`net/ipv6/af_inet6.c`), so an empty `peer6` must FALL THROUGH to the
// generic tuple rather than short-circuit to ENOTCONN — that early return
// declared every `getaddrinfo(AI_V4MAPPED)` connection unconnected.
#[test]
fn ipv6_peername_falls_through_to_the_v4_mapped_tuple() {
    let source = include_str!("052_getpeername.rs");
    let v6 = source.find("net::sock::AF_INET6").expect("the AF_INET6 branch exists");
    let tail = &source[v6..];
    let peer6 = tail.find("sock.peer6.lock()").expect("the branch reads peer6");
    let enotconn = tail.find("Errno::Enotconn").unwrap_or(tail.len());
    assert!(peer6 < enotconn,
        "the peer6 read must precede any ENOTCONN in the AF_INET6 branch");
    assert!(tail[..enotconn].contains("if let Some((ip, port)) = *sock.peer6.lock()"),
        "an absent native-v6 peer falls through instead of returning ENOTCONN");
}

// `getsockname` on the same socket has the mirror bug: reading `local_ip6`
// unconditionally reported `[::]`. Linux reports `sk_v6_rcv_saddr` or, when
// that is unspecified, whatever local address the socket actually holds.
#[test]
fn ipv6_sockname_consults_the_v4_mapped_source() {
    let source = include_str!("051_getsockname.rs");
    assert!(source.contains("v6_name_is_v4_mapped"),
        "the AF_INET6 branch routes through the shared name-source rule");
}

#[test]
fn connect_security_precedes_family_parse_and_unix_lookup_once() {
    let source = include_str!("042_connect.rs");
    let body = &source[source.find("pub fn sys_connect").expect("connect slot")..];
    let admission = body.find("net::sock::admit_connect").expect("generic admission");
    let family = body.find("let family = match storage.family()").expect("family parse");
    let unix_lookup = body.find("resolve_unix_addr").expect("UNIX lookup");
    assert!(admission < family && admission < unix_lookup);
    assert_eq!(body.matches("net::sock::admit_connect").count(), 1);
    assert!(body.contains("preflight_connect_admitted(&sock, admission)"));
    assert!(body.contains("connect_admitted("));
}

// The SOL_SOCKET options with their own argument or value shape are routed to
// their owner instead of the scalar table, and the option numbers come from the
// one canonical table.
#[test]
fn variable_shape_sol_socket_options_route_to_their_owners() {
    use net::sock_opts::sol_socket as sol;
    assert_eq!((sol::SO_ATTACH_REUSEPORT_CBPF, sol::SO_ATTACH_REUSEPORT_EBPF,
        sol::SO_DETACH_REUSEPORT_BPF, sol::SO_DEVMEM_DONTNEED), (51, 52, 68, 80));
    assert_eq!((sol::SO_MEMINFO, sol::SO_INCOMING_NAPI_ID, sol::SO_PEERGROUPS,
        sol::SO_PREFER_BUSY_POLL, sol::SO_BUSY_POLL_BUDGET), (55, 56, 59, 69, 70));
    assert_eq!((sol::SO_PEERNAME, sol::SO_PEERSEC, sol::SO_GET_FILTER), (28, 31, 26));

    let set = include_str!("054_setsockopt/sol_socket.rs");
    assert!(set.contains("ArgClass::Reuseport =>"));
    assert!(set.contains("ArgClass::Devmem => return devmem_dontneed("));
    assert!(set.contains("net::reuseport::attach_prog(sock, program)"));
    assert!(set.contains("net::reuseport::detach_prog(sock)"));
    // The buffer ceilings come from the live sysctl pair, not a constant.
    assert!(set.contains("ceilings: net::sysctl::buf_ceilings()"));

    let get = include_str!("055_getsockopt.rs");
    for routed in ["SO_MEMINFO => return varlen::meminfo(",
        "SO_PEERGROUPS => {", "SO_PEERNAME => return varlen::peername(",
        "SO_PEERSEC => return varlen::peersec("]
    {
        assert!(get.contains(routed), "{routed}");
    }
    assert!(get.contains("if optname == SO_GET_FILTER { return varlen::get_filter("));
    // The scalar table must not claim any of them.
    let table = include_str!("../../net/src/sock_opts/sol_socket/get.rs");
    for owned in ["SO_MEMINFO", "SO_PEERGROUPS", "SO_PEERNAME", "SO_PEERSEC", "SO_GET_FILTER",
        "SO_BUSY_POLL_BUDGET"]
    {
        assert!(!table.contains(&alloc::format!("{owned} =>")), "{owned}");
    }
    for owned in ["SO_PREFER_BUSY_POLL =>", "SO_INCOMING_NAPI_ID =>"] {
        assert!(table.contains(owned), "{owned}");
    }
}

// The peer identity one AF_UNIX end reports is a single snapshot, so
// SO_PEERCRED and SO_PEERGROUPS can never name two different instants.
#[test]
fn peer_credentials_and_groups_come_from_one_snapshot() {
    let pair = net::UnixPair::new();
    let groups: alloc::sync::Arc<[u32]> = alloc::vec![10u32, 20, 30].into();
    pair.set_end_cred(net::UnixEnd::A, net::PeerCred::new(7, 1000, 1000, Some(groups.clone())));
    // The peer of end B is end A.
    let seen = pair.peer_cred(net::UnixEnd::B);
    assert_eq!(seen.ids(), (7, 1000, 1000));
    assert_eq!(seen.group_count(), 3);
    assert_eq!(seen.groups.as_deref(), Some(&[10u32, 20, 30][..]));
    // A pair nobody published credentials for has no supplementary list.
    assert_eq!(pair.peer_cred(net::UnixEnd::A).group_count(), 0);
}
