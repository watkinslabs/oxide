// Syscall dispatch instrumentation and the name-query/credential routes.
// Split out of `socket_control_tests` at the per-file size cutoff; the socket
// option and packet-family coverage stays in the parent.

use super::*;

#[test]
fn sshd_base_lifecycle_omits_per_syscall_trace_and_detail_retains_it() {
    let source = include_str!("../dispatch/core.rs");
    let enter = source.find("trace_sshd_listener_enter(nr, &args);").unwrap();
    let dispatch = source.find("if let Some(rv) = super::seccomp::seccomp_gate").unwrap();
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
    let manifest = include_str!("../../Cargo.toml");
    assert!(manifest.contains("debug-sshd = []"));
    assert!(manifest.contains("debug-sshd-detail = [\"debug-sshd\"]"));
}

#[test]
fn aarch64_sshd_exec_marker_follows_executable_path_publication() {
    let source = include_str!("../059_execve/aarch64.rs");
    let path = source.find("cur.set_exe_path(Some(path_str.clone()));").unwrap();
    let marker = source.find("trace_sshd_exec_success(cur.tid, &path_owned);").unwrap();
    assert!(path < marker);
    assert!(source.contains("#[cfg(feature = \"debug-sshd\")]\nfn trace_sshd_exec_success"));
    assert!(source.contains("[SSHD-EXEC] tid="));
    assert!(source.contains("path=/usr/sbin/sshd"));
}

#[test]
fn syscall_return_stages_are_feature_gated_ordered_and_cleared() {
    let source = include_str!("../dispatch/core.rs");
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
// path, so its peer tuple is in `sock.peer`, not `sock.peer6`. The peer name
// such a socket reports is still the v4-mapped form `::ffff:a.b.c.d`, so an
// empty `peer6` must FALL THROUGH to the generic tuple rather than
// short-circuit to ENOTCONN — that early return declared every
// `getaddrinfo(AI_V4MAPPED)` connection unconnected.
#[test]
fn ipv6_peername_falls_through_to_the_v4_mapped_tuple() {
    let source = include_str!("../052_getpeername.rs");
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
    let source = include_str!("../051_getsockname.rs");
    assert!(source.contains("v6_name_is_v4_mapped"),
        "the AF_INET6 branch routes through the shared name-source rule");
}

#[test]
fn connect_security_precedes_family_parse_and_unix_lookup_once() {
    let source = include_str!("../042_connect.rs");
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

    let set = include_str!("../054_setsockopt/sol_socket.rs");
    assert!(set.contains("ArgClass::Reuseport =>"));
    assert!(set.contains("ArgClass::Devmem => return devmem_dontneed("));
    assert!(set.contains("net::reuseport::attach_prog(sock, program)"));
    assert!(set.contains("net::reuseport::detach_prog(sock)"));
    // The buffer ceilings come from the live sysctl pair, not a constant.
    assert!(set.contains("ceilings: net::sysctl::buf_ceilings()"));

    let get = include_str!("../055_getsockopt.rs");
    for routed in ["SO_MEMINFO => return varlen::meminfo(",
        "SO_PEERGROUPS => {", "SO_PEERNAME => return varlen::peername(",
        "SO_PEERSEC => return varlen::peersec("]
    {
        assert!(get.contains(routed), "{routed}");
    }
    assert!(get.contains("if optname == SO_GET_FILTER { return varlen::get_filter("));
    // The scalar table must not claim any of them.
    let table = include_str!("../../../net/src/sock_opts/sol_socket/get.rs");
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
