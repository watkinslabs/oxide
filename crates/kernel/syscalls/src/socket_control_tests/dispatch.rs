// Syscall dispatch instrumentation and the name-query/credential routes.
// Split out of `socket_control_tests` at the per-file size cutoff; the socket
// option and packet-family coverage stays in the parent.

use super::*;






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

// Resolving a pathname AF_UNIX address for `connect(2)` carries a filesystem
// right. The decision is behaviourally covered in `net::landlock_addr`; what
// this guards is the call disappearing from the one resolution site, or
// drifting ahead of the checks whose errors it would mask. The domain comes off
// the running task, so a hosted build cannot drive it any other way.
#[test]
fn connect_gates_pathname_unix_resolution_after_the_socket_type_check() {
    let source = include_str!("../namei_common.rs");
    let body = &source[source.find("fn resolve_unix_addr").expect("resolve slot")..];
    let hook = body.find("net::landlock_addr::check_unix_resolve(&p, &addr)")
        .expect("UNIX resolve gate");
    // A name that is not a socket keeps ECONNREFUSED.
    assert!(body.find("p.inode.file_type() != vfs::FileType::Socket").expect("type check")
        < hook);
    // Abstract names return before the path lookup and never reach the gate.
    assert!(body.find("net::unix_path_is_abstract(&path)").expect("abstract split") < hook);
    assert_eq!(body.matches("check_unix_resolve").count(), 1);
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

// C245: the v4-mapped dual-stack name rules moved to `sock_name::tests`, where
// they are asserted on the bytes each socket state actually reports.

// C246: the sshd-trace and syscall-return-stage instrumentation is DEBUG-ONLY
// scaffolding — it has no observable production behaviour, so no behavioural
// test can exist for it. What those grep tests actually guarded against was the
// blocks failing to COMPILE, which `make feature-gate` now covers directly:
// `GATE_FEATURES` derives its list from `kmain`'s manifest and so type-checks
// both arches with `debug-sshd`, `debug-sshd-detail` and
// `debug-syscall-return` among the other 84. Verified by reinstating a type
// error inside `trace_sshd_listener_enter`: the default build reports 0 errors,
// `make feature-gate-x86` fails E0308.
