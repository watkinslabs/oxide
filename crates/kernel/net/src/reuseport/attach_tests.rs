//! `SO_ATTACH_REUSEPORT_EBPF` program admission.

use super::*;

const INET_TCP: SockShape = SockShape { stream_or_dgram: true, tcp_or_udp: true, inet: true };

#[test]
fn a_socket_filter_attaches_to_any_socket_that_has_a_group() {
    for shape in [INET_TCP,
        SockShape { stream_or_dgram: false, ..INET_TCP },
        SockShape { tcp_or_udp: false, ..INET_TCP },
        SockShape { inet: false, ..INET_TCP }]
    {
        assert_eq!(admit_reuseport_prog(ProgFlavour::SocketFilter, shape),
            Ok(FilterKind::Ebpf));
    }
}

#[test]
fn a_selection_program_steers_only_an_inet_stream_or_datagram_socket() {
    assert_eq!(admit_reuseport_prog(ProgFlavour::SkReuseport, INET_TCP),
        Ok(FilterKind::SkReuseport));
    for shape in [
        SockShape { stream_or_dgram: false, ..INET_TCP },
        SockShape { tcp_or_udp: false, ..INET_TCP },
        SockShape { inet: false, ..INET_TCP }]
    {
        assert_eq!(admit_reuseport_prog(ProgFlavour::SkReuseport, shape),
            Err(Errno::Enotsupp), "{shape:?}");
    }
}

#[test]
fn the_refusal_is_not_the_errno_bpf_uses_for_an_unsupported_command() {
    // `ENOTSUPP` is kernel-internal and distinct from `EOPNOTSUPP`; a caller
    // told the wrong one would read it as the socket refusing the option.
    assert_ne!(Errno::Enotsupp, Errno::Eopnotsupp);
    assert_eq!(admit_reuseport_prog(ProgFlavour::SkReuseport,
        SockShape { inet: false, ..INET_TCP }), Err(Errno::Enotsupp));
}

#[test]
fn any_other_program_type_is_not_a_reuseport_program() {
    assert_eq!(admit_reuseport_prog(ProgFlavour::Other, INET_TCP), Err(Errno::Einval));
}
