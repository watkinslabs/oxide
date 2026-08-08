use super::*;
use security::network::{self, Operation, Verdict};

fn deny(_context: network::Context) -> Verdict { Verdict::Deny }

/// The token records the family it was taken for, and a denial produces no
/// token at all — so a family operation that demands one cannot run.
#[test]
fn a_denial_yields_no_token_for_either_operation() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    for operation in [Operation::Bind, Operation::Connect] {
        assert!(network::install(ns, operation, deny).is_none());
    }
    let vsock = crate::socket_args::AF_VSOCK as u16;
    let netlink = crate::socket_args::AF_NETLINK_WIRE;
    assert!(matches!(admit_bind_in(ns, vsock), Err(NetError::Eacces)));
    assert!(matches!(admit_connect_in(ns, vsock), Err(NetError::Eacces)));
    assert!(matches!(admit_bind_in(ns, netlink), Err(NetError::Eacces)));
    assert!(matches!(admit_connect_in(ns, netlink), Err(NetError::Eacces)));
    assert_eq!(network::counters(ns, Operation::Bind), Some((0, 2)));
    assert_eq!(network::counters(ns, Operation::Connect), Some((0, 2)));
    assert!(network::remove_namespace(ns) >= 2);
}

/// An unpoliced namespace admits every family, so the token is not a second
/// policy of its own.
#[test]
fn an_unpoliced_namespace_admits_every_family() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    for family in [crate::socket_args::AF_VSOCK as u16, crate::socket_args::AF_NETLINK_WIRE,
                   crate::sock::AF_INET, crate::sock::AF_INET6] {
        assert!(admit_bind_in(ns, family).is_ok());
        assert!(admit_connect_in(ns, family).is_ok());
    }
}
