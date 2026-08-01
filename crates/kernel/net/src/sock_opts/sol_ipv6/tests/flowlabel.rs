// `IPPROTO_IPV6` option coverage: flowlabel.

use syscall::errno::Errno;
use super::super::flowlabel::{self, FlowReq, Lease, Owner};
use super::super::state::Ipv6Opts;
use super::super::uapi::*;
use super::*;

// ---- the flow-label table -----------------------------------------------

#[test]
fn a_lease_shorter_than_the_floor_is_raised_and_a_long_one_is_privileged() {
    assert_eq!(flowlabel::check_linger(0, none()),
        Ok(flowlabel::FL_MIN_LINGER as u64 * 1_000_000_000));
    assert!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER, none()).is_ok());
    assert_eq!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER + 1, none()),
        Err(Errno::Eperm));
    assert!(flowlabel::check_linger(flowlabel::FL_MAX_LINGER + 1, net_admin()).is_ok());
}

#[test]
fn a_lease_needs_a_real_destination_and_a_known_sharing_mode() {
    let mut req = FlowReq { dst: [0u8; 16], share: IPV6_FL_S_ANY, ..Default::default() };
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
    // A mapped IPv4 destination is not an IPv6 flow.
    req.dst = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
    req.dst = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(flowlabel::admit_create(&req, none()).is_ok());
    req.share = 9;
    assert_eq!(flowlabel::admit_create(&req, none()), Err(Errno::Einval));
}

#[test]
fn an_exclusive_lease_is_never_shared_and_the_owner_must_match() {
    let owner = Owner { pid: 5, uid: 100 };
    let base = Lease { label: 7, dst: [0u8; 16], share: IPV6_FL_S_EXCL, owner,
        linger_ns: 0, expires_ns: 0, users: 1 };
    assert!(!flowlabel::shareable(&base, IPV6_FL_S_EXCL, owner));
    let any = Lease { share: IPV6_FL_S_ANY, ..base };
    assert!(flowlabel::shareable(&any, IPV6_FL_S_ANY, owner));
    // A different mode never matches.
    assert!(!flowlabel::shareable(&any, IPV6_FL_S_PROCESS, owner));
    let per_process = Lease { share: IPV6_FL_S_PROCESS, ..base };
    assert!(flowlabel::shareable(&per_process, IPV6_FL_S_PROCESS, owner));
    assert!(!flowlabel::shareable(&per_process, IPV6_FL_S_PROCESS,
        Owner { pid: 6, uid: 100 }));
    let per_user = Lease { share: IPV6_FL_S_USER, ..base };
    assert!(flowlabel::shareable(&per_user, IPV6_FL_S_USER, Owner { pid: 6, uid: 100 }));
    assert!(!flowlabel::shareable(&per_user, IPV6_FL_S_USER, Owner { pid: 6, uid: 101 }));
}

#[test]
fn the_table_interns_shares_and_releases_a_lease() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 0x12345, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 10, expires_ns: 100, users: 1 };
    assert_eq!(table.intern(1, lease, || 0).unwrap().label, 0x12345);
    // A second holder of the same label shares the entry.
    assert_eq!(table.intern(1, lease, || 0).unwrap().users, 2);
    assert_eq!(table.count(1), 1);
    // Namespaces do not share labels.
    assert_eq!(table.count(2), 0);
    assert!(table.release(1, 0x12345));
    assert_eq!(table.count(1), 1);
    assert!(table.release(1, 0x12345));
    assert_eq!(table.count(1), 0);
    assert!(!table.release(1, 0x12345));
}

#[test]
fn an_unnamed_label_is_allocated_from_the_label_space() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 0, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 10, expires_ns: 100, users: 1 };
    let got = table.intern(1, lease, || 0xfff_1234).unwrap();
    // The picked value is masked into the twenty-bit label field.
    assert_eq!(got.label, 0xfff_1234 & IPV6_FLOWINFO_FLOWLABEL);
    assert!(got.label != 0);
}

#[test]
fn renewing_a_lease_only_ever_extends_it() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 9, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 50, expires_ns: 1_000, users: 1 };
    table.intern(1, lease, || 0).unwrap();
    assert_eq!(table.renew(1, 8, 10, 10, 0), Err(Errno::Esrch));
    table.renew(1, 9, 10, 10, 0).unwrap();
    let after = table.lookup(1, 9).unwrap();
    assert_eq!(after.linger_ns, 50);
    assert_eq!(after.expires_ns, 1_000);
    table.renew(1, 9, 100, 2_000, 0).unwrap();
    let extended = table.lookup(1, 9).unwrap();
    assert_eq!(extended.linger_ns, 100);
    assert_eq!(extended.expires_ns, 2_000);
}

#[test]
fn an_expired_lease_is_retired() {
    let table = flowlabel::FlowLabels::new();
    let lease = Lease { label: 9, dst: [1u8; 16], share: IPV6_FL_S_ANY,
        owner: Owner::default(), linger_ns: 1, expires_ns: 100, users: 1 };
    table.intern(1, lease, || 0).unwrap();
    table.expire(50);
    assert!(table.lookup(1, 9).is_some());
    table.expire(100);
    assert!(table.lookup(1, 9).is_none());
}

#[test]
fn a_flow_label_request_round_trips_through_the_wire_form() {
    let req = FlowReq { dst: [7u8; 16], action: IPV6_FL_A_GET, share: IPV6_FL_S_USER,
        flags: IPV6_FL_F_CREATE, expires: 60, linger: 30, label: 0x2_3456 };
    assert_eq!(FlowReq::parse(&req.encode()), req);
}

#[test]
fn the_socket_lease_list_tracks_what_it_holds() {
    let opts = Ipv6Opts::default();
    assert!(!opts.holds_label(9));
    opts.hold_label(9);
    opts.hold_label(9);
    assert!(opts.holds_label(9));
    assert!(opts.release_label(9));
    assert!(!opts.release_label(9));
    opts.hold_label(1);
    opts.hold_label(2);
    assert_eq!(opts.take_labels(), alloc::vec![1, 2]);
    assert!(opts.take_labels().is_empty());
}
