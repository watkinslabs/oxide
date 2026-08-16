// The collision-avoiding search. A tuple handed out twice merges two
// conversations, so these drive the allocator against a taken-set it cannot
// see through.

extern crate alloc;
use alloc::vec::Vec;
use core::cell::RefCell;

use conntrack::tuple::{InetAddr, Tuple};

use crate::range::*;
use crate::unique::*;
use crate::uapi::*;
use super::range::{icmp, tcp};

struct Env {
    taken: RefCell<Vec<Tuple>>,
    rand: RefCell<u16>,
    prior: Option<Tuple>,
    evictable: bool,
    pub evictions: RefCell<u32>,
}

impl Env {
    fn new() -> Self {
        Self { taken: RefCell::new(Vec::new()), rand: RefCell::new(0),
               prior: None, evictable: false, evictions: RefCell::new(0) }
    }
    fn take(&self, t: Tuple) { self.taken.borrow_mut().push(t); }
}

impl NatEnv for Env {
    fn tuple_taken(&self, t: &Tuple) -> bool { self.taken.borrow().contains(t) }
    fn random_u16(&self) -> u16 {
        let mut r = self.rand.borrow_mut();
        *r = r.wrapping_mul(25173).wrapping_add(13849);
        *r
    }
    fn try_evict(&self, t: &Tuple) -> bool {
        if !self.evictable { return false; }
        *self.evictions.borrow_mut() += 1;
        let mut g = self.taken.borrow_mut();
        if let Some(i) = g.iter().position(|x| x == t) { g.remove(i); true } else { false }
    }
    fn find_appropriate_src(&self, _orig: &Tuple, _r: &NatRange) -> Option<Tuple> {
        self.prior
    }
}

fn snat_to(addr: [u8; 4]) -> NatRange {
    NatRange::single_addr(InetAddr::v4(addr), 0)
}

#[test]
fn an_unused_tuple_already_in_range_is_left_alone() {
    let env = Env::new();
    let t = tcp([203, 0, 113, 5], 1234, [93, 184, 216, 34], 80);
    let r = snat_to([203, 0, 113, 5]);
    assert_eq!(get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), Some(t),
        "an unnecessary rewrite is a bug, not a nicety");
}

#[test]
fn an_out_of_range_source_is_moved_into_the_range() {
    let env = Env::new();
    let t = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let r = snat_to([203, 0, 113, 5]);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_eq!(&out.src.addr.0[..4], &[203, 0, 113, 5]);
    assert_eq!(&out.dst.addr.0[..4], &[93, 184, 216, 34], "the far end is untouched");
}

#[test]
fn a_taken_tuple_forces_a_different_port() {
    let env = Env::new();
    let t = tcp([203, 0, 113, 5], 1234, [93, 184, 216, 34], 80);
    env.take(t);
    let r = snat_to([203, 0, 113, 5]);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_ne!(out.src.proto.port, 1234, "handing out a live tuple merges two flows");
    assert!(!env.tuple_taken(&out));
    assert!(out.src.proto.port >= 1024, "an ephemeral source keeps an ephemeral mapping");
}

#[test]
fn a_privileged_source_stays_privileged_after_a_collision() {
    let env = Env::new();
    let t = tcp([203, 0, 113, 5], 100, [93, 184, 216, 34], 80);
    env.take(t);
    let r = snat_to([203, 0, 113, 5]);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert!((1..=511).contains(&out.src.proto.port),
        "a reserved-port source must not be mapped into the ephemeral range");
}

#[test]
fn an_explicit_port_range_is_honoured() {
    let env = Env::new();
    let t = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 20000, max_proto: 20009, ..Default::default() };
    for _ in 0..10 {
        let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
        assert!((20000..=20009).contains(&out.src.proto.port), "{out:?}");
        env.take(out);
    }
    // The window is now full and the search must fail rather than duplicate.
    assert_eq!(get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), None);
}

#[test]
fn a_single_port_range_is_accepted_even_when_taken() {
    // With exactly one legal port there is nothing to search: the rule asked
    // for that port and the allocator must not silently pick another.
    let env = Env::new();
    let t = tcp([10, 0, 0, 1], 20000, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 20000, max_proto: 20000, ..Default::default() };
    let first = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_eq!(first.src.proto.port, 20000);
    env.take(first);
    let again = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_eq!(again.src.proto.port, 20000);
}

#[test]
fn a_one_port_range_the_flow_is_not_already_on_must_still_be_searched() {
    // The shortcut above only applies when the tuple already presents the one
    // legal port. Otherwise the port really is occupied and there is nowhere
    // else to go, so the allocation fails rather than duplicating.
    let env = Env::new();
    let t = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 20000, max_proto: 20000, ..Default::default() };
    let first = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_eq!(first.src.proto.port, 20000);
    env.take(first);
    assert_eq!(get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), None);
}

#[test]
fn a_prior_mapping_for_the_same_client_is_reused() {
    let mut env = Env::new();
    let prior = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    env.prior = Some(prior);
    let t = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let r = snat_to([203, 0, 113, 5]);
    assert_eq!(get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), Some(prior),
        "consistency is what lets address-carrying protocols work behind NAT");
}

#[test]
fn a_prior_mapping_that_is_now_taken_is_not_reused() {
    let mut env = Env::new();
    let prior = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    env.prior = Some(prior);
    env.take(prior);
    let t = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let r = snat_to([203, 0, 113, 5]);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_ne!(out, prior);
}

#[test]
fn a_random_request_ignores_the_prior_mapping() {
    let mut env = Env::new();
    let prior = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    env.prior = Some(prior);
    let t = tcp([203, 0, 113, 5], 1234, [93, 184, 216, 34], 80);
    let r = NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]),
                                  NF_NAT_RANGE_PROTO_RANDOM);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_ne!(out, prior, "randomness is the point of the flag");
    assert_ne!(out.src.proto.port, 1234, "and the original port is not kept either");
}

#[test]
fn icmp_ids_are_reallocated_on_collision() {
    let env = Env::new();
    let t = icmp([203, 0, 113, 5], [93, 184, 216, 34], 100);
    env.take(t);
    let r = snat_to([203, 0, 113, 5]);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_ne!(out.src.proto.port, 100);
    assert_eq!(out.dst.proto.icmp_type, 8, "the message type is not a port");
}

#[test]
fn a_full_window_gives_up_rather_than_duplicating() {
    let env = Env::new();
    let t = tcp([203, 0, 113, 5], 1234, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 30000, max_proto: 30003, ..Default::default() };
    for p in 30000..=30003u16 {
        let mut taken = t;
        taken.src.proto.port = p;
        env.take(taken);
    }
    assert_eq!(unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), None);
}

#[test]
fn eviction_only_engages_near_the_end_of_the_search() {
    // Evicting a live flow to free a port is a last resort: doing it on the
    // first probe would tear down connections whenever a port happened to be
    // busy. It must not fire while plenty of attempts remain.
    let mut env = Env::new();
    env.evictable = true;
    // Offset mode makes the probe order deterministic, so "how far in did the
    // search get" is an assertion rather than a coin toss.
    let t = tcp([203, 0, 113, 5], 30000, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED
                              | NF_NAT_RANGE_PROTO_OFFSET,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 30000, max_proto: 30200, base_proto: 30000, ..Default::default() };
    // The first 32 ports are busy; the 33rd probe finds a free one with 95
    // attempts still in hand, which is well above the eviction threshold.
    for p in 30000..30032u16 {
        let mut taken = t;
        taken.src.proto.port = p;
        env.take(taken);
    }
    let out = unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env).unwrap();
    assert_eq!(out.src.proto.port, 30032);
    assert_eq!(*env.evictions.borrow(), 0, "nothing needed to be torn down");
}

#[test]
fn eviction_is_reached_when_the_window_is_genuinely_full() {
    let mut env = Env::new();
    env.evictable = true;
    let t = tcp([203, 0, 113, 5], 1234, [93, 184, 216, 34], 80);
    let r = NatRange { flags: NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED,
        min_addr: InetAddr::v4([203, 0, 113, 5]),
        max_addr: InetAddr::v4([203, 0, 113, 5]),
        min_proto: 30000, max_proto: 30003, ..Default::default() };
    for p in 30000..=30003u16 {
        let mut taken = t;
        taken.src.proto.port = p;
        env.take(taken);
    }
    let out = unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env);
    assert!(out.is_some(), "a closing flow may be evicted to free its port");
    assert!(*env.evictions.borrow() > 0);
}

#[test]
fn the_search_terminates_on_a_fully_taken_default_window() {
    // Every probe collides and nothing is evictable. The bound is what keeps
    // this from scanning 64k ports in softirq on every packet.
    struct AllTaken;
    impl NatEnv for AllTaken {
        fn tuple_taken(&self, _t: &Tuple) -> bool { true }
        fn random_u16(&self) -> u16 { 7 }
    }
    let t = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    let r = snat_to([203, 0, 113, 5]);
    assert_eq!(unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &AllTaken), None);
}

#[test]
fn a_protocol_with_no_port_field_passes_through_unchanged() {
    let env = Env::new();
    let mut t = tcp([203, 0, 113, 5], 0, [93, 184, 216, 34], 0);
    t.protonum = 47;
    let r = snat_to([203, 0, 113, 5]);
    assert_eq!(unique_tuple(&t, &r, NF_NAT_MANIP_SRC, &env), Some(t));
}

#[test]
fn a_destination_binding_does_not_reuse_a_source_mapping() {
    // The reuse path exists to keep one CLIENT consistent. Applying it to a
    // destination translation would redirect a flow to wherever some unrelated
    // source was last mapped.
    let mut env = Env::new();
    env.prior = Some(tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80));
    let t = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let r = NatRange::single_addr(InetAddr::v4([10, 0, 0, 9]), 0);
    let out = get_unique_tuple(&t, &r, NF_NAT_MANIP_DST, &env).unwrap();
    assert_eq!(&out.dst.addr.0[..4], &[10, 0, 0, 9]);
    assert_eq!(out.dst.proto.port, 80, "no explicit range means the port stands");
    assert_eq!(&out.src.addr.0[..4], &[10, 0, 0, 1]);
}
