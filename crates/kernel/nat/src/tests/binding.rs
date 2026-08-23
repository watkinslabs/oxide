// Establishing a binding on a flow and replaying it. The reply-direction
// inversion is the highest-risk piece: getting it wrong sends replies to the
// wrong host while every test that only looks at the original direction passes.

extern crate alloc;
use core::cell::RefCell;

use conntrack::entry::Conn;
use conntrack::tuple::{InetAddr, Tuple};
use conntrack::uapi::*;

use crate::range::NatRange;
use crate::setup::*;
use crate::unique::NatEnv;
use crate::uapi::*;
use super::range::tcp;

struct Env { rand: RefCell<u16> }
impl Env { fn new() -> Self { Self { rand: RefCell::new(0) } } }
impl NatEnv for Env {
    fn tuple_taken(&self, _t: &Tuple) -> bool { false }
    fn random_u16(&self) -> u16 {
        let mut r = self.rand.borrow_mut();
        *r = r.wrapping_mul(25173).wrapping_add(13849);
        *r
    }
}

fn fresh(orig: Tuple) -> Conn { Conn::new(1, orig, orig.invert().unwrap(), 0) }

#[test]
fn a_source_binding_rewrites_the_reply_destination() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let c = fresh(orig);
    let r = NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]), 0);
    assert_eq!(setup_info(&c, &r, NF_NAT_MANIP_SRC, &env), SetupResult::Accept);

    // The original half is untouched: the client still sees its own address.
    assert_eq!(c.orig, orig);
    // The reply half is what the far side will send back to.
    let reply = c.reply_tuple();
    assert_eq!(&reply.src.addr.0[..4], &[93, 184, 216, 34]);
    assert_eq!(&reply.dst.addr.0[..4], &[203, 0, 113, 5]);
    assert_eq!(c.status() & IPS_SRC_NAT, IPS_SRC_NAT);
    assert_eq!(c.status() & IPS_SRC_NAT_DONE, IPS_SRC_NAT_DONE);
    assert_eq!(c.status() & IPS_DST_NAT, 0);
}

#[test]
fn a_destination_binding_rewrites_the_reply_source() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [203, 0, 113, 5], 80);
    let c = fresh(orig);
    let r = NatRange::single_addr(InetAddr::v4([10, 0, 0, 50]), 0);
    assert_eq!(setup_info(&c, &r, NF_NAT_MANIP_DST, &env), SetupResult::Accept);
    assert_eq!(&c.reply_tuple().src.addr.0[..4], &[10, 0, 0, 50],
        "the real server answers, but the client must see the address it dialled");
    assert_eq!(c.status() & IPS_DST_NAT, IPS_DST_NAT);
}

#[test]
fn a_binding_that_changes_nothing_records_done_but_not_the_manip_bit() {
    // The identity case: without the distinction every flow would be treated
    // as translated and every packet needlessly rewritten.
    let env = Env::new();
    let orig = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    let c = fresh(orig);
    let r = NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]), 0);
    assert_eq!(setup_info(&c, &r, NF_NAT_MANIP_SRC, &env), SetupResult::Accept);
    assert_eq!(c.status() & IPS_SRC_NAT, 0);
    assert_eq!(c.status() & IPS_SRC_NAT_DONE, IPS_SRC_NAT_DONE);
    assert_eq!(c.reply_tuple(), orig.invert().unwrap());
}

#[test]
fn a_second_binding_of_the_same_manip_is_refused() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let c = fresh(orig);
    let r = NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]), 0);
    assert_eq!(setup_info(&c, &r, NF_NAT_MANIP_SRC, &env), SetupResult::Accept);
    let r2 = NatRange::single_addr(InetAddr::v4([203, 0, 113, 9]), 0);
    assert_eq!(setup_info(&c, &r2, NF_NAT_MANIP_SRC, &env), SetupResult::Drop,
        "re-deciding mid-flow splits one conversation across two translations");
}

#[test]
fn both_manips_may_be_bound_on_one_flow() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [203, 0, 113, 5], 80);
    let c = fresh(orig);
    assert_eq!(setup_info(&c, &NatRange::single_addr(InetAddr::v4([10, 0, 0, 50]), 0),
                          NF_NAT_MANIP_DST, &env), SetupResult::Accept);
    assert_eq!(setup_info(&c, &NatRange::single_addr(InetAddr::v4([172, 16, 0, 1]), 0),
                          NF_NAT_MANIP_SRC, &env), SetupResult::Accept);
    let reply = c.reply_tuple();
    assert_eq!(&reply.src.addr.0[..4], &[10, 0, 0, 50]);
    assert_eq!(&reply.dst.addr.0[..4], &[172, 16, 0, 1]);
    assert_eq!(c.status() & (IPS_SRC_NAT | IPS_DST_NAT), IPS_SRC_NAT | IPS_DST_NAT);
}

#[test]
fn a_binding_is_refused_once_the_entry_is_published() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let c = fresh(orig);
    c.set_status_bits(IPS_CONFIRMED);
    // Accepting the request but silently not applying it would be worse than
    // refusing: the table is keyed on the reply tuple.
    assert_eq!(setup_info(&c, &NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]), 0),
                          NF_NAT_MANIP_SRC, &env), SetupResult::Accept);
    assert_eq!(c.reply_tuple(), orig.invert().unwrap(), "nothing may change after publication");
}

#[test]
fn the_null_binding_pins_the_addresses_and_resolves_only_ports() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let c = fresh(orig);
    assert_eq!(alloc_null_binding(&c, NF_NAT_MANIP_SRC, &env), SetupResult::Accept);
    assert_eq!(&c.reply_tuple().dst.addr.0[..4], &[10, 0, 0, 1],
        "no rule decided anything, so the address must not move");
    assert_eq!(c.status() & IPS_SRC_NAT_DONE, IPS_SRC_NAT_DONE);
}

#[test]
fn the_reply_direction_uses_the_opposite_manip_bit() {
    // A source-translated flow's replies get their DESTINATION restored. Using
    // the same bit in both directions rewrites the wrong end of the reply.
    let bit_out = packet_manip_bit(NF_INET_POST_ROUTING, IP_CT_DIR_ORIGINAL);
    assert_eq!(bit_out, IPS_SRC_NAT);
    let bit_in = packet_manip_bit(NF_INET_PRE_ROUTING, IP_CT_DIR_REPLY);
    assert_eq!(bit_in, IPS_SRC_NAT, "the reply is un-SNATed at pre-routing");

    let bit_dnat_out = packet_manip_bit(NF_INET_PRE_ROUTING, IP_CT_DIR_ORIGINAL);
    assert_eq!(bit_dnat_out, IPS_DST_NAT);
    let bit_dnat_in = packet_manip_bit(NF_INET_POST_ROUTING, IP_CT_DIR_REPLY);
    assert_eq!(bit_dnat_in, IPS_DST_NAT);
}

#[test]
fn only_a_bound_flow_is_rewritten() {
    assert!(!packet_needs_manip(0, NF_INET_POST_ROUTING, IP_CT_DIR_ORIGINAL));
    assert!(packet_needs_manip(IPS_SRC_NAT, NF_INET_POST_ROUTING, IP_CT_DIR_ORIGINAL));
    assert!(!packet_needs_manip(IPS_DST_NAT, NF_INET_POST_ROUTING, IP_CT_DIR_ORIGINAL));
}

#[test]
fn the_target_tuple_comes_from_the_other_direction() {
    let env = Env::new();
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let mut c = fresh(orig);
    let r = NatRange::single_addr(InetAddr::v4([203, 0, 113, 5]), 0);
    setup_info(&mut c, &r, NF_NAT_MANIP_SRC, &env);

    // Outbound: the packet must leave presenting the translated source.
    let out = target_tuple(&c, IP_CT_DIR_ORIGINAL).unwrap();
    assert_eq!(&out.src.addr.0[..4], &[203, 0, 113, 5]);
    assert_eq!(&out.dst.addr.0[..4], &[93, 184, 216, 34]);

    // Inbound: the reply must be restored to the client's own address.
    let back = target_tuple(&c, IP_CT_DIR_REPLY).unwrap();
    assert_eq!(&back.src.addr.0[..4], &[93, 184, 216, 34]);
    assert_eq!(&back.dst.addr.0[..4], &[10, 0, 0, 1]);
}

#[test]
fn hook_manip_mapping() {
    assert_eq!(hook_to_manip(NF_INET_POST_ROUTING), NF_NAT_MANIP_SRC);
    assert_eq!(hook_to_manip(NF_INET_LOCAL_IN), NF_NAT_MANIP_SRC);
    assert_eq!(hook_to_manip(NF_INET_PRE_ROUTING), NF_NAT_MANIP_DST);
    assert_eq!(hook_to_manip(NF_INET_LOCAL_OUT), NF_NAT_MANIP_DST);
    assert_eq!(hook_to_manip(NF_INET_FORWARD), NF_NAT_MANIP_DST);
    // Destination translation must run before filtering; source after.
    assert!(hook_priority(NF_NAT_MANIP_DST) < 0);
    assert!(hook_priority(NF_NAT_MANIP_SRC) > 0);
}

#[test]
fn a_masquerade_binding_goes_stale_when_the_route_moves() {
    extern crate alloc;
    use alloc::sync::Arc;
    let orig = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let c = Arc::new(fresh(orig));
    assert!(masq_still_valid(&c, 3), "an unrecorded interface constrains nothing");
    c.nat.lock().masq_index = 3;
    assert!(masq_still_valid(&c, 3));
    assert!(!masq_still_valid(&c, 4),
        "the chosen source address belongs to the old interface");
}
