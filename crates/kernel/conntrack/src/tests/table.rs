// Table insertion, both-tuple lookup, confirmation races, expiry and GC.

extern crate alloc;
use alloc::sync::Arc;

use crate::core::{CtNet, L4, Packet, Track};
use crate::entry::Conn;
use crate::proto::tcp_state::TCPHDR_SYN;
use crate::proto::tcp_window::TcpSeg;
use crate::table::CtTable;
use crate::uapi::*;
use super::tuple::{v4_tcp, v4_udp};

fn conn(t: &CtTable, orig: crate::Tuple) -> Arc<Conn> {
    let reply = orig.invert().unwrap();
    let c = Arc::new(Conn::new(t.alloc_id(), orig, reply, 0));
    t.add_pending(c.clone());
    c
}

#[test]
fn a_confirmed_entry_is_found_from_both_directions() {
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let c = conn(&t, orig);
    c.refresh(0, 100);
    assert!(t.confirm(&c, 0));

    let f = t.lookup(&orig, 0).expect("original half");
    assert_eq!(f.dir, IP_CT_DIR_ORIGINAL);
    let f = t.lookup(&orig.invert().unwrap(), 0).expect("reply half");
    assert_eq!(f.dir, IP_CT_DIR_REPLY);
    assert_eq!(t.count(), 1);
}

#[test]
fn a_translated_reply_tuple_is_what_gets_indexed() {
    // Under NAT the reply is not the inverse of the original. Indexing the
    // inverse instead would make every reply miss.
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    let translated = v4_tcp([93, 184, 216, 34], 80, [203, 0, 113, 5], 40000);
    let mut c = Conn::new(t.alloc_id(), orig, orig.invert().unwrap(), 0);
    assert!(c.alter_reply(translated));
    let c = Arc::new(c);
    t.add_pending(c.clone());
    c.refresh(0, 100);
    assert!(t.confirm(&c, 0));

    assert!(t.lookup(&translated, 0).is_some(), "the translated reply must match");
    assert!(t.lookup(&orig.invert().unwrap(), 0).is_none(),
        "the untranslated inverse must NOT match");
}

#[test]
fn the_reply_tuple_cannot_change_after_confirmation() {
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let c = conn(&t, orig);
    c.refresh(0, 100);
    assert!(t.confirm(&c, 0));
    let mut owned = Conn::new(99, orig, orig.invert().unwrap(), 0);
    owned.set_status_bits(IPS_CONFIRMED);
    assert!(!owned.alter_reply(v4_tcp([1, 1, 1, 1], 1, [2, 2, 2, 2], 2)),
        "changing a key after insertion strands the old one");
}

#[test]
fn a_racing_confirm_on_the_same_tuple_loses() {
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let a = conn(&t, orig);
    let b = conn(&t, orig);
    a.refresh(0, 100);
    b.refresh(0, 100);
    assert!(t.confirm(&a, 0));
    assert!(!t.confirm(&b, 0), "two flows must never share one tuple");
    assert_eq!(t.count(), 1);
}

#[test]
fn a_racing_confirm_loses_even_when_both_tuples_share_one_bucket() {
    // With one bucket the two halves collide on the same lock, which is the
    // path a multi-bucket table almost never takes — and the one where a
    // check-then-insert with the lock dropped between lets both flows win.
    let t = CtTable::with_buckets(1, 1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let a = conn(&t, orig);
    let b = conn(&t, orig);
    a.refresh(0, 100);
    b.refresh(0, 100);
    assert!(t.confirm(&a, 0));
    assert!(!t.confirm(&b, 0));
    assert_eq!(t.count(), 1);
}

#[test]
fn a_reversed_tuple_of_a_live_flow_is_also_taken() {
    // Both halves are keys. A second flow claiming the reply tuple as its
    // original would make one wire tuple resolve to two entries.
    let t = CtTable::with_buckets(1, 1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let a = conn(&t, orig);
    a.refresh(0, 100);
    assert!(t.confirm(&a, 0));
    let b = conn(&t, orig.invert().unwrap());
    b.refresh(0, 100);
    assert!(!t.confirm(&b, 0));
}

#[test]
fn two_flows_may_not_share_an_original_tuple() {
    // Distinct reply tuples, same original: a second entry would make the
    // original half resolve to whichever the bucket walk reached first.
    for buckets in [1usize, crate::limits::CT_HASH_BUCKETS] {
        let t = CtTable::with_buckets(buckets, 1);
        let orig = v4_tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);

        let a = Arc::new(Conn::new(t.alloc_id(), orig,
            v4_tcp([93, 184, 216, 34], 80, [203, 0, 113, 5], 40000), 0));
        t.add_pending(a.clone());
        a.refresh(0, 100);
        assert!(t.confirm(&a, 0));

        let b = Arc::new(Conn::new(t.alloc_id(), orig,
            v4_tcp([93, 184, 216, 34], 80, [203, 0, 113, 6], 40001), 0));
        t.add_pending(b.clone());
        b.refresh(0, 100);
        assert!(!t.confirm(&b, 0), "buckets={buckets}");
        assert_eq!(t.count(), 1, "buckets={buckets}");
    }
}

#[test]
fn two_flows_may_not_share_a_reply_tuple() {
    // Under NAT two originals can be translated onto one reply tuple. That is
    // exactly the collision the unique-tuple search exists to avoid, and the
    // table is the backstop: allowing it makes one wire tuple ambiguous.
    for buckets in [1usize, crate::limits::CT_HASH_BUCKETS] {
        let t = CtTable::with_buckets(buckets, 1);
        let shared_reply = v4_tcp([93, 184, 216, 34], 80, [203, 0, 113, 5], 40000);

        let mut a = Conn::new(t.alloc_id(),
            v4_tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80), shared_reply, 0);
        assert!(a.alter_reply(shared_reply));
        let a = Arc::new(a);
        t.add_pending(a.clone());
        a.refresh(0, 100);
        assert!(t.confirm(&a, 0));

        let b = Arc::new(Conn::new(t.alloc_id(),
            v4_tcp([10, 0, 0, 9], 5678, [93, 184, 216, 34], 80), shared_reply, 0));
        t.add_pending(b.clone());
        b.refresh(0, 100);
        assert!(!t.confirm(&b, 0), "buckets={buckets}");
        assert_eq!(t.count(), 1, "buckets={buckets}");
    }
}

#[test]
fn an_expired_entry_is_not_a_match() {
    let t = CtTable::new(1);
    let orig = v4_udp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 53);
    let c = conn(&t, orig);
    c.refresh(0, 30);
    assert!(t.confirm(&c, 0));
    assert!(t.lookup(&orig, 29).is_some());
    // Returning a dead flow would hand a new connection its state and its
    // NAT binding.
    assert!(t.lookup(&orig, 31).is_none());
}

#[test]
fn gc_retires_expired_entries() {
    let t = CtTable::new(1);
    for p in 0..5u16 {
        let c = conn(&t, v4_udp([10, 0, 0, 1], 1000 + p, [10, 0, 0, 2], 53));
        c.refresh(0, 10);
        assert!(t.confirm(&c, 0));
    }
    assert_eq!(t.count(), 5);
    assert_eq!(t.gc(5), 0, "nothing has expired yet");
    assert_eq!(t.gc(11), 5);
    assert_eq!(t.count(), 0);
}

#[test]
fn tuple_taken_ignores_the_entry_asking() {
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let c = conn(&t, orig);
    c.refresh(0, 100);
    assert!(t.confirm(&c, 0));
    assert!(t.tuple_taken(&orig, None, 0));
    assert!(!t.tuple_taken(&orig, Some(&c), 0),
        "a flow does not collide with itself when re-deciding its binding");
}

#[test]
fn killing_unlinks_both_halves() {
    let t = CtTable::new(1);
    let orig = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let c = conn(&t, orig);
    c.refresh(0, 100);
    assert!(t.confirm(&c, 0));
    assert!(t.kill(&c));
    assert!(!t.kill(&c), "a second kill is a no-op, not a double count");
    assert!(t.lookup(&orig, 0).is_none());
    assert!(t.lookup(&orig.invert().unwrap(), 0).is_none());
    assert_eq!(t.count(), 0);
}

#[test]
fn snapshot_reports_each_entry_once() {
    let t = CtTable::new(1);
    for p in 0..3u16 {
        let c = conn(&t, v4_tcp([10, 0, 0, 1], 1000 + p, [10, 0, 0, 2], 80));
        c.refresh(0, 100);
        assert!(t.confirm(&c, 0));
    }
    // Each entry is linked under two tuples; a naive walk would double it.
    assert_eq!(t.snapshot(0).len(), 3);
}

fn syn(seq: u32) -> TcpSeg<'static> {
    TcpSeg { seq, ack: 0, win: 8192, flags: TCPHDR_SYN, datalen: 0, options: &[] }
}

#[test]
fn track_creates_then_confirms_a_flow() {
    let net = CtNet::new(0, 7);
    let tuple = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let pkt = Packet { tuple, l4: L4::Tcp(syn(1000)), len: 60 };
    let Track::Ok { conn, dir, ctinfo, .. } = net.track(&pkt, 0)
        else { panic!("first SYN must be tracked") };
    assert_eq!(dir, IP_CT_DIR_ORIGINAL);
    assert_eq!(ctinfo, IP_CT_NEW);
    assert!(!conn.confirmed(), "not published until the hooks accept it");
    assert!(net.table.lookup(&tuple, 0).is_none());
    assert!(net.confirm(&conn, 0));
    assert!(net.table.lookup(&tuple, 0).is_some());
}

#[test]
fn a_dropped_first_packet_leaves_no_entry() {
    let net = CtNet::new(0, 7);
    let tuple = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let pkt = Packet { tuple, l4: L4::Tcp(syn(1000)), len: 60 };
    let Track::Ok { conn, .. } = net.track(&pkt, 0) else { panic!() };
    // The ruleset drops it; nothing is confirmed.
    net.destroy(&conn);
    assert!(net.table.lookup(&tuple, 0).is_none());
    assert_eq!(net.table.count(), 0);
}

#[test]
fn a_reply_marks_the_flow_seen() {
    let net = CtNet::new(0, 7);
    let tuple = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let Track::Ok { conn, .. } = net.track(
        &Packet { tuple, l4: L4::Tcp(syn(1000)), len: 60 }, 0) else { panic!() };
    assert!(net.confirm(&conn, 0));

    let reply = tuple.invert().unwrap();
    let sa = TcpSeg { seq: 5000, ack: 1001, win: 8192,
                      flags: TCPHDR_SYN | crate::proto::tcp_state::TCPHDR_ACK,
                      datalen: 0, options: &[] };
    let Track::Ok { dir, .. } = net.track(&Packet { tuple: reply, l4: L4::Tcp(sa), len: 60 }, 1)
        else { panic!("the reply must find the flow") };
    assert_eq!(dir, IP_CT_DIR_REPLY);
    assert_eq!(conn.status() & IPS_SEEN_REPLY, IPS_SEEN_REPLY);
}

#[test]
fn a_protocol_mismatch_against_an_existing_entry_is_invalid() {
    // A UDP packet whose tuple matches a TCP entry means the tuple compare
    // dropped the protocol; refusing it is the last line of defence.
    let net = CtNet::new(0, 7);
    let tuple = v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80);
    let Track::Ok { conn, .. } = net.track(
        &Packet { tuple, l4: L4::Tcp(syn(1000)), len: 60 }, 0) else { panic!() };
    assert!(net.confirm(&conn, 0));
    let r = net.track(&Packet { tuple, l4: L4::Udp, len: 60 }, 0);
    assert!(matches!(r, Track::Invalid));
}
