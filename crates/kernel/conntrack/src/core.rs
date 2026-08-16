//! Packet path. One entry point per packet: resolve the tuple to an entry,
//! run the protocol tracker, and return the verdict plus the conntrack-info
//! the rest of the stack keys on.

extern crate alloc;
use alloc::sync::Arc;

use crate::entry::{Conn, ProtoState};
use crate::event::EventCache;
use crate::proto::{icmp, tcp, udp};
use crate::proto::tcp_window::TcpSeg;
use crate::sysctl::CtSysctl;
use crate::table::CtTable;
use crate::tuple::Tuple;
use crate::uapi::*;

/// L4 detail one packet carries, in the shape each tracker wants.
#[derive(Copy, Clone, Debug)]
pub enum L4<'a> {
    Tcp(TcpSeg<'a>),
    Udp,
    Icmp,
    Generic,
}

/// One packet, as the tracker needs it.
#[derive(Copy, Clone, Debug)]
pub struct Packet<'a> {
    pub tuple: Tuple,
    pub l4: L4<'a>,
    /// Whole-packet byte count, for the accounting extension.
    pub len: u64,
}

/// Result of tracking one packet.
#[derive(Clone, Debug)]
pub enum Track {
    /// Packet belongs to `conn`, arriving in `dir`.
    Ok { conn: Arc<Conn>, dir: u8, ctinfo: u8, events: u32 },
    /// Refuse the packet.
    Invalid,
    /// Pass it, but attach nothing.
    Untracked,
    /// The entry was killed; retry the whole lookup on a fresh table read.
    Repeat,
}

/// Per-namespace conntrack instance.
pub struct CtNet {
    pub table: CtTable,
    pub expect: crate::expect::ExpectTable,
    pub sysctl: sync::Spinlock<CtSysctl, sync::Socket>,
    pub events: crate::event::EventQueue,
    pub net_ns: u64,
}

impl CtNet {
    /// # C: O(N_buckets)
    pub fn new(net_ns: u64, seed: u32) -> Self {
        Self {
            table: CtTable::new(seed),
            expect: crate::expect::ExpectTable::new(seed),
            sysctl: sync::Spinlock::new(CtSysctl::default()),
            events: crate::event::EventQueue::new(),
            net_ns,
        }
    }

    /// Track one packet. `now` is seconds. The entry returned is not yet in
    /// the table when it is new: `confirm` publishes it after the hooks have
    /// run, so a rule that drops the packet leaves no entry behind.
    /// # C: O(bucket length + len(options))
    pub fn track(&self, pkt: &Packet, now: u64) -> Track {
        let sysctl = *self.sysctl.lock();
        if let Some(found) = self.table.lookup(&pkt.tuple, now) {
            return self.run(found.conn, found.dir, pkt, now, &sysctl, true);
        }
        // A packet whose protocol cannot produce a reply tuple has no second
        // half to track and must not create a one-sided entry.
        let Some(reply) = pkt.tuple.invert() else { return Track::Invalid; };
        if self.table.count() >= self.table.max.load(core::sync::atomic::Ordering::Relaxed)
            && !self.table.early_drop(now)
        {
            return Track::Invalid;
        }
        let id = self.table.alloc_id();
        let conn = Arc::new(Conn::new(id, pkt.tuple, reply, self.net_ns));
        self.table.add_pending(conn.clone());
        let r = self.run(conn.clone(), IP_CT_DIR_ORIGINAL, pkt, now, &sysctl, false);
        if matches!(r, Track::Invalid) { self.table.kill(&conn); }
        r
    }

    fn run(&self, conn: Arc<Conn>, dir: u8, pkt: &Packet, now: u64,
           sysctl: &CtSysctl, confirmed: bool) -> Track
    {
        let mut cache = EventCache::default();
        let status = conn.status();
        if !confirmed { cache.cache(IPCT_NEW); }
        if dir == IP_CT_DIR_REPLY && status & IPS_SEEN_REPLY == 0 {
            conn.set_status_bits(IPS_SEEN_REPLY);
            cache.cache(IPCT_REPLY);
        }
        let status = conn.status();

        let timeout = {
            let mut p = conn.proto.lock();
            match (&mut *p, &pkt.l4) {
                (ProtoState::Tcp(track), L4::Tcp(seg)) => {
                    let (verdict, delta) =
                        tcp::packet(track, dir, seg, status, confirmed, &sysctl.tcp);
                    if delta.protoinfo_changed { cache.cache(IPCT_PROTOINFO); }
                    if delta.set_assured {
                        conn.set_status_bits(IPS_ASSURED);
                        cache.cache(IPCT_ASSURED);
                    }
                    match verdict {
                        tcp::TcpVerdict::Accept { timeout } => Some(timeout),
                        tcp::TcpVerdict::Ignore  => None,
                        tcp::TcpVerdict::Invalid => { drop(p); return Track::Invalid; }
                        tcp::TcpVerdict::Repeat  => {
                            drop(p);
                            self.table.kill(&conn);
                            return Track::Repeat;
                        }
                        tcp::TcpVerdict::Kill => {
                            drop(p);
                            self.kill_with_event(&conn);
                            return Track::Ok { conn, dir, ctinfo: IP_CT_ESTABLISHED,
                                               events: cache.take() };
                        }
                    }
                }
                (ProtoState::Udp(track), L4::Udp) => {
                    let r = udp::packet(track, status & IPS_SEEN_REPLY != 0,
                                        status & IPS_ASSURED != 0, now, &sysctl.udp);
                    if r.set_assured {
                        conn.set_status_bits(IPS_ASSURED);
                        cache.cache(IPCT_ASSURED);
                    }
                    Some(r.timeout)
                }
                (ProtoState::Icmp, L4::Icmp) => {
                    let s = if pkt.tuple.l3num == NFPROTO_IPV6 { &sysctl.icmpv6 }
                            else { &sysctl.icmp };
                    match icmp::packet(&pkt.tuple, confirmed, s) {
                        Some(t) => Some(t),
                        None => { drop(p); return Track::Invalid; }
                    }
                }
                (ProtoState::Generic, _) => Some(icmp::generic_packet(&sysctl.generic)),
                // The entry's tracker and the packet's protocol disagree, which
                // means the tuple matched a flow it does not belong to.
                _ => { drop(p); return Track::Invalid; }
            }
        };

        if let Some(t) = timeout { conn.refresh(now, t); }
        if sysctl.acct { conn.counters[dir as usize].account(pkt.len); }
        let ctinfo = conn.ctinfo(dir);
        let events = cache.take();
        if sysctl.events { self.events.post(conn.id, events); }
        Track::Ok { conn, dir, ctinfo, events }
    }

    fn kill_with_event(&self, conn: &Arc<Conn>) {
        if self.table.kill(conn) {
            self.expect.purge_master(conn);
            self.events.post(conn.id, IPCT_DESTROY);
        }
    }

    /// Publish an entry after the hooks have accepted the packet. An entry is
    /// only ever inserted here, never at creation: inserting earlier would
    /// leave a live flow behind for a packet the ruleset then dropped.
    /// # C: O(bucket length)
    pub fn confirm(&self, conn: &Arc<Conn>, now: u64) -> bool {
        if conn.confirmed() { return true; }
        if !self.table.confirm(conn, now) { return false; }
        // An entry created from an expectation is RELATED, not NEW, and the
        // expectation is consumed so a second connection cannot reuse it.
        if let Some(exp) = self.expect.find(&conn.orig, now) {
            conn.set_status_bits(IPS_EXPECTED);
            self.expect.remove(&exp.tuple);
            self.events.post(conn.id, IPCT_RELATED);
        }
        true
    }

    /// Retire expired entries and expectations. # C: O(N)
    pub fn gc(&self, now: u64) -> usize { self.table.gc(now) }

    /// Kill one entry and announce it. # C: O(bucket length)
    pub fn destroy(&self, conn: &Arc<Conn>) { self.kill_with_event(conn); }
}
