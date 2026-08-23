//! Packet path. One entry point per packet: resolve the tuple to an entry,
//! run the protocol tracker, and return the verdict plus the conntrack-info
//! the rest of the stack keys on.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use crate::entry::{Conn, LabelUpdate, ProtoState, SeqAdjust, TcpProtoInfoUpdate};
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
    pub helpers: crate::helper::HelperRegistry,
    pub sysctl: sync::Spinlock<CtSysctl, sync::Socket>,
    pub events: crate::event::EventQueue,
    pub net_ns: u64,
}

/// Linux ctnetlink's result when changing a helper on an existing entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HelperChangeError { NotFound, Unsupported, Busy }

impl CtNet {
    /// # C: O(N_buckets)
    pub fn new(net_ns: u64, seed: u32) -> Self {
        Self {
            table: CtTable::new(seed),
            expect: crate::expect::ExpectTable::new(seed),
            helpers: crate::helper::HelperRegistry::new(),
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
        if sysctl.helper {
            if let Some(helper) = self.helpers.find_for(&pkt.tuple) {
                conn.attach_helper(helper.name, false);
            }
        }
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
        if sysctl.events { self.events.post(&conn, events); }
        Track::Ok { conn, dir, ctinfo, events }
    }

    fn kill_with_event(&self, conn: &Arc<Conn>) {
        if self.table.kill(conn) {
            self.expect.purge_master(conn);
            self.events.post(&conn, IPCT_DESTROY);
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
            self.events.post(&conn, IPCT_RELATED);
        }
        true
    }

    /// Delete one live entry selected by ctnetlink id and queue its destroy
    /// notification through the canonical event queue. # C: O(N)
    pub fn delete_id(&self, id: u64, now: u64) -> bool {
        let Some(conn) = self.table.find_id(id, now) else { return false; };
        if !self.table.kill(&conn) { return false; }
        self.expect.purge_master(&conn);
        self.events.post(&conn, IPCT_DESTROY);
        true
    }

    /// Apply Linux's existing-flow helper change rules. A request naming the
    /// already attached helper is a no-op; a different helper is busy, and a
    /// flow without a helper cannot gain one after creation. # C: O(N)
    pub fn update_helper_id(&self, id: u64, now: u64, name: String)
        -> Result<(), HelperChangeError> {
        let Some(conn) = self.table.find_id(id, now) else {
            return Err(HelperChangeError::NotFound);
        };
        let current = conn.helper.lock().clone();
        if current.as_deref() == Some(name.as_str()) { return Ok(()); }
        if current.is_some() { return Err(HelperChangeError::Busy); }
        Err(HelperChangeError::Unsupported)
    }

    /// Apply the ctnetlink fields supported by the live entry owner. Linux
    /// changes timeout, status, mark, and sequence adjustment on an existing
    /// flow; immutable status bits are screened by the ctnetlink encoder's
    /// shared mask. # C: O(N)
    pub fn update_id(&self, id: u64, now: u64, timeout: Option<u32>,
                     status: Option<u32>, mark: Option<(u32, Option<u32>)>,
                     seqadj: [Option<SeqAdjust>; IP_CT_DIR_MAX],
                     protoinfo: Option<TcpProtoInfoUpdate>,
                     labels: Option<LabelUpdate>) -> bool {
        let Some(conn) = self.table.find_id(id, now) else { return false; };
        if let Some(secs) = timeout {
            conn.set_status_bits(IPS_FIXED_TIMEOUT);
            conn.timeout.store(now + secs as u64, core::sync::atomic::Ordering::Release);
        }
        if let Some(requested) = status {
            let writable = crate::ctnetlink::writable_status(requested);
            let old = conn.status();
            conn.status.store((old & IPS_UNCHANGEABLE_MASK) | writable,
                              core::sync::atomic::Ordering::Release);
            if old != conn.status() { self.events.post(&conn, IPCT_PROTOINFO); }
        }
        if let Some((value, mask)) = mark {
            let old = conn.mark.load(core::sync::atomic::Ordering::Relaxed);
            let mask = mask.unwrap_or(0);
            let new = (old & mask) ^ value;
            conn.mark.store(new, core::sync::atomic::Ordering::Release);
            if old != new { self.events.post(&conn, IPCT_MARK); }
        }
        for (dir, record) in seqadj.into_iter().enumerate() {
            if let Some(record) = record {
                if conn.seqadj_replace(dir as u8, record) {
                    self.events.post(&conn, IPCT_SEQADJ);
                }
            }
        }
        if let Some(update) = protoinfo {
            if conn.tcp_protoinfo_update(update) { self.events.post(&conn, IPCT_PROTOINFO); }
        }
        if let Some(update) = labels {
            if conn.labels_replace(&update) { self.events.post(&conn, IPCT_LABEL); }
        }
        true
    }

    /// Create and immediately confirm one userspace-supplied tuple. The
    /// ctnetlink creator owns a confirmed entry, unlike packet tracking which
    /// keeps a new entry pending until the packet hooks accept it. # C: O(bucket length)
    pub fn create_tuple(&self, tuple: Tuple, reply: Option<Tuple>, now: u64,
                        timeout: u32, status: u32, mark: Option<u32>,
                        protoinfo: Option<TcpProtoInfoUpdate>,
                        helper: Option<String>) -> Option<u64> {
        self.create_tuple_with(tuple, reply, now, timeout, status, mark, protoinfo, helper,
                               None, |_| true)
    }

    /// Create a userspace entry and run one final pre-confirmation setup.
    /// NAT uses this seam because its reply tuple must be allocated before the
    /// entry is published; the callback is never run on a confirmed entry.
    pub fn create_tuple_with<F>(&self, tuple: Tuple, reply: Option<Tuple>, now: u64,
                                timeout: u32, status: u32, mark: Option<u32>,
                                protoinfo: Option<TcpProtoInfoUpdate>,
                                helper: Option<String>, labels: Option<LabelUpdate>, setup: F)
                                -> Option<u64>
        where F: FnOnce(&Arc<Conn>) -> bool
    {
        let reply = reply.or_else(|| tuple.invert())?;
        let conn = Arc::new(Conn::new(self.table.alloc_id(), tuple, reply, self.net_ns));
        conn.set_status_bits(crate::ctnetlink::writable_status(status));
        if conn.status() & IPS_FIXED_TIMEOUT != 0 {
            conn.timeout.store(now + timeout as u64, core::sync::atomic::Ordering::Release);
        } else {
            conn.refresh(now, timeout);
        }
        if let Some(mark) = mark { conn.mark.store(mark, core::sync::atomic::Ordering::Release); }
        if let Some(update) = protoinfo {
            // Non-TCP protocol owners have no TCP from_nlattr hook; Linux
            // accepts the protocol-info container and leaves them unchanged.
            let _ = conn.tcp_protoinfo_update(update);
        }
        if let Some(name) = helper {
            self.helpers.find_named_for(&name, &tuple)?;
            conn.attach_helper(name, true);
        }
        let label_event = labels.is_some();
        if let Some(update) = labels { conn.labels_replace(&update); }
        if !setup(&conn) { return None; }
        self.table.add_pending(conn.clone());
        if !self.table.confirm(&conn, now) {
            let _ = self.table.kill(&conn);
            return None;
        }
        self.events.post(&conn, IPCT_NEW | if label_event { IPCT_LABEL } else { 0 });
        Some(conn.id)
    }

    /// Retire expired entries and expectations. # C: O(N)
    pub fn gc(&self, now: u64) -> usize { self.table.gc(now) }

    /// Kill one entry and announce it. # C: O(bucket length)
    pub fn destroy(&self, conn: &Arc<Conn>) { self.kill_with_event(conn); }
}
