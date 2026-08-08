// The listener half of fast open: gathering the state one SYN is judged
// against, and doing what the judgement says.
//
// The judgement itself is not here — `crate::tcp_fastopen::server::decide`
// owns it, ungated, so every rung is a `cargo test` away. This file is the
// hop between that decision and the transport: it reads the enable bits, the
// keys and the queue, and it puts the answer where the handshake will find it.
//
// A SYN whose data is taken reaches the accept queue immediately, while the
// connection is still SYN-RECV. That is the point of the feature — a program
// gets the request without waiting a round trip for the acknowledgement — and
// it is why the acknowledgement that later completes the handshake must not
// publish the child again.

use super::*;
use crate::netdev::iff;
use crate::mib::{self, TcpExt};
use crate::tcp_fastopen::{self, Counter, Passive};

/// What the fast-open decision left for the handshake to carry out.
pub(crate) struct Plan {
    /// The cookie the SYN-ACK carries, if any.
    pub reply: Option<crate::tcp_conn::fastopen::Cookie>,
    /// The SYN's data is taken and the child is published at once.
    pub accept: bool,
}

/// Judge one SYN against its listener's fast-open state. `metrics` are the
/// route's, already fetched for this destination by the passive open.
/// # C: O(1)
pub(crate) fn plan(listener: &TcpListenEntry, hdr: &crate::tcp_hdr::TcpHdr, seg: &[u8],
                   src_ip: IpAddr, dst_ip: IpAddr,
                   metrics: &crate::route_metrics::RouteMetrics) -> Plan
{
    let namespace = &listener.owner.net_namespace;
    let syn = tcp_fastopen::Syn {
        bits: tcp_fastopen::enable_bits(namespace),
        option: crate::tcp_conn::fastopen::parse(seg, true),
        syn_data: seg.len() > hdr.payload_offset(),
        sock_no_cookie: listener.fastopen_no_cookie.load(
            ::core::sync::atomic::Ordering::Acquire),
        route_no_cookie: metrics.fastopen_no_cookie != 0,
        // A listener that named keys of its own mints from those; otherwise
        // from the namespace's, which is the pair every other listener in it
        // shares.
        keys: listener.fastopen.keys().or_else(|| tcp_fastopen::ns_keys(namespace)),
        src: src_ip,
        dst: dst_ip,
    };
    let decision = tcp_fastopen::decide_counted(&listener.fastopen, &syn, crate::tcp_conn::ka_now_ns());
    for counter in decision.counters() {
        mib::bump_tcp_ext(namespace.id().as_u64(), match counter {
            Counter::Passive => TcpExt::TcpFastOpenPassive,
            Counter::PassiveFail => TcpExt::TcpFastOpenPassiveFail,
            Counter::PassiveAltKey => TcpExt::TcpFastOpenPassiveAltKey,
            Counter::CookieReqd => TcpExt::TcpFastOpenCookieReqd,
            Counter::ListenOverflow => TcpExt::TcpFastOpenListenOverflow,
        });
    }
    match decision.passive {
        Passive::Decline => Plan { reply: None, accept: false },
        Passive::Offer(cookie) => Plan { reply: Some(cookie), accept: false },
        Passive::Accept { reply } => Plan { reply, accept: true },
    }
}

/// Move what an active open learned out of the connection and into the
/// namespace that owns it: the cookie for next time, the pause a blackholed
/// path earns, and the clearing of that pause by a fast open that worked.
///
/// The connection cannot do this itself — the cookie cache and the pause are
/// namespace state — so it records the facts and this runs at every point a
/// segment or a timer could have produced them. # C: O(log N)
pub(crate) fn drain_client(stack: &NetStack, entry: &Arc<TcpEntry>, now_ns: u64) {
    let (learned, blackholed, confirmed, src, dst, mss) = {
        let mut c = entry.conn.lock();
        let confirmed = c.fastopen_confirming && c.data_segs_in > 0;
        if confirmed { c.fastopen_confirming = false; }
        (c.fastopen_learned.take(), ::core::mem::take(&mut c.fastopen_blackhole_seen), confirmed,
            c.local.ip, c.remote.ip, c.peer_mss)
    };
    if learned.is_none() && !blackholed && !confirmed { return; }
    let namespace = &entry.owner.net_namespace;
    if let Some(learned) = learned.as_ref() {
        tcp_fastopen::cache_learned(namespace, src, dst, now_ns, mss, learned);
    }
    if blackholed { tcp_fastopen::blackhole_disable(namespace, now_ns); }
    // A fast open that carried data over a path the pause had just released
    // is the evidence that ends the pause outright.
    if confirmed && !confirmed_on_loopback(stack, entry) {
        tcp_fastopen::blackhole_reset(namespace);
    }
}

/// Linux resets the Fast Open blackhole recurrence only when the confirming
/// connection's selected egress device is not loopback. A vanished route has
/// no loopback device to protect, matching the reference's absent-dst case.
/// # C: O(route lookup)
fn confirmed_on_loopback(stack: &NetStack, entry: &TcpEntry) -> bool {
    let net_ns = entry.net_ns();
    let bound = entry.bound_iface();
    let dst = entry.conn.lock().remote.ip;
    match dst {
        IpAddr::V4(dst) => stack.route_v4_iface_in(net_ns, dst, bound, crate::stack_binddev::UNMARKED)
            .map(|(_, iface, _)| iface.flags() & iff::IFF_LOOPBACK != 0)
            .unwrap_or(false),
        IpAddr::V6(dst) => stack.route_v6_iface_in(net_ns, dst, bound, crate::stack_binddev::UNMARKED)
            .map(|(_, iface, _)| iface.flags() & iff::IFF_LOOPBACK != 0)
            .unwrap_or(false),
    }
}

impl Plan {
    /// Put the decision where the handshake reads it, before the SYN is
    /// processed: the SYN-ACK's option area, and — for a taken SYN — the flag
    /// that makes the child deliver the payload and the charge against the
    /// listener's bound. # C: O(1)
    pub(crate) fn install(&self, entry: &Arc<TcpEntry>) {
        let mut c = entry.conn.lock();
        c.fastopen_opt = self.reply;
        c.fastopen_child = self.accept;
        drop(c);
        if self.accept {
            entry.fastopen_qlen.store(true, ::core::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
#[path = "tcp_fastopen_tests.rs"]
mod tests;
