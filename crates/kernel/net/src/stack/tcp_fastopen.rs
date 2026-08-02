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
use crate::tcp_fastopen::{self, Passive};

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
    match tcp_fastopen::decide(&listener.fastopen, &syn, crate::tcp_conn::ka_now_ns()) {
        Passive::Decline => Plan { reply: None, accept: false },
        Passive::Offer(cookie) => Plan { reply: Some(cookie), accept: false },
        Passive::Accept { reply } => Plan { reply, accept: true },
    }
}

impl Plan {
    /// Put the decision where the handshake reads it, before the SYN is
    /// processed: the SYN-ACK's option area, and — for a taken SYN — the flag
    /// that makes the child deliver the payload and the charge against the
    /// listener's bound. # C: O(1)
    pub(crate) fn install(&self, entry: &Arc<TcpEntry>) {
        let mut c = entry.conn.lock();
        c.fastopen_reply = self.reply;
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
