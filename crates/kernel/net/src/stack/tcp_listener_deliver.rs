// B1618: TCP passive-open (listener) delivery, split out of `stack/tcp.rs`.
//
// `deliver_tcp_packet` had both delivery branches in one frame: the established
// path that continues into transmit, and this one, which materialises a whole
// `TcpConn` by value plus the child socket's filter and PMTU state. LLVM reserves
// the union, so every established-connection delivery — reached from a `sendmsg`
// already ~9 KiB deep on a 16 KiB stack — paid for locals it never touched.

use super::*;
use super::tcp_tx::TcpTxPolicy;

impl NetStack {
    /// Passive open: match a listener for a SYN and instantiate the child connection.
    /// # C: O(bucket) select + O(segment) handler
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deliver_tcp_to_listener(&self, net_ns: u64, iface: NetIfaceId,
        src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8], packet: &[u8],
        hdr: &crate::tcp_hdr::TcpHdr, key: TcpKey, tables: &super::inet_tables::InetTables,
        hop: u8, ipv6: bool) -> NetResult<()>
    {
        if (hdr.flags & tcp_flags::SYN) == 0 { return Ok(()); }
        let Some((listener, keep)) = select_listener_for_syn(
            self, net_ns, iface, src_ip, dst_ip, seg, packet, hdr, tables, hop, ipv6)
        else { return Ok(()); };
        let seg = &seg[..keep];
        // F180b: synthesise a per-conn local endpoint that pins the
        // wildcard listener to the actual delivery dst — so outbound
        // segments carry a real src, not 0.0.0.0/::.
        let mut local_ep = listener.local;
        if local_ep.ip == IpAddr::V4(Ipv4Addr::ANY) || local_ep.ip == IpAddr::V6(Ipv6Addr::ANY) {
            local_ep.ip = dst_ip;
        }
        // F192: enforce listen backlog. Drop the SYN on the floor
        // when accept_q is already at cap — peer retries naturally
        // via SYN retx.
        if !listener.reserve_backlog() { return Ok(()); }
        // F184: SYN-ACK we're about to build advertises our MSS too.
        let bound = listener.bound_iface();
        let ip_mode = listener.ip_mtu_discover.load(
            ::core::sync::atomic::Ordering::Acquire);
        let ipv6_mode = listener.ipv6_mtu_discover.load(
            ::core::sync::atomic::Ordering::Acquire);
        let own_mss = self.mss_for_dst_on_iface_pmtu_modes_in(
            net_ns, src_ip, bound, ip_mode, ipv6_mode);
        let metrics = self.route_metrics_for_dst_in(net_ns, src_ip, bound);
        // Handshake input runs against the heap-resident child, so the
        // connection state never occupies a frame on the delivery path.
        let new_entry = build_passive_child(local_ep, own_mss, metrics, packet, &listener);
        let resp = match new_entry.conn.lock().input_prevalidated(src_ip, dst_ip, seg) {
            Ok(resp) => resp,
            Err(_) => {
                listener.syn_backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
                return Err(NetError::Einval);
            }
        };
        if !super::tcp_listener::publish_passive_child(&tables, &listener, key, &new_entry) {
            return Ok(());
        }
        if let Some(r) = resp {
            if let Err(error) = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &r, 0, bound,
                TcpTxPolicy::Entry(&new_entry))
            {
                super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &new_entry);
                new_entry.release_backlog();
                new_entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Build the passive child connection directly onto the heap.
///
/// Pick the listener a SYN belongs to and how much of the segment its filter
/// retains.
///
/// `#[inline(never)]` and separate on purpose: the candidate bucket, the
/// reuseport selection and the two filter contexts are dead the moment a
/// listener is chosen, but inlined they keep their slots reserved for the rest
/// of the passive open — which transmits a SYN-ACK and, over loopback,
/// re-enters the whole receive path on top of them.
/// # C: O(bucket) select + O(segment) filter
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn select_listener_for_syn(stack: &NetStack, net_ns: u64, iface: NetIfaceId, src_ip: IpAddr,
    dst_ip: IpAddr, seg: &[u8], packet: &[u8], hdr: &crate::tcp_hdr::TcpHdr,
    tables: &super::inet_tables::InetTables, hop: u8, ipv6: bool)
    -> Option<(Arc<TcpListenEntry>, usize)>
{
    let bucket = {
        let g = tables.tcp_listens.lock();
        super::tcp_listener::lookup_listen_bucket(&g, dst_ip, hdr.dst_port)
    }?;
    // F192: an attached SO_REUSEPORT program picks the listener; without
    // one the 4-tuple hash distributes. Single-entry bucket -> idx 0.
    let idx = super::tcp_listener::select_listener_index(
        &bucket, src_ip, hdr.src_port, hdr.dst_port, seg);
    let mut listener = None;
    for off in 0..bucket.len() {
        let cand = bucket[(idx + off) % bucket.len()].clone();
        // A listener demanding a hop-limit minimum drops the connection
        // request silently, exactly as an established socket does.
        if cand.min_hop.refuses(hop, ipv6) { continue; }
        if cand.bound_iface().is_none_or(|id| id == iface) {
            listener = Some(cand);
            break;
        }
    }
    let listener = listener?;
    let protocol = match dst_ip {
        IpAddr::V4(_) => crate::addr::eth_p::IPV4,
        IpAddr::V6(_) => crate::addr::eth_p::IPV6,
    };
    if !crate::cgroup_bpf::ingress(&listener.owner, packet, protocol, iface) { return None; }
    let keep = crate::bpf_filter::retained_tcp_len(
        listener.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
            packet: seg, protocol, ifindex: Some(iface.raw()),
            pay_offset: hdr.payload_offset() as u32,
            hatype: stack.ifaces.lookup_in_ns(iface, net_ns)
                .map_or(0, |dev| dev.hardware_type()),
        }), seg,
    )?;
    Some((listener, keep))
}

/// `#[inline(never)]` and separate on purpose: a `TcpConn` plus the `TcpEntry` that
/// wraps it are hundreds of bytes each, and constructing them inline put both in the
/// delivery frame — a frame that then continues into transmit. Linux allocates the
/// child sock (`inet_csk_clone_lock`) rather than building a connection on the stack.
/// # C: O(1)
#[inline(never)]
fn build_passive_child(local_ep: Endpoint, own_mss: u16,
    metrics: crate::route_metrics::RouteMetrics, packet: &[u8],
    listener: &Arc<TcpListenEntry>) -> Arc<TcpEntry>
{
    let mut conn = TcpConn::new_listener(local_ep);
    conn.own_mss = own_mss;
    conn.apply_route_metrics(metrics);
    // Record the handshake packet the child was opened by, from the network
    // header onward, so an accepted socket that asked for it with
    // `TCP_SAVE_SYN` has something to collect. It is dropped with the
    // connection if nobody does.
    conn.syn_bytes = Some(
        packet[..::core::cmp::min(packet.len(), crate::stack::SAVED_SYN_MAX)].to_vec());
    Arc::new(TcpEntry::new_bound_full(
        conn, Arc::new(crate::SocketError::new()), Some(listener.bind.clone()),
        Arc::new(crate::bpf_filter::SocketFilter::inherited(&listener.bpf_filter)),
        Arc::new(::core::sync::atomic::AtomicI32::new(
            listener.ip_mtu_discover.load(::core::sync::atomic::Ordering::Acquire))),
        Arc::new(::core::sync::atomic::AtomicI32::new(
            listener.ipv6_mtu_discover.load(::core::sync::atomic::Ordering::Acquire))),
        Some(Arc::downgrade(listener)),
        // The hop-limit minimums stay SHARED with the listener rather than
        // snapshotted: a later write reaches every child, which is what a
        // socket option inherited from a listening socket does.
        listener.min_hop.clone(),
    ))
}
