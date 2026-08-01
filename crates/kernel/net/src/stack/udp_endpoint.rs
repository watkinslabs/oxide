use super::*;

impl UdpRxQueue {
    /// # C: O(1)
    pub fn new(bound_ip: Ipv4Addr, bound_port: u16) -> Self {
        Self::new_with_error(bound_ip, bound_port, Arc::new(crate::SocketError::new()))
    }

    /// Queue bound to one socket's canonical error state. # C: O(1)
    pub fn new_with_error(bound_ip: Ipv4Addr, bound_port: u16, error: Arc<crate::SocketError>) -> Self {
        Self::new_socket(0, bound_ip, bound_port, error,
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            crate::SocketOwner::root(network_namespace::initial(), 0),
            Arc::new(Spinlock::new(None)), Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Build one socket-owned endpoint for a grouped UDP port binding. # C: O(1)
    pub fn new_socket(_net_ns: u64, bound_ip: Ipv4Addr, bound_port: u16, error: Arc<crate::SocketError>,
                      reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                      reuseport: Arc<::core::sync::atomic::AtomicI32>,
                      ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                      gro: Arc<::core::sync::atomic::AtomicI32>,
                      owner: Arc<crate::SocketOwner>,
                      peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                      bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                      mcast: Arc<crate::mcast_filter::SocketMcast>) -> Self {
        Self {
            owner, bound_ip, bound_port,
            state: Spinlock::new(UdpRxState { accepting: true, datagrams: VecDeque::new() }),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error, peer, reuseaddr, reuseport, ip_mtu_discover, gro,
            bound_ifindex: ::core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None), bpf_filter, mcast,
            reuseport_group: crate::reuseport::new_slot(),
        }
    }

    /// Publish an asynchronous socket error and wake all endpoint observers. # C: O(1)
    pub fn set_error(&self, errno: i32) -> bool {
        let state = self.state.lock();
        if !state.accepting || !self.error.set(errno) { return false; }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let slot = self.poll_subs.lock().clone();
        if let Some(weak) = slot {
            if let Some(s) = weak.upgrade() { s.notify_mask(vfs::POLL_ERR); }
        }
        true
    }

    /// Publish one ICMP error using this endpoint's connected/RECVERR policy. # C: O(1)
    pub fn publish_error(&self, entry: crate::SocketErrorEntry, hard: bool) -> bool {
        let connected = self.peer.lock().is_some();
        let state = self.state.lock();
        if !state.accepting || !self.error.publish(entry, connected, hard) { return false; }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let slot = self.poll_subs.lock().clone();
        if let Some(weak) = slot {
            if let Some(s) = weak.upgrade() { s.notify_mask(vfs::POLL_ERR); }
        }
        true
    }

    /// Register bound socket's subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Pop or peek one endpoint-local datagram. # C: O(payload when peeking)
    pub fn recv(&self, peek: bool) -> Option<UdpDatagram> {
        self.recv_gro(peek).map(|(datagram, _)| datagram)
    }

    /// Pop or peek one receive together with the segment size it reports when
    /// several datagrams were coalesced into it. # C: O(payload when peeking)
    pub fn recv_gro(&self, peek: bool) -> Option<(UdpDatagram, Option<usize>)> {
        let mut state = self.state.lock();
        let queued = if peek { state.datagrams.front().cloned() }
            else { state.datagrams.pop_front() };
        queued.map(|q| { let seg = q.gro.cmsg_seg_size(); (q.datagram, seg) })
    }

    /// `UDP_GRO` is engaged on the owning socket. # C: O(1)
    pub fn gro_enabled(&self) -> bool {
        self.gro.load(::core::sync::atomic::Ordering::Acquire) != 0
    }

    /// Queue one datagram if this endpoint still accepts delivery. # C: O(payload)
    pub fn enqueue(&self, datagram: UdpDatagram) -> bool {
        self.enqueue_gro(datagram, false, false)
    }

    /// Deliver one datagram, coalescing it into the queued run when the
    /// canonical rule admits it and the ingress interface offers coalescing.
    /// # C: O(payload)
    pub fn enqueue_gro(&self, datagram: UdpDatagram, checksum_zero: bool, offered: bool) -> bool {
        use crate::udp_gro::{GroAdmit, GroRun, admit};
        let mut state = self.state.lock();
        if !state.accepting { return false; }
        let len = datagram.payload.len();
        let same_flow = state.datagrams.back()
            .is_some_and(|q| udp4_same_flow(&q.datagram, &datagram));
        let decision = admit(state.datagrams.back().map(|q| &q.gro), same_flow, len,
            checksum_zero,
            crate::udp_gro::coalescable_receive(offered, datagram.frag_max)
                && self.gro_enabled());
        match decision {
            GroAdmit::Merge => {
                let tail = state.datagrams.back_mut().expect("a merge names a tail");
                tail.datagram.payload.extend_from_slice(&datagram.payload);
                tail.gro.extend(len);
            }
            GroAdmit::Separate { open } => {
                let gro = if open { GroRun::open(len) } else { GroRun::single(len) };
                state.datagrams.push_back(QueuedUdp { datagram, gro });
            }
        }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN); }
        }
        true
    }

    /// Stop future delivery; accepted datagrams remain endpoint-observable. # C: O(1)
    pub fn deactivate(&self) {
        let mut state = self.state.lock();
        if !state.accepting { return; }
        state.accepting = false;
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN | vfs::POLL_HUP); }
        }
    }

    /// Number of queued datagrams. # C: O(1)
    pub fn queued_len(&self) -> usize { self.state.lock().datagrams.len() }

    /// Whether the endpoint still accepts network delivery. # C: O(1)
    pub fn is_accepting(&self) -> bool { self.state.lock().accepting }

    /// Total queued payload bytes. # C: O(N)
    pub fn queued_bytes(&self) -> usize {
        self.state.lock().datagrams.iter().map(|q| q.datagram.payload.len()).sum()
    }

    /// Atomically publish read shutdown against receive delivery. # C: O(1)
    pub fn shutdown_read(&self, read_shut: &::core::sync::atomic::AtomicBool) {
        let _state = self.state.lock();
        read_shut.store(true, ::core::sync::atomic::Ordering::Release);
    }

    /// Register the current task as a waiter only while the endpoint is idle. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn park_if_idle(&self, read_shut: &::core::sync::atomic::AtomicBool, deadline_ns: u64) -> bool {
        let state = self.state.lock();
        if !state.datagrams.is_empty() || self.error.has()
            || read_shut.load(::core::sync::atomic::Ordering::Acquire) { return false; }
        // SAFETY: process context; endpoint state closes the delivery/wait race.
        unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(state);
        true
    }
}

/// Two IPv4 receives belong to one coalescing flow when they share the source
/// endpoint, the local endpoint they arrived on, the ingress interface, and
/// EVERY header value the receive ancillary messages publish.
///
/// The device-level check compares only the protocol and the two addresses,
/// but a coalesced receive reports ONE hop limit, ONE type-of-service byte and
/// ONE option area for every datagram merged into it — so a receive path that
/// publishes those values has to refuse a merge that would make them a lie.
/// # C: O(option area)
fn udp4_same_flow(a: &UdpDatagram, b: &UdpDatagram) -> bool {
    a.src == b.src && a.sport == b.sport && a.dst == b.dst && a.dport == b.dport
        && a.iface == b.iface && a.ttl == b.ttl && a.tos == b.tos && a.options == b.options
}
