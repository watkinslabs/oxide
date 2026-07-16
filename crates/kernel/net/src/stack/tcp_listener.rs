use super::*;

/// Result of atomically rechecking and arming a blocking TCP accept.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpAcceptWait {
    /// A completed child is ready for `tcp_accept`.
    Ready,
    /// Listener teardown owns the queue and no future child can arrive.
    Closed,
    /// The current task was registered while the accept queue lock was held.
    Parked,
}

pub(super) fn remove_tcp_entry_exact(tables: &super::inet_tables::InetTables,
                                     key: &TcpKey, entry: &Arc<TcpEntry>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if !conns.get(key).is_some_and(|current| Arc::ptr_eq(current, entry)) { return false; }
    conns.remove(key);
    true
}

pub(super) fn publish_passive_child(tables: &super::inet_tables::InetTables,
                                    listener: &TcpListenEntry, key: TcpKey,
                                    entry: &Arc<TcpEntry>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if listener.is_closed() || conns.contains_key(&key) {
        drop(conns);
        entry.release_backlog();
        entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
        return false;
    }
    conns.insert(key, entry.clone());
    true
}

impl TcpListenEntry {
    /// # C: O(1)
    pub fn new(bind: Arc<TcpBindReservation>) -> Self {
        Self::new_with_filter(bind, Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)))
    }

    /// Build a listener sharing its socket's live filter. # C: O(1)
    pub fn new_with_filter(bind: Arc<TcpBindReservation>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> Self {
        Self {
            accept_q: Spinlock::new(VecDeque::new()), local: bind.local, bind, bpf_filter,
            ip_mtu_discover, ipv6_mtu_discover,
            backlog: ::core::sync::atomic::AtomicUsize::new(128),
            backlog_used: ::core::sync::atomic::AtomicUsize::new(0),
            closed: ::core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }

    /// Reserve one listen backlog slot across handshake and accept. # C: O(1)
    pub fn reserve_backlog(&self) -> bool {
        if self.closed.load(::core::sync::atomic::Ordering::Acquire) { return false; }
        let cap = self.backlog.load(::core::sync::atomic::Ordering::Acquire);
        let reserved = self.backlog_used.fetch_update(
            ::core::sync::atomic::Ordering::AcqRel,
            ::core::sync::atomic::Ordering::Acquire,
            |used| (used < cap).then_some(used + 1),
        ).is_ok();
        if reserved && self.closed.load(::core::sync::atomic::Ordering::Acquire) {
            self.backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
            return false;
        }
        reserved
    }

    /// Publish a completed passive child unless close already owns the queue. # C: O(1)
    pub fn enqueue_accepted(&self, entry: Arc<TcpEntry>) -> bool {
        let mut queue = self.accept_q.lock();
        if self.closed.load(::core::sync::atomic::Ordering::Acquire) { return false; }
        queue.push_back(entry);
        drop(queue);
        #[cfg(target_os = "oxide-kernel")]
        self.accept_waiters.wake_all();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN); }
        }
        true
    }

    /// Close admission and take every completed unaccepted child. # C: O(N)
    pub fn close_accept_queue(&self) -> Vec<Arc<TcpEntry>> {
        self.close_accept_queue_with(|| {
            #[cfg(target_os = "oxide-kernel")]
            self.accept_waiters.wake_all();
        })
    }

    fn close_accept_queue_with(&self, wake: impl FnOnce()) -> Vec<Arc<TcpEntry>> {
        let mut queue = self.accept_q.lock();
        self.closed.store(true, ::core::sync::atomic::Ordering::Release);
        let queued = queue.drain(..).collect();
        drop(queue);
        wake();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN | vfs::POLL_HUP); }
        }
        queued
    }

    /// True after listener close owns child admission. # C: O(1)
    pub fn is_closed(&self) -> bool {
        self.closed.load(::core::sync::atomic::Ordering::Acquire)
    }

    /// F192: apply Linux unsigned backlog normalization. # C: O(1)
    pub fn set_backlog(&self, b: i32, limit: usize) {
        let n = crate::sysctl::normalize_listen_backlog(b, limit);
        self.backlog.store(n, ::core::sync::atomic::Ordering::Release);
    }

    /// F181a: register listener-fd subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// Atomically recheck the accept queue and park an interruptible caller. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_accept_wait(&self, deadline_ns: u64) -> TcpAcceptWait {
        self.arm_accept_wait_with(|| {
            // SAFETY: queue lock serializes child and close publication with
            // wait registration; both publishers wake after dropping it.
            unsafe { self.accept_waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    fn arm_accept_wait_with(&self, arm: impl FnOnce()) -> TcpAcceptWait {
        let q = self.accept_q.lock();
        if !q.is_empty() { return TcpAcceptWait::Ready; }
        if self.closed.load(::core::sync::atomic::Ordering::Acquire) {
            return TcpAcceptWait::Closed;
        }
        arm();
        drop(q);
        TcpAcceptWait::Parked
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> { self.bind.bound_iface() }
}

impl NetStack {
    /// Open v4 listener at (ip,port). Eaddrinuse if taken or TIME_WAIT
    /// conflict (unless SO_REUSEADDR). # C: O(log N + N_conns).
    pub fn tcp_listen(&self, local_ip: Ipv4Addr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip(IpAddr::V4(local_ip), local_port, reuseaddr)
    }

    /// F180b: address-family-aware listen (v4 + v6). # C: O(log N).
    pub fn tcp_listen_ip(&self, local_ip: IpAddr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip_with(local_ip, local_port, reuseaddr, false)
    }

    /// F192: SO_REUSEPORT-aware listener publication. # C: O(log N).
    pub fn tcp_listen_ip_with(&self, local_ip: IpAddr, local_port: u16,
                              reuseaddr: bool, reuseport: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        let bind = self.tcp_reserve(local_ip, local_port, None, reuseaddr, reuseport, 0,
            matches!(local_ip, IpAddr::V6(_)))?;
        self.tcp_listen_reserved(&bind)
    }

    /// Pop one accepted connection from listener's backlog. # C: O(1)
    pub fn tcp_accept(&self, listener: &TcpListenEntry) -> Option<Arc<TcpEntry>> {
        let entry = {
            let mut queue = listener.accept_q.lock();
            if listener.is_closed() { return None; }
            let entry = queue.pop_front()?;
            entry.accepted.store(true, ::core::sync::atomic::Ordering::Release);
            entry
        };
        entry.release_backlog();
        Some(entry)
    }

    /// Remove a listener and every passive child not transferred by accept. # C: O(N)
    pub fn tcp_unlisten_entry(&self, entry: &Arc<TcpListenEntry>) {
        let queued = entry.close_accept_queue();
        let key = TcpListenKey { local_ip: entry.local.ip, local_port: entry.local.port };
        let Some(tables) = self.try_inet_tables(entry.bind.net_ns()) else {
            for child in queued { child.release_backlog(); child.close_and_wake(); }
            entry.bind.role.store(TCP_BIND_BOUND, ::core::sync::atomic::Ordering::Release);
            return;
        };
        {
            let mut listeners = tables.tcp_listens.lock();
            if let Some(entries) = listeners.get_mut(&key) {
                entries.retain(|old| !Arc::ptr_eq(old, entry));
                if entries.is_empty() { listeners.remove(&key); }
            }
        }
        let mut removed = Vec::new();
        {
            let mut conns = tables.tcp_conns.lock();
            conns.retain(|_, child| {
                let listener_owned = !child.accepted.load(
                    ::core::sync::atomic::Ordering::Acquire)
                    && child.passive_listener.as_ref()
                        .and_then(alloc::sync::Weak::upgrade)
                        .is_some_and(|owner| Arc::ptr_eq(&owner, entry));
                if listener_owned { removed.push(child.clone()); }
                !listener_owned
            });
        }
        for child in queued.iter().chain(removed.iter()) {
            child.release_backlog();
            child.close_and_wake();
        }
        entry.bind.role.store(TCP_BIND_BOUND, ::core::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
#[path = "tcp_listener_tests.rs"]
mod tests;
