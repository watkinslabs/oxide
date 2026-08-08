use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use vfs;

use super::{GcNode, GcRights, UnixAddr};

pub struct UnixDgram {
    pub payload: Vec<u8>,
    /// Sender's (pid, uid, gid) at sendmsg time.
    pub creds: crate::unix_sock::MsgCred,
    /// F189: SCM_RIGHTS — files carried alongside the payload.
    pub fds: Vec<Arc<vfs::File>>,
}

pub struct UnixDgramRecord {
    pub msg: UnixDgram,
    pub sender: Option<UnixAddr>,
    rights: GcRights,
    /// Linux `skb->sk` — the SENDING socket that owns this record's write-memory
    /// charge. Held so the charge is released against the sender, not the
    /// receiver, when the record is freed.
    owner: Option<Arc<UnixDgramQueue>>,
    /// Linux `skb->truesize` — the exact amount charged to `owner`'s
    /// `sk_wmem_alloc`, so release subtracts what push added even if the
    /// payload was truncated afterwards.
    charge: usize,
}

/// Linux `sock_wfree`, the skb destructor: give the sender back its
/// `sk_wmem_alloc` charge and run `sk_write_space` on it. Implemented as `Drop`
/// so EVERY removal path — `recv_with`, the release drain, queue teardown —
/// settles the charge without each having to remember to.
impl Drop for UnixDgramRecord {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else { return };
        owner.release_wmem(self.charge);
    }
}

impl UnixDgramRecord {
    /// Take the payload out of a record that is about to be dropped. `Drop`
    /// (the `sock_wfree` charge release) forbids moving fields out, so the
    /// payload is taken in place and the destructor still settles the charge.
    /// # C: O(1)
    fn take_msg(&mut self) -> (UnixDgram, Option<UnixAddr>) {
        let msg = UnixDgram {
            payload: core::mem::take(&mut self.msg.payload),
            creds:   self.msg.creds.clone(),
            fds:     core::mem::take(&mut self.msg.fds),
        };
        (msg, self.sender.take())
    }
}

impl core::ops::Deref for UnixDgramRecord {
    type Target = UnixDgram;
    fn deref(&self) -> &Self::Target { &self.msg }
}

pub struct UnixDgramQueue {
    pub msgs: Spinlock<VecDeque<UnixDgramRecord>, UnixLockClass>,
    /// Bound local address for pathname/abstract datagram sockets.
    pub bound: Spinlock<Option<UnixAddr>, UnixLockClass>,
    /// Connected peer address for AF_UNIX SOCK_DGRAM.
    pub peer: Spinlock<Option<UnixAddr>, UnixLockClass>,
    /// Bound socket owning this registry entry; its file credentials are the
    /// one source of truth for the publishing Landlock domain.
    owner_socket: Spinlock<Option<alloc::sync::Weak<crate::sock::InetSocket>>, UnixLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    pub reader_shutdown: core::sync::atomic::AtomicBool,
    queued_bytes: core::sync::atomic::AtomicUsize,
    /// Linux `sk->sk_wmem_alloc`: bytes THIS socket has sent that the receiving
    /// end has not yet freed. Charged on send, released by the record's
    /// destructor. This — not the destination's receive queue — is what bounds
    /// a symmetrically connected pair (`unix_writable`).
    wmem: core::sync::atomic::AtomicUsize,
    shutdown_generation: core::sync::atomic::AtomicU64,
    released: core::sync::atomic::AtomicBool,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub writers: sched::live::WaitList,
    /// F181a: epoll subscribers of the owning InetSocket.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// Wait queues of OTHER sockets that are connected to this
    /// one and found it full during `unix_dgram_poll`. Their `EPOLLOUT`
    /// depends on THIS queue draining, and they are subscribed to their own
    /// list, not to this one — without the relay a poll-driven connected
    /// datagram writer parks and is never woken. Weak, deduped by pointer,
    /// pruned on every wake.
    peer_writer_subs: Spinlock<Vec<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    gc: GcNode,
}

impl UnixDgramQueue {
    /// Associate this queue with its bound socket. # C: O(1)
    pub fn set_owner_socket(&self, sock: &Arc<crate::sock::InetSocket>) {
        *self.owner_socket.lock() = Some(Arc::downgrade(sock));
    }

    /// Sandbox domain in the bound socket's file credentials. # C: O(1)
    pub fn owner_domain(&self) -> Option<Arc<landlock::Domain>> {
        self.owner_socket.lock().as_ref()?.upgrade()?.file_domain()
    }

    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Self::new_with_filter(Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build a queue sharing its owning socket's filter state. # C: O(1)
    pub fn new_with_filter(bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Arc<Self> {
        Arc::new(Self {
            msgs: Spinlock::new(VecDeque::new()),
            bound: Spinlock::new(None),
            peer: Spinlock::new(None),
            owner_socket: Spinlock::new(None),
            bpf_filter,
            reader_shutdown: core::sync::atomic::AtomicBool::new(false),
            queued_bytes: core::sync::atomic::AtomicUsize::new(0),
            wmem: core::sync::atomic::AtomicUsize::new(0),
            shutdown_generation: core::sync::atomic::AtomicU64::new(0),
            released: core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            writers: sched::live::WaitList::new(),
            peer_writer_subs: Spinlock::new(Vec::new()),
            subs: Spinlock::new(None),
            gc: GcNode::new(),
        })
    }

    /// Stable identity of this datagram receive queue. # C: O(1)
    pub fn gc_node(&self) -> GcNode { self.gc.clone() }

    /// Store the local bind address.
    /// # C: O(1)
    pub fn set_bound(&self, addr: UnixAddr) {
        *self.bound.lock() = Some(addr);
    }

    /// Return the local bind address, if any.
    /// # C: O(1)
    pub fn bound(&self) -> Option<UnixAddr> {
        self.bound.lock().clone()
    }

    /// F181a: register owning InetSocket's subscribers.
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Store the connected datagram peer.
    /// # C: O(1)
    pub fn set_peer(&self, addr: UnixAddr) {
        *self.peer.lock() = Some(addr);
    }

    /// Clear the connected datagram peer. # C: O(1)
    pub fn clear_peer(&self) {
        *self.peer.lock() = None;
    }

    /// Return the connected datagram peer, if any.
    /// # C: O(1)
    pub fn peer(&self) -> Option<UnixAddr> {
        self.peer.lock().clone()
    }

    /// Enqueue unless the owning socket shut down its receive half.
    /// # C: O(1)
    pub fn try_push(&self, mut msg: UnixDgram) -> Result<(), crate::NetError> {
        let rights = GcRights::from_files(core::mem::take(&mut msg.fds));
        self.try_push_from_with_rights(msg, None, rights)
    }

    /// Enqueue a datagram with its sender address and embedded file batch. # C: O(rights)
    pub fn try_push_from(&self, mut msg: UnixDgram, sender: Option<UnixAddr>) -> Result<(), crate::NetError> {
        let rights = GcRights::from_files(core::mem::take(&mut msg.fds));
        self.try_push_from_with_rights(msg, sender, rights)
    }

    /// Enqueue a datagram with a classified canonical rights batch. # C: O(1)
    pub fn try_push_with_rights(&self, msg: UnixDgram, rights: GcRights) -> Result<(), crate::NetError> {
        self.try_push_from_with_rights(msg, None, rights)
    }

    /// Linux `refcount_read(&sk->sk_wmem_alloc)` for this socket. # C: O(1)
    pub fn wmem_alloc(&self) -> usize { self.wmem.load(core::sync::atomic::Ordering::Acquire) }

    /// Linux `sk_write_space`: the sender's write memory dropped, so anything
    /// parked on or polling THIS socket's write side must re-evaluate.
    /// # C: O(1) + O(subscribers)
    pub fn wake_write_space(&self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            self.writers.wake_all();
            if let Some(subs) = self.subs.lock().as_ref().and_then(|weak| weak.upgrade()) {
                subs.notify_mask(vfs::POLL_OUT | vfs::POLL_WRNORM);
            } else { sched::live::notify_epoll_waiters(); }
        }
    }

    /// Linux `sock_wfree`: settle one original skb allocation charge.
    fn release_wmem(&self, charge: usize) {
        self.wmem.fetch_sub(charge, core::sync::atomic::Ordering::AcqRel);
        self.wake_write_space();
    }

    /// Enqueue one canonical record with its optional sender address. # C: O(1)
    pub fn try_push_from_with_rights(&self, msg: UnixDgram, sender: Option<UnixAddr>, rights: GcRights) -> Result<(), crate::NetError> {
        self.try_push_from_with_rights_bounded(msg, sender, rights, usize::MAX)
    }

    /// `sock_alloc_send_pskb` + `skb_set_owner_w`: charge the SENDER's
    /// `sk_wmem_alloc` for this datagram and hand ownership to the queued
    /// record, whose destructor releases it (`sock_wfree`).
    ///
    /// `owner_sndbuf` is the sender's `SO_SNDBUF`. A sender over its
    /// `unix_writable` watermark gets `EAGAIN` here, which is the bound Linux
    /// relies on for a symmetrically connected pair — the destination's receive
    /// queue is deliberately NOT consulted for one (`unix_peer(other) == sk`),
    /// so without this a socketpair would be unbounded.
    /// # C: O(1)
    pub fn try_push_owned(&self, msg: UnixDgram, sender: Option<UnixAddr>, rights: GcRights,
        cap: usize, owner: &Arc<UnixDgramQueue>, owner_sndbuf: usize)
        -> Result<(), crate::NetError>
    {
        let charge = message_charge(msg.payload.len());
        if !super::unix_writable(owner.wmem_alloc().saturating_add(charge), owner_sndbuf) {
            return Err(crate::NetError::Eagain);
        }
        owner.wmem.fetch_add(charge, core::sync::atomic::Ordering::AcqRel);
        match self.try_push_from_with_rights_bounded_owned(msg, sender, rights, cap,
            Some(owner.clone()), charge)
        {
            Ok(()) => Ok(()),
            Err(e) => {
                // The record was never queued, so no destructor will run.
                owner.release_wmem(charge);
                Err(e)
            }
        }
    }

    /// Enqueue one atomic datagram under the sender's queue cap. # C: O(1)
    pub fn try_push_from_with_rights_bounded(&self, msg: UnixDgram, sender: Option<UnixAddr>,
        rights: GcRights, cap: usize) -> Result<(), crate::NetError>
    {
        self.try_push_from_with_rights_bounded_owned(msg, sender, rights, cap, None, 0)
    }

    /// [`try_push_from_with_rights_bounded`] carrying the sender's write-memory
    /// ownership (`skb->sk` / `skb->truesize`). # C: O(1)
    ///
    /// Send admission charges a message before filtering; filtering changes
    /// its length, not its charged size; and
    /// Linux `sock_wfree` releases that original `truesize` whether
    /// the filter drops or truncates the skb.
    fn try_push_from_with_rights_bounded_owned(&self, mut msg: UnixDgram, sender: Option<UnixAddr>,
        rights: GcRights, cap: usize, owner: Option<Arc<UnixDgramQueue>>, charge: usize)
        -> Result<(), crate::NetError>
    {
        if message_charge(msg.payload.len()) > cap {
            drop(rights);
            super::collect_scm_rights();
            return Err(crate::NetError::Emsgsize);
        }
        let verdict = self.bpf_filter.verdict(&msg.payload);
        if verdict == 0 {
            drop(rights);
            super::collect_scm_rights();
            if let Some(owner) = owner { owner.release_wmem(charge); }
            return Ok(());
        }
        msg.payload.truncate(msg.payload.len().min(verdict as usize));
        let transition = self.gc.pin();
        rights.register(&self.gc);
        let mut q = self.msgs.lock();
        if self.released.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Econnrefused); }
        if self.reader_shutdown.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Epipe); }
        let queued_charge = message_charge(msg.payload.len());
        if self.queued_bytes.load(core::sync::atomic::Ordering::Relaxed).saturating_add(queued_charge) > cap {
            return Err(crate::NetError::Eagain);
        }
        q.push_back(UnixDgramRecord { msg, sender, rights, owner, charge });
        self.queued_bytes.fetch_add(queued_charge, core::sync::atomic::Ordering::Relaxed);
        drop(q);
        drop(transition);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.waiters.wake_all();
            if let Some(subs) = self.subs.lock().as_ref().and_then(|weak| weak.upgrade()) {
                subs.notify_mask(vfs::POLL_IN);
            } else { sched::live::notify_epoll_waiters(); }
        }
        Ok(())
    }

    /// Preserve queued datagrams, then expose EOF and reject later sends.
    /// # C: O(1)
    pub fn shutdown_reader(&self) {
        let q = self.msgs.lock();
        if !self.reader_shutdown.swap(true, core::sync::atomic::Ordering::AcqRel) {
            self.shutdown_generation.fetch_add(1, core::sync::atomic::Ordering::Release);
        }
        drop(q);
        #[cfg(target_os = "oxide-kernel")]
        { self.waiters.wake_all(); self.writers.wake_all(); }
    }

    /// Close the queue at final fput and release all unread messages.
    /// # C: O(unread messages + descriptors + SCM collection)
    pub fn release(&self) {
        let dropped = {
            let mut q = self.msgs.lock();
            self.released.store(true, core::sync::atomic::Ordering::Release);
            self.reader_shutdown.store(true, core::sync::atomic::Ordering::Release);
            self.shutdown_generation.fetch_add(1, core::sync::atomic::Ordering::Release);
            self.queued_bytes.store(0, core::sync::atomic::Ordering::Relaxed);
            core::mem::take(&mut *q)
        };
        drop(dropped);
        super::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        { self.waiters.wake_all(); self.writers.wake_all(); }
    }

    /// Pop one dgram if any.
    /// # C: O(1)
    pub fn pop(&self) -> Option<UnixDgram> {
        self.recv_with(false, |_, _, _| Ok::<(), core::convert::Infallible>(()))
            .unwrap_or_else(|never| match never {}).map(|(_, msg, _)| msg)
    }

    /// Inspect one datagram under the queue lock. Callback failure consumes a
    /// normal receive and preserves a peeked record. # C: O(payload + rights)
    pub fn recv_with<R, E>(&self, peek: bool,
        copy: impl FnOnce(&UnixDgram, Option<&UnixAddr>, usize) -> Result<R, E>)
        -> Result<Option<(R, UnixDgram, Option<UnixAddr>)>, E>
    {
        let mut q = self.msgs.lock();
        let Some(front) = q.front() else { return Ok(None); };
        let copied = match copy(&front.msg, front.sender.as_ref(), front.rights.len()) {
            Ok(copied) => copied,
            Err(err) => {
                let dropped = if peek { None } else { q.pop_front() };
                if let Some(record) = dropped.as_ref() {
                    self.queued_bytes.fetch_sub(message_charge(record.payload.len()), core::sync::atomic::Ordering::Relaxed);
                }
                drop(q);
                #[cfg(target_os = "oxide-kernel")]
                if dropped.is_some() { self.wake_writers(); }
                drop(dropped);
                if !peek { super::collect_scm_rights(); }
                return Err(err);
            }
        };
        if peek {
            let msg = UnixDgram { payload: front.payload.clone(), creds: front.creds.clone(), fds: front.rights.clone_files() };
            return Ok(Some((copied, msg, front.sender.clone())));
        }
        let mut record = q.pop_front().unwrap();
        self.queued_bytes.fetch_sub(message_charge(record.payload.len()), core::sync::atomic::Ordering::Relaxed);
        drop(q);
        #[cfg(target_os = "oxide-kernel")]
        self.wake_writers();
        record.msg.fds = record.rights.take_files();
        let (msg, sender) = record.take_msg();
        Ok(Some((copied, msg, sender)))
    }

    /// Snapshot the receive shutdown generation before an empty receive attempt. # C: O(1)
    pub fn shutdown_generation(&self) -> u64 {
        self.shutdown_generation.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Current charged receive-queue bytes. # C: O(1)
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(core::sync::atomic::Ordering::Acquire)
    }

    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_read(&self, generation: u64, deadline_ns: u64) -> ArmDgramRead {
        let q = self.msgs.lock();
        if !q.is_empty() { return ArmDgramRead::Retry; }
        if self.shutdown_generation() != generation { return ArmDgramRead::Shutdown; }
        // SAFETY: registration occurs under the message lock held by enqueue,
        // shutdown, and release before their wake publication.
        unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(q);
        ArmDgramRead::Parked
    }

    /// Park the SENDER on its own write-space list when its `sk_wmem_alloc` is
    /// over the `unix_writable` watermark — the bound a symmetric pair has
    /// instead of the destination's receive queue. Registration happens under
    /// this queue's message lock, which `wake_write_space`'s callers hold before
    /// publishing, so the wake cannot be lost.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_write_wmem(&self, charge: usize, sndbuf: usize, deadline_ns: u64) -> ArmDgramWrite {
        let _q = self.msgs.lock();
        if super::unix_writable(self.wmem_alloc().saturating_add(charge), sndbuf) {
            return ArmDgramWrite::Retry;
        }
        // SAFETY: registration under the message lock the write-space wake takes
        // before publishing, so a concurrent release cannot miss this waiter.
        unsafe { self.writers.park_interruptible_with_deadline(deadline_ns); }
        ArmDgramWrite::Parked
    }

    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_write(&self, len: usize, cap: usize, deadline_ns: u64) -> ArmDgramWrite {
        let _q = self.msgs.lock();
        if self.released.load(core::sync::atomic::Ordering::Acquire)
            || self.reader_shutdown.load(core::sync::atomic::Ordering::Acquire)
        { return ArmDgramWrite::PeerClosed; }
        let charge = message_charge(len);
        if charge > cap { return ArmDgramWrite::MessageTooLarge; }
        if self.queued_bytes().saturating_add(charge) <= cap { return ArmDgramWrite::Retry; }
        // SAFETY: registration occurs under the message lock held by receive
        // and terminal transitions before their writer wake publication.
        unsafe { self.writers.park_interruptible_with_deadline(deadline_ns); }
        ArmDgramWrite::Parked
    }

    /// Linux `unix_dgram_peer_wake_connect`: remember `subs` so this queue's
    /// drain relays an `EPOLLOUT` wake to the connected sender that just
    /// observed us full. Idempotent on pointer identity.
    /// # C: O(N_registered)
    pub fn register_peer_writer(&self, subs: &Arc<vfs::PollSubscribers>) {
        let want = Arc::as_ptr(subs);
        let mut g = self.peer_writer_subs.lock();
        g.retain(|w| w.strong_count() != 0);
        if g.iter().any(|w| w.as_ptr() == want) { return; }
        g.push(Arc::downgrade(subs));
    }

    #[cfg(target_os = "oxide-kernel")]
    fn wake_writers(&self) {
        self.writers.wake_all();
        if let Some(subs) = self.subs.lock().as_ref().and_then(|weak| weak.upgrade()) {
            subs.notify_mask(vfs::POLL_OUT);
        }
        // `unix_dgram_peer_wake_relay` → `wake_up_interruptible_poll(
        // sk_sleep(sk), EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND)` on every sender
        // that registered while we were full.
        let relay: Vec<Arc<vfs::PollSubscribers>> = {
            let mut g = self.peer_writer_subs.lock();
            g.retain(|w| w.strong_count() != 0);
            g.iter().filter_map(|w| w.upgrade()).collect()
        };
        for subs in relay { subs.notify_mask(vfs::POLL_OUT | vfs::POLL_WRNORM); }
    }
}

#[cfg(target_os = "oxide-kernel")]
pub enum ArmDgramRead { Retry, Shutdown, Parked }

#[cfg(target_os = "oxide-kernel")]
pub enum ArmDgramWrite { Retry, PeerClosed, MessageTooLarge, Parked }

fn message_charge(len: usize) -> usize { len.max(1) }
