use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

use super::{GcNode, GcRights, UnixAddr};

pub struct UnixDgram {
    pub payload: Vec<u8>,
    /// Sender's (pid, uid, gid) at sendmsg time.
    pub creds: (u32, u32, u32),
    /// F189: SCM_RIGHTS — files carried alongside the payload.
    pub fds: Vec<Arc<vfs::File>>,
}

pub struct UnixDgramRecord {
    pub msg: UnixDgram,
    pub sender: Option<UnixAddr>,
    rights: GcRights,
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
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    pub reader_shutdown: core::sync::atomic::AtomicBool,
    queued_bytes: core::sync::atomic::AtomicUsize,
    shutdown_generation: core::sync::atomic::AtomicU64,
    released: core::sync::atomic::AtomicBool,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub writers: sched::live::WaitList,
    /// F181a: epoll subscribers of the owning InetSocket.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    gc: GcNode,
}

impl UnixDgramQueue {
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
            bpf_filter,
            reader_shutdown: core::sync::atomic::AtomicBool::new(false),
            queued_bytes: core::sync::atomic::AtomicUsize::new(0),
            shutdown_generation: core::sync::atomic::AtomicU64::new(0),
            released: core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            writers: sched::live::WaitList::new(),
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

    /// Enqueue one canonical record with its optional sender address. # C: O(1)
    pub fn try_push_from_with_rights(&self, msg: UnixDgram, sender: Option<UnixAddr>, rights: GcRights) -> Result<(), crate::NetError> {
        self.try_push_from_with_rights_bounded(msg, sender, rights, usize::MAX)
    }

    /// Enqueue one atomic datagram under the sender's queue cap. # C: O(1)
    pub fn try_push_from_with_rights_bounded(&self, mut msg: UnixDgram, sender: Option<UnixAddr>,
        rights: GcRights, cap: usize) -> Result<(), crate::NetError>
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
            return Ok(());
        }
        msg.payload.truncate(msg.payload.len().min(verdict as usize));
        let transition = self.gc.pin();
        rights.register(&self.gc);
        let mut q = self.msgs.lock();
        if self.released.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Econnrefused); }
        if self.reader_shutdown.load(core::sync::atomic::Ordering::Acquire) { return Err(crate::NetError::Epipe); }
        let charge = message_charge(msg.payload.len());
        if self.queued_bytes.load(core::sync::atomic::Ordering::Relaxed).saturating_add(charge) > cap {
            return Err(crate::NetError::Eagain);
        }
        q.push_back(UnixDgramRecord { msg, sender, rights });
        self.queued_bytes.fetch_add(charge, core::sync::atomic::Ordering::Relaxed);
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
            let msg = UnixDgram { payload: front.payload.clone(), creds: front.creds, fds: front.rights.clone_files() };
            return Ok(Some((copied, msg, front.sender.clone())));
        }
        let mut record = q.pop_front().unwrap();
        self.queued_bytes.fetch_sub(message_charge(record.payload.len()), core::sync::atomic::Ordering::Relaxed);
        drop(q);
        #[cfg(target_os = "oxide-kernel")]
        self.wake_writers();
        record.msg.fds = record.rights.take_files();
        Ok(Some((copied, record.msg, record.sender)))
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

    #[cfg(target_os = "oxide-kernel")]
    fn wake_writers(&self) {
        self.writers.wake_all();
        if let Some(subs) = self.subs.lock().as_ref().and_then(|weak| weak.upgrade()) {
            subs.notify_mask(vfs::POLL_OUT);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
pub enum ArmDgramRead { Retry, Shutdown, Parked }

#[cfg(target_os = "oxide-kernel")]
pub enum ArmDgramWrite { Retry, PeerClosed, MessageTooLarge, Parked }

fn message_charge(len: usize) -> usize { len.max(1) }
